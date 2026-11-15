// Mus — Proof Gatekeeper request handler (shared by the standalone server
// and the Vercel serverless function).
//
// Pipeline (in order):
//   1. Verify HMAC-SHA256 (x-agent-games-signature) over the RAW body BEFORE
//      parsing. Mismatch -> 401, no work done.
//   2. Parse the task envelope. Validate the type.
//   3. Idempotency: if task_id was already answered, return the cached
//      response (same decision + same proof) with a fresh signature.
//   4. Run the 7 decision checks (fail closed -> REJECT).
//   5. Generate a Groth16 proof with snarkjs (decision 1 or 0) — except for
//      PROOF_REUSED, which has no proof to submit.
//   6. Respond { decision, reason_code, proof, public_signals, proof_tx },
//      signed with x-agent-games-signature over the raw response body.
//   7. On any proof-generation failure, fall back to the decision WITHOUT a
//      proof (a correct decision without a proof still scores +12-2; a
//      timeout is -2). Never let the handler hang: the whole pipeline is
//      bounded well under the 60s platform deadline.
//
// State (per process): responseCache (task_id -> response) and seenProofTx
// (proof_tx values). In a long-lived server these persist; in a serverless
// function they persist across warm invocations only.
'use strict';

const { decide, buildCircuitInput } = require('./gatekeeper');
const { verifySignature, signBody } = require('./hmac');
const { generateProof } = require('./prover');

const responseCache = new Map(); // task_id -> response object (without signature)
const seenProofTx = new Set(); // proof_tx values from processed tasks

const PROOF_TIMEOUT_MS = 30000; // bound proof generation; platform deadline is 60s

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout:' + label)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Handle one task. rawBody is a Buffer (the exact bytes received).
// Returns { status, headers, body } where body is a string (already JSON).
async function handleTask(rawBody, signatureHeader, hmacSecret) {
  const started = Date.now();

  // 1. HMAC first, before parsing.
  if (!verifySignature(hmacSecret, rawBody, signatureHeader)) {
    return {
      status: 401,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'invalid signature' }),
    };
  }

  // 2. Parse + validate.
  let task;
  try {
    task = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return { status: 400, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'invalid json' }) };
  }
  if (!task || typeof task !== 'object' || !task.input || !task.task_id) {
    // Signed but not a task envelope: this is the platform's preflight /
    // health ping (a signed request that is not a transfer task). It must
    // get HTTP 200 with signed protocol-v1 JSON, not a 400. The 2026-11-15
    // preflight failed with 400 "invalid task envelope" until this branch
    // was added. Return a signed acknowledgement.
    const ack = { ok: true, protocol: 'v1', agent: 'Mus', track: 'proof-gatekeeper' };
    const raw = JSON.stringify(ack);
    return {
      status: 200,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(hmacSecret, raw) },
      body: raw,
    };
  }
  const input = task.input;
  const taskId = String(task.task_id);

  // 3. Idempotency: same task_id -> same response.
  if (responseCache.has(taskId)) {
    const cached = responseCache.get(taskId);
    const raw = JSON.stringify(cached);
    return {
      status: 200,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(hmacSecret, raw) },
      body: raw,
    };
  }

  // 4. Decision.
  const { decision, reason_code, isProvable } = decide(input, seenProofTx);
  const decision01 = decision === 'APPROVE' ? 1 : 0;

  // 5. Proof (unless PROOF_REUSED).
  let proof = null;
  let publicSignals = null;
  if (isProvable) {
    try {
      const circuitInput = buildCircuitInput(input, taskId, decision01);
      const res = await withTimeout(generateProof(circuitInput), PROOF_TIMEOUT_MS, 'fullProve');
      proof = res.proof;
      publicSignals = res.publicSignals;
    } catch (e) {
      // Proof generation failed (shouldn't happen if the decision matches
      // the circuit). Fall back to the decision WITHOUT a proof rather than
      // timing out: correct decision w/o proof scores +12-2, timeout is -2.
      proof = null;
      publicSignals = null;
    }
  }

  // 6. Response.
  const response = { decision, reason_code, proof_tx: input.proof_tx || null };
  if (proof && publicSignals) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  // Cache + record (only after a successful response is built).
  responseCache.set(taskId, response);
  if (input.proof_tx) seenProofTx.add(input.proof_tx);

  const raw = JSON.stringify(response);
  return {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': signBody(hmacSecret, raw),
      'x-agent-games-ms': String(Date.now() - started),
    },
    body: raw,
  };
}

// Health check payload (no auth).
function healthPayload() {
  return {
    ok: true,
    agent: 'Mus',
    track: 'proof-gatekeeper',
    tasks_seen: responseCache.size,
    uptime_s: Math.floor(process.uptime()),
  };
}

module.exports = { handleTask, healthPayload, responseCache, seenProofTx };
