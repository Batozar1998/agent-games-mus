// Mus — end-to-end test for the Proof Gatekeeper agent.
// Starts the server on a test port with a test HMAC secret, sends signed
// task envelopes, and checks: HMAC verification (good + bad), correct
// decisions, valid Groth16 proofs (re-verified with snarkjs), idempotency,
// PROOF_REUSED handling, and response time (< 60s, target < 10s).
// Run:  npm test   (or: node test/test-agent.mjs)
// Exits 0 only if every check passes.
import { spawn } from 'child_process';
import crypto from 'crypto';
import path from 'path';
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 32-byte test secret (hex)
const PORT = 3101;
const BASE = `http://127.0.0.1:${PORT}`;
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR = '0xde42a1b2c3d4e5f600000000000000000009f01';
const ADDR2 = '0x1111111111111111111111111111111111111111';

function hmac(secretHex, raw) {
  return crypto.createHmac('sha256', Buffer.from(secretHex, 'hex')).update(raw).digest('hex');
}
function task(over = {}, id = 'gk_test_1') {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: id,
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0xaaa111',
      ...over,
    },
  };
}
async function post(pathname, bodyObj, secretHex, rawOverride) {
  const raw = rawOverride !== undefined ? rawOverride : JSON.stringify(bodyObj);
  const res = await fetch(BASE + pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': secretHex ? hmac(secretHex, raw) : 'deadbeef' },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* ignore */ }
  return { status: res.status, headers: res.headers, json, text };
}
function check(name, cond, extra) {
  console.log((cond ? 'PASS' : 'FAIL') + '  ' + name + (extra ? '  (' + extra + ')' : ''));
  if (!cond) process.exitCode = 1;
}

async function main() {
  const vk = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'vk.json'), 'utf8'));
  const server = spawn('node', [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Wait for the server to come up.
  let up = false;
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(BASE + '/health'); if (r.ok) { up = true; break; } } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  check('server starts + /health', up);
  if (!up) { server.kill(); process.exit(1); }

  // 1. Valid task -> APPROVE + valid proof.
  let t0 = Date.now();
  let r = await post('/agent', task({}, 'gk_test_1'), SECRET);
  const ms1 = Date.now() - t0;
  const firstProof = r.json && r.json.proof ? JSON.stringify(r.json.proof) : null;
  check('valid task -> 200', r.status === 200, 'status=' + r.status);
  check('valid task -> APPROVE', r.json && r.json.decision === 'APPROVE', r.json && r.json.decision);
  check('valid task -> VALID_CONDITION', r.json && r.json.reason_code === 'VALID_CONDITION', r.json && r.json.reason_code);
  check('valid task -> proof present', !!(r.json && r.json.proof && r.json.public_signals));
  let proofOk = false;
  if (r.json && r.json.proof) {
    proofOk = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
  }
  check('valid task -> proof verifies (snarkjs)', proofOk);
  check('valid task -> response HMAC valid', (() => {
    const raw = JSON.stringify(r.json);
    // The server signs the exact JSON it sent; re-serializing may differ in
    // key order, so verify against the raw text instead.
    return hmac(SECRET, r.text) === r.headers.get('x-agent-games-signature');
  })());
  check('valid task -> fast (<10s)', ms1 < 10000, ms1 + 'ms');

  // 2. VK substitution trap -> REJECT + valid proof.
  r = await post('/agent', task({ proof_vk: VK_OTHER, proof_tx: '0xaaa222' }, 'gk_test_2'), SECRET);
  check('VK trap -> REJECT', r.json && r.json.decision === 'REJECT');
  check('VK trap -> VK_SUBSTITUTION', r.json && r.json.reason_code === 'VK_SUBSTITUTION');
  proofOk = r.json && r.json.proof ? await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof) : false;
  check('VK trap -> proof verifies', proofOk);

  // 3. Threshold trap -> REJECT.
  r = await post('/agent', task({ public_balance: '500', proof_tx: '0xaaa333' }, 'gk_test_3'), SECRET);
  check('threshold trap -> REJECT/THRESHOLD_MISMATCH', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'THRESHOLD_MISMATCH');

  // 4. Recipient trap -> REJECT.
  r = await post('/agent', task({ recipient: ADDR2, proof_tx: '0xaaa444' }, 'gk_test_4'), SECRET);
  check('recipient trap -> REJECT/RECIPIENT_MISMATCH', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'RECIPIENT_MISMATCH');

  // 5. Expired trap -> REJECT.
  r = await post('/agent', task({ current_block: 8430000, proof_tx: '0xaaa555' }, 'gk_test_5'), SECRET);
  check('expired trap -> REJECT/EXPIRED_CONDITION', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'EXPIRED_CONDITION');

  // 6. Amount overflow trap -> REJECT.
  r = await post('/agent', task({ amount: '1500', proof_tx: '0xaaa666' }, 'gk_test_6'), SECRET);
  check('amount trap -> REJECT/AMOUNT_OVERFLOW', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'AMOUNT_OVERFLOW');

  // 7. PROOF_REUSED: same proof_tx as task 1 (0xaaa111) but a NEW task_id.
  r = await post('/agent', task({}, 'gk_test_7'), SECRET);
  check('reused proof_tx -> REJECT/PROOF_REUSED', r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED');
  check('reused proof_tx -> NO proof attached', r.json && !r.json.proof && !r.json.public_signals);

  // 8. Idempotency: resend task 1 (same task_id) -> same decision + same proof.
  const r1 = await post('/agent', task({}, 'gk_test_1'), SECRET);
  check('idempotent retry -> same decision', r1.json && r1.json.decision === 'APPROVE');
  check('idempotent retry -> same proof', r1.json && JSON.stringify(r1.json.proof) === firstProof);

  // 9. Bad signature -> 401.
  r = await post('/agent', task({}, 'gk_test_9'), null);
  check('bad signature -> 401', r.status === 401, 'status=' + r.status);

  // 10. No signature -> 401.
  const rawNoSig = JSON.stringify(task({}, 'gk_test_10'));
  const resNoSig = await fetch(BASE + '/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: rawNoSig });
  check('missing signature -> 401', resNoSig.status === 401, 'status=' + resNoSig.status);

  server.kill();
  console.log(process.exitCode ? '\nSOME CHECKS FAILED' : '\nALL CHECKS PASSED');
}

main().catch((e) => { console.error('test crashed:', e); process.exit(1); });
