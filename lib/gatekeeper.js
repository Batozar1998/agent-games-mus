// Mus — Proof Gatekeeper agent core (zkVerify Agent Games, Season 01).
// Pure decision + proof logic. No I/O, no secrets. Safe to unit-test.
//
// Decision rules (from the official trap encyclopedia — each task has exactly
// one failing check; a single failure means REJECT with that reason_code):
//   PROOF_REUSED      proof_tx already seen in a previous task
//   VK_SUBSTITUTION   proof_vk != registered_vk
//   THRESHOLD_MISMATCH public_balance < minimum
//   RECIPIENT_MISMATCH recipient != condition_recipient
//   EXPIRED_CONDITION current_block >= expiry_block
//   AMOUNT_OVERFLOW   amount > max_transfer
//   VALID_CONDITION   all checks pass -> APPROVE
//
// Circuit input encoding (verified end-to-end with snarkjs 0.7.6; the circuit
// enforces decision==1 iff every check passes, so a wrong decision cannot
// even produce a witness):
//   - vk hashes (registeredVkHash / proofVkHash): BigInt(hex) as decimal.
//     The 256-bit hash exceeds the BN254 field prime; snarkjs reduces mod p.
//     Both sides reduce the same way, so equality is preserved.
//   - addresses (recipient / conditionRecipient): BigInt(hex) as decimal.
//   - minimum / publicBalance / amount / maxTransfer / expiryBlock /
//     currentBlock: decimal numbers as given in the task.
//   - decision: 1 = APPROVE, 0 = REJECT.
//   - taskId: the task-id string interpreted as bytes -> number
//     (BigInt('0x' + Buffer.from(taskId).toString('hex'))).
//   - salt: private random field element (fresh per proof).
// Public signals returned by the circuit (13): [computedHash, registeredVkHash,
// proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient,
// conditionRecipient, amount, maxTransfer, decision, taskId].
// PROOF_REUSED tasks have no proof to submit (platform excludes them from the
// reliability bonus), so the response omits proof/public_signals for them.
'use strict';

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------
function hexToDec(h) {
  if (typeof h !== 'string') return String(h);
  return BigInt(h).toString();
}

function strToField(s) {
  return BigInt('0x' + Buffer.from(String(s), 'utf8').toString('hex')).toString();
}

function randomSalt() {
  // Random 128-bit field element (well under the BN254 prime).
  return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
}

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------
// input: the task's `input` object.
// seenProofTx: a Set of proof_tx values from previously processed tasks.
// Returns { decision: 'APPROVE'|'REJECT', reason_code, isProvable }.
// isProvable=false only for PROOF_REUSED (no proof to submit).
function decide(input, seenProofTx) {
  const norm = (v) => (typeof v === 'string' ? v.toLowerCase() : v);
  const toBig = (v) => BigInt(v);

  const proofTx = input.proof_tx;
  if (proofTx && seenProofTx && seenProofTx.has(proofTx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', isProvable: false };
  }
  if (norm(input.proof_vk) !== norm(input.registered_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', isProvable: true };
  }
  if (toBig(input.public_balance) < toBig(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', isProvable: true };
  }
  if (norm(input.recipient) !== norm(input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', isProvable: true };
  }
  if (Number(input.current_block) >= Number(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', isProvable: true };
  }
  if (toBig(input.amount) > toBig(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', isProvable: true };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', isProvable: true };
}

// ---------------------------------------------------------------------------
// Circuit input builder
// ---------------------------------------------------------------------------
// taskInput: the task's `input` object. taskId: the envelope-level task_id
// (it is NOT inside `input`). decision01: 1 (approve) or 0 (reject).
// Returns the 13-field input object for snarkjs groth16 fullProve.
function buildCircuitInput(taskInput, taskId, decision01, salt) {
  return {
    registeredVkHash: hexToDec(taskInput.registered_vk),
    proofVkHash: hexToDec(taskInput.proof_vk),
    minimum: String(taskInput.minimum),
    publicBalance: String(taskInput.public_balance),
    expiryBlock: Number(taskInput.expiry_block),
    currentBlock: Number(taskInput.current_block),
    recipient: hexToDec(taskInput.recipient),
    conditionRecipient: hexToDec(taskInput.condition_recipient),
    amount: String(taskInput.amount),
    maxTransfer: String(taskInput.max_transfer),
    decision: decision01,
    taskId: strToField(taskId || ''),
    salt: salt || randomSalt(),
  };
}

module.exports = { decide, buildCircuitInput, hexToDec, strToField, randomSalt };
