// Mus — Groth16 proof generation (snarkjs, official gatekeeper circuit).
// Loads the wasm/zkey once (from disk paths or Buffers) and reuses them.
// fullProve takes ~1s on this hardware; the platform deadline is 60s.
'use strict';

const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

let wasmBuf = null;
let zkeyBuf = null;
let vk = null;

function circuitDir() {
  // Works for the standalone server (lib/../circuits) and the Vercel
  // function (api/../circuits). Falls back to an env override.
  if (process.env.AGENT_CIRCUITS_DIR) return process.env.AGENT_CIRCUITS_DIR;
  const candidates = [
    path.join(__dirname, '..', 'circuits'),
    path.join(__dirname, 'circuits'),
    path.join(process.cwd(), 'circuits'),
  ];
  for (const d of candidates) {
    if (fs.existsSync(path.join(d, 'gatekeeper.wasm'))) return d;
  }
  return candidates[0];
}

function loadCircuits() {
  if (wasmBuf && zkeyBuf && vk) return { wasmBuf, zkeyBuf, vk };
  const dir = circuitDir();
  wasmBuf = fs.readFileSync(path.join(dir, 'gatekeeper.wasm'));
  zkeyBuf = fs.readFileSync(path.join(dir, 'gatekeeper_final.zkey'));
  vk = JSON.parse(fs.readFileSync(path.join(dir, 'vk.json'), 'utf8'));
  return { wasmBuf, zkeyBuf, vk };
}

// Generate a Groth16 proof for a circuit input object.
// Returns { proof, publicSignals }.
async function generateProof(circuitInput) {
  const { wasmBuf: w, zkeyBuf: z } = loadCircuits();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, w, z);
  return { proof, publicSignals };
}

// Verify a proof against the bundled verification key (self-check).
async function verifyProof(proof, publicSignals) {
  const { vk: v } = loadCircuits();
  return snarkjs.groth16.verify(v, publicSignals, proof);
}

module.exports = { loadCircuits, generateProof, verifyProof };
