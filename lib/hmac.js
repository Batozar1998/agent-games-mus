// Mus — HMAC signing/verification + Groth16 proof generation.
// The HMAC secret is the 32-byte value the platform generates at agent
// registration and shows exactly once. It is NEVER hardcoded here; it comes
// from the AGENT_GAMES_HMAC_SECRET env var (see .env.example).
//
// Secret encoding: the platform shows the secret as a hex string (64 hex
// chars) or base64. We decode it to raw bytes when it looks like hex/base64,
// otherwise use the string as UTF-8 bytes. For verification we accept the
// header in hex or base64; for signing we emit hex (the common convention).
'use strict';

const crypto = require('crypto');

// Decode the configured secret to raw key bytes.
function secretBytes(secret) {
  const s = String(secret || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex');
  if (/^[A-Za-z0-9+/]{43}=$/.test(s)) return Buffer.from(s, 'base64');
  return Buffer.from(s, 'utf8');
}

// Candidate HMAC keys for a secret. The platform shows a 64-hex-char secret,
// but it is ambiguous whether it HMACs with the hex-decoded 32 raw bytes or
// with the 64-char hex string as UTF-8 bytes. The 2026-11-15 preflight
// failed with 401 even though the secret in Vercel matched the user's secret
// (a self-signed test request was accepted), which points at a key-encoding
// mismatch. Try both so either platform convention verifies.
function secretKeyCandidates(secret) {
  const s = String(secret || '').trim();
  const keys = [secretBytes(s)];
  if (/^[0-9a-fA-F]{64}$/.test(s)) keys.push(Buffer.from(s, 'utf8'));
  if (/^[A-Za-z0-9+/]{43}=$/.test(s)) keys.push(Buffer.from(s, 'utf8'));
  return keys;
}

// Compute HMAC-SHA256 over a raw body, return hex string.
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secretBytes(secret)).update(rawBody).digest('hex');
}

// Verify an incoming x-agent-games-signature header against a raw body.
// Accepts the header in hex or base64. Timing-safe comparison.
// Tries every key encoding so a platform that HMACs with the hex string
// as UTF-8 (instead of hex-decoded bytes) still verifies.
// Returns the key Buffer that verified, or null.
function verifyAndGetKey(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return null;
  const given = String(headerValue).trim();
  for (const key of secretKeyCandidates(secret)) {
    const hex = crypto.createHmac('sha256', key).update(rawBody).digest('hex');
    const candidates = [hex, Buffer.from(hex, 'hex').toString('base64')];
    for (const cand of candidates) {
      const a = Buffer.from(cand);
      const b = Buffer.from(given);
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) return key;
    }
  }
  return null;
}

function verifySignature(secret, rawBody, headerValue) {
  return verifyAndGetKey(secret, rawBody, headerValue) !== null;
}

// Sign a raw response body. Returns the hex HMAC to send as
// x-agent-games-signature.
function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

// Sign with an explicit key Buffer (the key that verified the request, so
// the response signature uses the same key encoding the platform expects).
function signBodyWithKey(key, rawBody) {
  return crypto.createHmac('sha256', key).update(rawBody).digest('hex');
}

module.exports = { secretBytes, hmacHex, verifySignature, verifyAndGetKey, signBody, signBodyWithKey };
