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

// Compute HMAC-SHA256 over a raw body, return hex string.
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secretBytes(secret)).update(rawBody).digest('hex');
}

// Verify an incoming x-agent-games-signature header against a raw body.
// Accepts the header in hex or base64. Timing-safe comparison.
function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const hex = hmacHex(secret, rawBody);
  const candidates = [hex, Buffer.from(hex, 'hex').toString('base64')];
  const given = String(headerValue).trim();
  for (const cand of candidates) {
    const a = Buffer.from(cand);
    const b = Buffer.from(given);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

// Sign a raw response body. Returns the hex HMAC to send as
// x-agent-games-signature.
function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

module.exports = { secretBytes, hmacHex, verifySignature, signBody };
