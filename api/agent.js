// Mus — Proof Gatekeeper agent (Vercel serverless function).
// Deploy: import this repo into Vercel (Hobby, free). Set the env var
// AGENT_GAMES_HMAC_SECRET to the secret shown once at agent registration.
// The endpoint URL will be https://<project>.vercel.app/api/agent
// (register THAT as the agent endpoint on the Agent Games dashboard).
// The circuits/ directory (wasm + zkey + vk.json) is bundled with the
// function; snarkjs reads them from disk at runtime.
//
// NOTE: Vercel Hobby serverless functions have a 10s max duration. Proof
// generation takes ~1s, so a task completes in ~2-3s total — well within
// the limit and the platform's 60s deadline. The seen-set / response cache
// live in module scope and persist across warm invocations of the same
// instance; a cold start resets them (the platform also tracks reuse, and
// the decision logic is stateless, so a reset only risks missing a
// PROOF_REUSED trap on the first task after a cold start).
'use strict';

const { handleTask, healthPayload } = require('../lib/handler');

// Disable Vercel's built-in body parser: we need the RAW request bytes to
// verify the HMAC signature before parsing.
module.exports.config = { api: { bodyParser: false } };

module.exports = async (req, res) => {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET || '';
  if (req.method === 'GET') {
    res.status(200).json(healthPayload());
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  if (!secret) {
    res.status(500).json({ error: 'agent not configured (missing HMAC secret)' });
    return;
  }
  // Read the RAW body (Vercel does not parse it for us when we disable the
  // body parser; see vercel.json). We need the exact bytes for HMAC.
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  try {
    const sig = req.headers['x-agent-games-signature'] || '';
    const out = await handleTask(rawBody, sig, secret);
    res.status(out.status);
    for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
    res.send(out.body);
  } catch (e) {
    console.error('[mus] handler error:', e && e.message);
    res.status(500).json({ error: 'internal error' });
  }
};
