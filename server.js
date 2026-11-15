// Mus — Proof Gatekeeper agent (standalone HTTP server).
// Listens on PORT (default 3000). Endpoints:
//   GET  /health  -> { ok, agent, track, tasks_seen, uptime_s } (no auth)
//   POST /agent   -> Proof Gatekeeper task handler (HMAC required)
//   POST /        -> same as /agent (some platforms POST to the root)
// Env:
//   AGENT_GAMES_HMAC_SECRET  (required) the 32-byte secret the platform
//                              generated at agent registration, shown once.
//                              Set it via env var or a .env file. Never
//                              commit it.
//   PORT                     (default 3000)
//   AGENT_CIRCUITS_DIR       (optional) override for the circuits directory.
// Run:  node server.js
// The server must be reachable at a PUBLIC HTTPS URL for the platform to
// deliver tasks. See README.md for deployment (Vercel recommended).
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { handleTask, healthPayload } = require('./lib/handler');

// Load .env if present (simple KEY=VALUE parser; never commit .env).
(function loadDotEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PORT = Number(process.env.PORT || 3000);

if (!HMAC_SECRET) {
  console.error('[mus] FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start without it (HMAC verification would be meaningless).');
  console.error('[mus] Set it in the environment or in a .env file (see .env.example). The secret is shown once when you register the agent on the Agent Games dashboard.');
  process.exit(1);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
    const body = JSON.stringify(healthPayload());
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
    return;
  }
  if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      try {
        const sig = req.headers['x-agent-games-signature'] || '';
        const out = await handleTask(rawBody, sig, HMAC_SECRET);
        res.writeHead(out.status, out.headers);
        res.end(out.body);
      } catch (e) {
        // Never hang: fail closed with a REJECT-shaped 500 is not useful to
        // the platform, so return a plain 500; the platform scores it as a
        // timeout (-2) rather than a wrong decision.
        console.error('[mus] handler error:', e && e.message);
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal error' }));
      }
    });
    return;
  }
  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[mus] Proof Gatekeeper agent listening on :${PORT} (POST /agent, GET /health)`);
});
