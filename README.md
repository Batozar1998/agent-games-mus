# Mus — Proof Gatekeeper agent (zkVerify Agent Games, Season 01)

An AI agent for the [zkVerify Agent Games](https://agentgames.zkverify.io) **Proof
Gatekeeper** track. It receives task envelopes from the platform, verifies the
HMAC signature, decides **APPROVE** or **REJECT** using the official trap
encyclopedia, generates a Groth16 proof locally with snarkjs using the official
gatekeeper circuit, and returns the signed response — all in ~1 second, well
under the platform's 60-second deadline.

Agent name: **Mus** · Track: **Proof Gatekeeper** · Season 01 (13–20 Nov 2026).

## How it works

1. The platform POSTs a JSON task envelope to the agent endpoint with an
   `x-agent-games-signature` HMAC-SHA256 header.
2. The agent verifies the HMAC over the **raw body before parsing**. Bad
   signature → 401, no work done.
3. The agent runs the 7 decision checks, in order (exactly one check fails
   per task; a single failure means REJECT):
   - `PROOF_REUSED` — `proof_tx` already seen in a previous task (no proof to
     submit; the response omits `proof`/`public_signals`).
   - `VK_SUBSTITUTION` — `proof_vk != registered_vk`
   - `THRESHOLD_MISMATCH` — `public_balance < minimum`
   - `RECIPIENT_MISMATCH` — `recipient != condition_recipient`
   - `EXPIRED_CONDITION` — `current_block >= expiry_block`
   - `AMOUNT_OVERFLOW` — `amount > max_transfer`
   - `VALID_CONDITION` — all checks pass → **APPROVE**
4. The agent generates a Groth16 proof (BN254, Circom 2.x) with snarkjs using
   the official circuit (`circuits/gatekeeper.wasm`,
   `circuits/gatekeeper_final.zkey`). The circuit enforces `decision == 1`
   iff every check passes, so a wrong decision cannot even produce a witness.
   If proof generation ever fails, the agent still returns the decision
   **without** a proof (a correct decision without a proof scores +12−2; a
   timeout is −2).
5. The response `{ decision, reason_code, proof, public_signals, proof_tx }`
   is signed with `x-agent-games-signature` (HMAC over the raw response body).
6. Responses are cached by `task_id` (idempotency — the platform may retry a
   task; the same task gets the same decision and the same proof).

Fail closed: on timeout or uncertainty the agent rejects rather than
approving. It never signs a transaction and needs no wallet — signing is
HMAC only.

## Run locally

```bash
npm install
cp .env.example .env        # then paste the HMAC secret (see below)
npm start                   # listens on :3000
curl http://127.0.0.1:3000/health
```

## Deploy (Vercel, free Hobby tier)

1. Import this repo into [Vercel](https://vercel.com/new) (Hobby, no credit card).
2. Set the environment variable `AGENT_GAMES_HMAC_SECRET` to the secret the
   Agent Games dashboard shows **once** when you register the agent.
3. Deploy. The endpoint is `https://<your-project>.vercel.app/api/agent`.
4. Register that URL as the agent endpoint on the
   [Agent Games dashboard](https://agentgames.zkverify.io) (agent name **Mus**,
   track **Proof Gatekeeper**), and complete the signed preflight + practice
   task there.

Proof generation takes ~1 s, so a task completes in ~2–3 s total — well within
Vercel Hobby's 10 s function limit and the platform's 60 s deadline.

## Configuration

| Variable | Required | What it is |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | The 32-byte HMAC secret the platform generates at agent registration, shown exactly once. Paste it into `.env` locally, or as a Vercel env var. **Never commit it.** |
| `PORT` | no | Standalone server port (default `3000`). |
| `AGENT_CIRCUITS_DIR` | no | Override for the circuits directory (default `./circuits`). |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (no auth): `{ ok, agent, track, tasks_seen, uptime_s }` |
| `POST` | `/agent` | Proof Gatekeeper task handler (HMAC required) |
| `POST` | `/` | Same as `/agent` |

## Tests

```bash
npm test
```

Starts the server on a test port with a test HMAC secret and runs 21 checks:
valid task (APPROVE + proof that verifies with `snarkjs groth16 verify`),
all 5 trap types (correct REJECT + reason_code + verifying proof),
PROOF_REUSED (REJECT, no proof), idempotent retry, bad/missing signature
(401), and response time (< 10 s).

## Files

```
server.js            standalone HTTP server (POST /agent, GET /health)
api/agent.js         Vercel serverless function (same handler, raw-body HMAC)
lib/gatekeeper.js    decision rules + circuit input encoding
lib/handler.js       request pipeline (HMAC -> decide -> prove -> sign)
lib/hmac.js          HMAC-SHA256 verify/sign (hex + base64 header forms)
lib/prover.js        snarkjs Groth16 fullProve / verify (official circuit)
circuits/            official gatekeeper circuit (wasm + zkey + vk.json)
test/test-agent.mjs  end-to-end test suite (npm test)
```

## Steal the VFY

Not implemented. The guide requires a strategy commitment **before** Swiss
Round 1 opens, and Swiss is already at Round 2 (13–17 Nov) — the track is
almost certainly locked out for new entrants. This agent supports Proof
Gatekeeper only.

## Security

- No wallet, no private key, no seed. The agent never signs a transaction.
- The HMAC secret lives only in `.env` / an env var — never in the repo.
- `.env` is git-ignored. Do not paste the secret into issues, logs, or chat.
