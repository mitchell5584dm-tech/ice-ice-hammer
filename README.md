# Ice Ice Hammer

Your own Suno-style song generator, now as a multi-user service (Phase 1).
Write lyrics, describe a style, press Create, and get full songs with vocals.
Songs are made by AI music models on [Replicate](https://replicate.com) and saved to your own library.

**Phase 1 (SaaS):** email+password accounts, per-user libraries, credit-metered
generation. Credits are debited *before* any Replicate call, so spend can never
exceed balances. Free accounts get 10 credits once (after email verification)
and can use the three cheapest engines; expensive engines need a paid plan
(granted manually by an admin for now — billing UI is Phase 2).

- **Models:** ACE-Step (vocals, cheapest), MiniMax Music 2.5 (best singing), ElevenLabs Music, MusicGen and Stable Audio 2.5 (instrumental). Models that are unavailable on your account show as greyed out.
- **Two takes per Create**, each with its own seed. You can Remix (same settings, new seed), Reuse (load settings back into the form), Download, and Delete.
- **Generation runs on the server.** You can close the tab and come back.
- **No dependencies.** Plain Node.js 22.5 or newer (uses built-in `node:sqlite`). No `npm install`, no build step.

## Run it

1. Install Node.js 22.5+ from https://nodejs.org.
2. Get a Replicate API token: https://replicate.com/account/api-tokens (you need billing set up on Replicate).
3. Copy `.env.example` to `.env` and set `REPLICATE_API_TOKEN` and `SESSION_SECRET`.
   Set `EMAIL_AUTO_VERIFY=1` for local dev to skip email verification (the
   verification link is otherwise logged to the server console — no mail
   provider is wired up yet).
4. Run: `node server.mjs`
5. Open http://localhost:3000 and create an account. **The first account is the admin.**

## How the SaaS bits work

- **Auth:** `POST /api/auth/signup|login|logout`, `GET /api/auth/verify?token=…`.
  Sessions are HMAC-signed HTTP-only cookies (30 days). Passwords are scrypt hashes.
  Signup/login are rate-limited (10 attempts/min per IP, shared bucket, 429 +
  `Retry-After`). Cookie-authenticated POST/PUT/DELETE calls also require the
  per-user CSRF token from `GET /api/me` as the `X-CSRF-Token` header
  (the Stripe webhook is exempt — it uses HMAC signature auth instead).
- **Credits:** `lib/costs.mjs` holds per-model prices (2.5–3× estimated Replicate
  cost — re-tune from real invoices before launch). `/api/generate` debits
  *before* calling Replicate; failed tracks are refunded exactly once
  (`generation_ledger` + `credit_transactions` are append-only).
- **Admin:** `GET /api/admin/spend` shows per-model and per-user spend. Grant
  credits or change plans with SQLite directly for now, e.g.:
  `sqlite3 data/ice.db "UPDATE users SET credits = credits + 100 WHERE email='someone@example.com'"`.
- **Storage:** `DATA_DIR/ice.db` (SQLite) + `DATA_DIR/audio/<userId>/…`.
  Migrating an old single-user `data/library.json` library:
  `npm run migrate -- --email you@example.com [--data-dir ./data] [--dry-run]`
  — assigns every track to that user (creating the account if needed) and moves
  audio files into the per-user directory. Idempotent; safe to re-run.

## Nightly spend reconciliation

`npm run reconcile` compares the last 24h of `generation_ledger` cost estimates
against actual Replicate spend and exits 2 (cron-alertable) when drift exceeds
15% — the signal that `lib/costs.mjs` credit prices have gone stale. Replicate
exposes no public billing API, so set `REPLICATE_EXPECTED_SPEND_USD` to the 24h
figure from https://replicate.com/account/billing to enable the drift check;
without it the script prints the ledger summary and exits 0 (UNVERIFIED).
Run it nightly, e.g.:

```
0 3 * * * cd /opt/ice-ice-hammer && node scripts/reconcile.mjs >> logs/reconcile.log 2>&1
```

## Security notes

- Every response carries `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- API responses are `Cache-Control: no-store`; the HTML shell is `no-cache`
  (revalidated each load); audio streams are `private, max-age=86400`.
- Signup/login are rate-limited per IP (10/min). The session cookie is
  `HttpOnly` + `SameSite=Lax`; set `COOKIE_SECURE=1` behind HTTPS.
- Email verification links are single-use 48-hex-char tokens.
- `SESSION_SECRET` must be set in production — without it sessions (and CSRF
  tokens) do not survive restarts.

## Put it online (Render)

1. Push this folder to a GitHub repo.
2. In Render, choose **New → Blueprint** and pick the repo. It reads `render.yaml`.
3. When asked, set `REPLICATE_API_TOKEN` and `SESSION_SECRET`.

`render.yaml` attaches a 5 GB disk so the database and songs survive restarts. Disks need a paid instance (Starter). Without a disk, everything is wiped on every deploy.

Docker also works: `docker build -t ich . && docker run -p 3000:3000 -v ich-data:/data --env-file .env ich`

## Costs

You pay Replicate per song, at the price shown on each model's page. Open-source models like ACE-Step bill for GPU time and usually cost a few cents per song. Hosted models like MiniMax and ElevenLabs charge a fixed amount per song, which is usually more. Two takes cost twice as much. Check current prices on Replicate before heavy use.

Users spend *credits*, not your Replicate balance directly: each model has a
per-take credit price in `lib/costs.mjs` (~2.5–3× estimated Replicate cost),
and generation is impossible with a zero balance. `MAX_ACTIVE_GENERATIONS`
(default 6) is a global backstop; each user is capped at 2 simultaneous
generations (`USER_MAX_ACTIVE_GENERATIONS`).

## How it talks to the models

Each model names its inputs differently: `tags` or `prompt`, `duration` or `audio_duration`, and so on. `lib/replicate.mjs` reads each model's published input schema and maps the form's style, lyrics, length, seed and instrumental setting onto it, clamped to that model's limits. For example, MusicGen's 30-second cap is applied automatically.

To add a model, add an entry to `lib/providers.mjs` with its Replicate `owner/name`. If it needs an input the form doesn't fill, set it under `extra`. The app shows an error naming that input.

## Files

| Path | What it does |
|---|---|
| `server.mjs` | Web server, API routes, background job polling, audio streaming |
| `lib/replicate.mjs` | Replicate API calls and input mapping |
| `lib/providers.mjs` | The list of models |
| `lib/db.mjs` | SQLite store: users, per-user tracks, generation ledger, credit transactions |
| `lib/costs.mjs` | Per-model credit prices and tier model access |
| `lib/auth.mjs` | scrypt password hashing, signed cookie sessions, verification stub, CSRF tokens |
| `lib/ratelimit.mjs` | In-memory per-IP sliding-window rate limiter (auth endpoints) |
| `scripts/migrate-json.mjs` | One-shot migration: old `library.json` → SQLite + per-user audio (`npm run migrate`) |
| `scripts/reconcile.mjs` | Nightly Replicate spend reconciliation (`npm run reconcile`) |
| `public/index.html` | The whole interface |
| `test/smoke.mjs` | End-to-end test against a fake Replicate API (`npm test`) |

## Content and rights

Check each model's license and Replicate's terms before selling or distributing songs. Don't prompt for another artist's voice or copyrighted lyrics.
