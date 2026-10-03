// End-to-end smoke test against a fake Replicate API. No network, no token needed.
// Covers: signup/login/logout, email verification, credit debiting (402),
// per-user isolation, tier model gating, admin spend, and the original
// generation/library/audio behavior. Run: npm test
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const MOCK_PORT = 4555, APP_PORT = 4556;
const seen = [];
const polls = {};
let n = 0;

const SCHEMAS = {
  'lucataco/ace-step': { tags: { type: 'string' }, lyrics: { type: 'string' }, duration: { type: 'number', minimum: 1, maximum: 240 }, seed: { type: 'integer', default: -1 } },
  'meta/musicgen': { prompt: { type: 'string' }, duration: { type: 'integer', maximum: 30 }, output_format: { type: 'string', enum: ['wav', 'mp3'] } },
  'ryan5453/demucs': { audio: { type: 'string' }, model_name: { type: 'string', enum: ['htdemucs', 'htdemucs_ft'], default: 'htdemucs' }, output_format: { type: 'string', enum: ['mp3', 'wav'], default: 'mp3' } },
};
const demucsPreds = new Set();

const mock = http.createServer(async (req, res) => {
  const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.headers.authorization !== 'Bearer test-token' && !req.url.startsWith('/files/')) return json(401, { detail: 'bad token' });
  const url = req.url;
  let m;
  if ((m = url.match(/^\/v1\/models\/([^/]+\/[^/]+)$/))) {
    const props = SCHEMAS[m[1]];
    if (!props) return json(404, { detail: 'Not found' });
    return json(200, { description: 'x', latest_version: { id: 'ver-' + m[1].split('/')[1], openapi_schema: { components: { schemas: { Input: { properties: props, required: [Object.keys(props)[0]] } } } } } });
  }
  if (url === '/v1/predictions' && req.method === 'POST') {
    let b = ''; for await (const c of req) b += c;
    const body = JSON.parse(b); seen.push(body);
    const id = 'pred' + (++n);
    if (body.version === 'ver-demucs') demucsPreds.add(id);
    return json(201, { id, status: 'starting' });
  }
  if ((m = url.match(/^\/v1\/predictions\/(pred\d+)$/))) {
    polls[m[1]] = (polls[m[1]] || 0) + 1;
    if (polls[m[1]] < 2) return json(200, { id: m[1], status: 'processing' });
    if (demucsPreds.has(m[1])) {
      const stem = (name) => `http://127.0.0.1:${MOCK_PORT}/files/${m[1]}-${name}.mp3`;
      return json(200, { id: m[1], status: 'succeeded', output: { vocals: stem('vocals'), drums: stem('drums'), bass: stem('bass'), other: stem('other') } });
    }
    return json(200, { id: m[1], status: 'succeeded', output: [`http://127.0.0.1:${MOCK_PORT}/files/${m[1]}.mp3`] });
  }
  if ((m = url.match(/^\/v1\/predictions\/(pred\d+)\/cancel$/))) return json(200, {});
  if (url.startsWith('/files/')) { res.writeHead(200, { 'Content-Type': 'audio/mpeg' }); return res.end(Buffer.alloc(5000, 7)); }
  json(404, { detail: 'nope' });
});
await new Promise((r) => mock.listen(MOCK_PORT, r));

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ich-'));
const app = spawn(process.execPath, ['server.mjs'], {
  cwd: path.join(path.dirname(new URL(import.meta.url).pathname), '..'),
  env: {
    ...process.env, PORT: APP_PORT, DATA_DIR: dataDir, REPLICATE_API_TOKEN: 'test-token',
    REPLICATE_API_BASE: `http://127.0.0.1:${MOCK_PORT}/v1`, POLL_MS: '200',
    SESSION_SECRET: 'test-secret',
    // Stripe billing in mock mode: no network, webhook signatures verified for real.
    STRIPE_SECRET_KEY: 'sk_test_mock', STRIPE_WEBHOOK_SECRET: 'whsec_test_123', STRIPE_MOCK: '1', STRIPE_MOCK_TRANSFER_DELAY_MS: '150',
    STRIPE_PRICE_STARTER: 'price_test_starter', STRIPE_PRICE_CREATOR: 'price_test_creator',
    STRIPE_PRICE_PRO: 'price_test_pro', STRIPE_PRICE_PACK: 'price_test_pack',
    // EMAIL_AUTO_VERIFY is deliberately NOT set: we exercise the verify-link flow.
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log = ''; app.stdout.on('data', (d) => (log += d)); app.stderr.on('data', (d) => (log += d));
const base = `http://127.0.0.1:${APP_PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Minimal cookie jar keyed by test user name, plus per-user CSRF tokens.
const jar = {};
const csrf = {};
const CSRF_SKIP_PATHS = ['/api/auth/signup', '/api/auth/login', '/api/billing/webhook'];
async function ensureCsrf(user) {
  if (csrf[user] || !jar[user]) return;
  const r = await fetch(base + '/api/me', { headers: { Cookie: jar[user] } });
  if (r.ok) csrf[user] = (await r.json()).csrfToken;
}
async function req(p, { method = 'GET', body, user = 'anon', headers = {}, noCsrf = false } = {}) {
  const h = { ...headers };
  if (jar[user]) h.Cookie = jar[user];
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const pathOnly = p.split('?')[0];
  if (!noCsrf && jar[user] && ['POST', 'PUT', 'DELETE'].includes(method) && !CSRF_SKIP_PATHS.includes(pathOnly)) {
    await ensureCsrf(user);
    if (csrf[user]) h['X-CSRF-Token'] = csrf[user];
  }
  const res = await fetch(base + p, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const set = res.headers.get('set-cookie');
  if (set) { jar[user] = set.split(';')[0]; delete csrf[user]; } // new session: refetch token lazily
  return res;
}
const j = (r) => r.json().catch(() => ({}));

// Read the verify token straight from the DB (stand-in for the email inbox).
let dbm = null;
async function verifyUser(email) {
  if (!dbm) {
    process.env.DATA_DIR = dataDir;
    dbm = await import('../lib/db.mjs');
    dbm.initDb();
  }
  const u = dbm.getUserByEmail(email);
  assert.ok(u && u.verify_token, 'verify token exists for ' + email);
  const r = await req('/api/auth/verify?token=' + u.verify_token);
  assert.equal(r.status, 200, 'verify link works');
  assert.match(await r.text(), /verified/i);
}

const meOf = async (user) => (await j(await req('/api/me', { user }))).user;

async function waitForReady(user) {
  for (let i = 0; i < 60; i++) {
    const ts = (await j(await req('/api/tracks', { user }))).tracks;
    if (ts.length && ts.every((t) => t.status === 'ready')) return ts;
    await sleep(200);
  }
  throw new Error('tracks did not finish for ' + user);
}

try {
  for (let i = 0; i < 50; i++) { try { await fetch(base + '/api/health'); break; } catch { await sleep(100); } }

  assert.equal((await req('/api/tracks')).status, 401, 'tracks need a session');
  assert.equal((await req('/')).status, 200, 'UI is served publicly');

  // ---- security headers on every response ----
  const hh = await req('/api/health');
  assert.equal(hh.headers.get('x-content-type-options'), 'nosniff', 'X-Content-Type-Options set');
  assert.equal(hh.headers.get('x-frame-options'), 'DENY', 'X-Frame-Options set');
  assert.equal(hh.headers.get('referrer-policy'), 'strict-origin-when-cross-origin', 'Referrer-Policy set');

  // ---- auth ----
  let r = await req('/api/auth/signup', { method: 'POST', user: 'alice', body: { email: 'bad', password: 'longenough1' } });
  assert.equal(r.status, 400, 'bad email rejected');
  r = await req('/api/auth/signup', { method: 'POST', user: 'alice', body: { email: 'alice@example.com', password: 'short' } });
  assert.equal(r.status, 400, 'short password rejected');

  r = await req('/api/auth/signup', { method: 'POST', user: 'alice', body: { email: 'alice@example.com', password: 'alice-pass-1' } });
  assert.equal(r.status, 200, JSON.stringify(await j(r.clone())));
  let d = await j(r);
  assert.equal(d.user.role, 'admin', 'first user becomes admin');
  assert.equal(d.verified, false, 'not verified yet');
  const aliceId = d.user.id;

  r = await req('/api/auth/signup', { method: 'POST', user: 'alice2', body: { email: 'alice@example.com', password: 'alice-pass-1' } });
  assert.equal(r.status, 409, 'duplicate email rejected');

  r = await req('/api/auth/login', { method: 'POST', user: 'alice', body: { email: 'alice@example.com', password: 'wrong-pass-1' } });
  assert.equal(r.status, 401, 'wrong password rejected');

  // unverified users cannot generate
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y' } });
  assert.equal(r.status, 403, 'unverified users cannot generate');

  await verifyUser('alice@example.com');
  assert.equal((await meOf('alice')).credits, 10, 'verified signup grants 10 credits');
  assert.equal((await meOf('alice')).verified, true);

  // ---- providers carry pricing + gating ----
  const prov = await j(await req('/api/providers', { user: 'alice' }));
  const ace = prov.providers.find((p) => p.id === 'ace-step');
  assert.ok(ace.ok && ace.durationMax === 240, 'ACE-Step schema read');
  assert.equal(ace.creditCost, 2, 'credit cost advertised');
  assert.equal(ace.allowed, true, 'cheap model allowed on free plan');
  assert.equal(prov.providers.find((p) => p.id === 'minimax-2.5').allowed, false, 'expensive model gated on free plan');
  assert.ok(!prov.providers.find((p) => p.id === 'minimax-2.5').ok, 'unknown model reported unavailable');

  const meCsrf = await j(await req('/api/me', { user: 'alice' }));
  assert.match(meCsrf.csrfToken, /^[0-9a-f]{64}$/, '/api/me returns a CSRF token');

  // ---- generation with credit metering ----
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'hard trap, female rap', lyrics: '[Verse]\nCold hands steady heart\n[Chorus]\nIce ice hammer', duration: 500, seed: 10 } });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  assert.equal(d.tracks.length, 2);
  assert.equal(d.tracks[0].title, 'Cold Hands Steady Heart');
  assert.deepEqual(seen[0], { version: 'ver-ace-step', input: { tags: 'hard trap, female rap', lyrics: '[Verse]\nCold hands steady heart\n[Chorus]\nIce ice hammer', duration: 240, seed: 10 } });
  assert.equal(seen[1].input.seed, 10 + 7919, 'second take gets a different seed');
  assert.equal((await meOf('alice')).credits, 6, '2 takes x 2 credits debited');
  await waitForReady('alice');

  // ---- second user, isolation ----
  r = await req('/api/auth/signup', { method: 'POST', user: 'bob', body: { email: 'bob@example.com', password: 'bob-pass-22' } });
  assert.equal((await j(r)).user.role, 'user', 'second user is not admin');
  await verifyUser('bob@example.com');

  r = await req('/api/auth/verify?token=not-a-real-token');
  assert.equal(r.status, 404, 'malformed verify token rejected');

  r = await req('/api/generate', { method: 'POST', user: 'bob', body: { providerId: 'musicgen', style: 'lofi beat', lyrics: 'hello', duration: 90, takes: 1 } });
  d = await j(r);
  assert.equal(d.tracks.length, 1);
  assert.deepEqual(seen[2].input, { prompt: 'lofi beat', duration: 30, output_format: 'mp3' });
  assert.match(d.tracks[0].notes[0], /instrumentals only/);
  assert.equal(d.tracks[0].title, 'Lofi Beat', 'instrumental-only model is named from the style');
  assert.equal(d.tracks[0].duration, 30, 'library shows the clamped length');
  assert.equal(d.tracks[0].seed, null, 'no seed shown when the model has none');
  assert.equal((await meOf('bob')).credits, 8, 'bob debited 1 take x 2 credits');
  const bobTrackId = d.tracks[0].id;

  const aliceTracks = (await j(await req('/api/tracks', { user: 'alice' }))).tracks;
  const bobTracks = (await j(await req('/api/tracks', { user: 'bob' }))).tracks;
  assert.equal(aliceTracks.length, 2, 'alice sees only her tracks');
  assert.equal(bobTracks.length, 1, 'bob sees only his tracks');
  assert.equal((await req('/api/tracks/' + bobTrackId, { user: 'alice' })).status, 404, 'alice cannot fetch bob track');
  assert.equal((await req(bobTracks[0].audioUrl || '/api/audio/' + bobTrackId, { user: 'alice' })).status, 404, 'alice cannot stream bob audio');

  // ---- tier gating + 402 ----
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'minimax-2.5', style: 'pop', lyrics: 'la la' } });
  assert.equal(r.status, 403, 'expensive model blocked on free plan');

  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y', takes: 1 } });
  assert.equal(r.status, 200);
  assert.equal((await meOf('alice')).credits, 4, '1 take x 2 credits debited');
  await waitForReady('alice');
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y', takes: 1 } });
  assert.equal(r.status, 200);
  assert.equal((await meOf('alice')).credits, 2);
  await waitForReady('alice'); // clear the active-track cap so the 402 path is exercised
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y', takes: 2 } });
  assert.equal(r.status, 402, 'out of credits -> 402');
  assert.match((await j(r)).error, /credits/i);

  // ---- admin spend ----
  r = await req('/api/admin/spend', { user: 'bob' });
  assert.equal(r.status, 403, 'non-admin blocked from spend');
  d = await j(await req('/api/admin/spend', { user: 'alice' }));
  assert.ok(d.perModel.length > 0 && d.perUser.length === 2, 'spend summary has models and users');
  assert.equal(d.totals.generations, 5, 'ledger has 5 generated tracks');
  assert.ok(d.perModel.find((m) => m.provider_id === 'ace-step'), 'ace-step in per-model breakdown');

  // ---- billing: Stripe in mock mode (no network), real webhook signatures ----
  const WHSEC = 'whsec_test_123';
  const signWebhook = (payload, secret) => {
    const t = Math.floor(Date.now() / 1000);
    const v1 = crypto.createHmac('sha256', secret).update(`${t}.${payload}`).digest('hex');
    return `t=${t},v1=${v1}`;
  };
  async function postWebhook(event, secret = WHSEC) {
    const payload = JSON.stringify(event);
    const res = await fetch(base + '/api/billing/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Stripe-Signature': signWebhook(payload, secret) },
      body: payload,
    });
    return res;
  }
  const evt = (id, type, object) => ({ id, type, data: { object } });

  d = await j(await req('/api/billing/config'));
  assert.equal(d.enabled, true, 'billing enabled with mock keys');
  assert.equal(d.plans.length, 3, 'three paid plans');
  assert.deepEqual(d.plans.map((p) => p.id), ['starter', 'creator', 'pro']);
  assert.equal(d.pack.credits, 100, 'credit pack is 100 credits');

  assert.equal((await req('/api/billing/checkout', { method: 'POST', body: { kind: 'pack' } })).status, 401, 'checkout needs a session');
  r = await req('/api/billing/checkout', { method: 'POST', user: 'alice', body: { kind: 'subscription', plan: 'bogus' } });
  assert.equal(r.status, 400, 'unknown plan rejected');
  r = await req('/api/billing/checkout', { method: 'POST', user: 'alice', body: { kind: 'subscription', plan: 'creator' } });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  assert.match(d.url, /^https:\/\/checkout\.stripe\.com/, 'mock checkout url returned');
  r = await req('/api/billing/checkout', { method: 'POST', user: 'alice', body: { kind: 'pack' } });
  assert.equal(r.status, 200, 'credit pack checkout works');
  assert.equal((await req('/api/billing/portal', { user: 'bob' })).status, 400, 'portal needs a billing account');

  // subscription purchase via webhook
  const creditsBefore = (await meOf('alice')).credits;
  r = await postWebhook(evt('evt_sub_1', 'checkout.session.completed', {
    id: 'cs_test_1', mode: 'subscription', customer: 'cus_test_alice', subscription: 'sub_test_1',
    metadata: { userId: aliceId, kind: 'subscription', plan: 'creator' },
  }));
  assert.equal(r.status, 200, 'webhook accepted');
  let m = await meOf('alice');
  assert.equal(m.plan, 'creator', 'plan upgraded by webhook');
  assert.equal(m.credits, creditsBefore + 150, 'monthly credits granted on subscribe');
  assert.equal(m.hasBilling, true, 'hasBilling set');
  assert.equal(m.monthlyCredits, 150, 'monthly allowance exposed');

  // idempotency: Stripe retries must not double-grant
  r = await postWebhook(evt('evt_sub_1', 'checkout.session.completed', {
    id: 'cs_test_1', mode: 'subscription', customer: 'cus_test_alice', subscription: 'sub_test_1',
    metadata: { userId: aliceId, kind: 'subscription', plan: 'creator' },
  }));
  assert.equal(r.status, 200);
  assert.deepEqual(await j(r), { received: true, ok: true, duplicate: true });
  assert.equal((await meOf('alice')).credits, creditsBefore + 150, 'replay grants nothing');

  // credit pack purchase
  r = await postWebhook(evt('evt_pack_1', 'checkout.session.completed', {
    id: 'cs_test_2', mode: 'payment', customer: 'cus_test_alice',
    metadata: { userId: aliceId, kind: 'pack', credits: '100' },
  }));
  assert.equal(r.status, 200);
  assert.equal((await meOf('alice')).credits, creditsBefore + 250, 'pack credits stack');

  // first invoice of a subscription is covered by checkout.session.completed
  r = await postWebhook(evt('evt_inv_1', 'invoice.paid', {
    id: 'in_test_1', customer: 'cus_test_alice', subscription: 'sub_test_1', billing_reason: 'subscription_create',
  }));
  assert.equal(r.status, 200);
  assert.equal((await meOf('alice')).credits, creditsBefore + 250, 'subscription_create invoice grants nothing');

  // renewal invoice refills
  r = await postWebhook(evt('evt_inv_2', 'invoice.paid', {
    id: 'in_test_2', customer: 'cus_test_alice', subscription: 'sub_test_1', billing_reason: 'subscription_cycle',
  }));
  assert.equal(r.status, 200);
  assert.equal((await meOf('alice')).credits, creditsBefore + 400, 'renewal refills monthly credits');

  // portal works once the customer exists
  r = await req('/api/billing/portal', { user: 'alice' });
  assert.equal(r.status, 200);
  assert.match((await j(r)).url, /^https:\/\/billing\.stripe\.com/, 'mock portal url');

  // subscription cancelled -> downgrade to free, credits kept
  r = await postWebhook(evt('evt_del_1', 'customer.subscription.deleted', { id: 'sub_test_1', customer: 'cus_test_alice' }));
  assert.equal(r.status, 200);
  m = await meOf('alice');
  assert.equal(m.plan, 'free', 'downgraded to free');
  assert.equal(m.credits, creditsBefore + 400, 'paid-for credits are kept');

  // unknown event types are ignored, not errors
  r = await postWebhook(evt('evt_unk_1', 'customer.updated', { id: 'cus_test_alice' }));
  assert.equal(r.status, 200, 'unknown event type ignored');

  // tampered signature rejected
  r = await postWebhook(evt('evt_bad_1', 'invoice.paid', { id: 'in_bad' }), 'wrong-secret');
  assert.equal(r.status, 400, 'bad webhook signature rejected');

  // ---- CSRF enforcement ----
  const genBody = { providerId: 'ace-step', style: 'x', lyrics: 'y', takes: 1 };
  r = await req('/api/generate', { method: 'POST', user: 'alice', noCsrf: true, body: genBody });
  assert.equal(r.status, 403, 'state-changing POST without CSRF token is rejected');
  r = await req('/api/generate', { method: 'POST', user: 'alice', noCsrf: true, headers: { 'X-CSRF-Token': '0'.repeat(64) }, body: genBody });
  assert.equal(r.status, 403, 'wrong CSRF token is rejected');
  // the Stripe webhook is exempt: signature auth instead of CSRF, even with a session cookie
  const whPayload = JSON.stringify(evt('evt_csrf_1', 'customer.updated', { id: 'cus_csrf' }));
  const whRes = await fetch(base + '/api/billing/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Stripe-Signature': signWebhook(whPayload, WHSEC), Cookie: jar.alice },
    body: whPayload,
  });
  assert.equal(whRes.status, 200, 'webhook skips CSRF even with a session cookie');

  // ---- studio mixer: stem separation (mock demucs) ----
  r = await req('/api/auth/signup', { method: 'POST', user: 'carol', body: { email: 'carol@example.com', password: 'carol-pass-1' } });
  assert.equal(r.status, 200);
  await verifyUser('carol@example.com');
  assert.equal((await meOf('carol')).credits, 10, 'carol starts with 10 credits');

  r = await req('/api/generate', { method: 'POST', user: 'carol', body: { providerId: 'ace-step', style: 'funk', lyrics: 'get down', takes: 1 } });
  assert.equal(r.status, 200);
  const carolTrackA = (await j(r)).tracks[0].id;
  await waitForReady('carol');
  assert.equal((await meOf('carol')).credits, 8, 'carol debited 2 for 1 take');

  // stem list before splitting
  d = await j(await req(`/api/tracks/${carolTrackA}/stems`, { user: 'carol' }));
  assert.deepEqual(d.stems, [], 'no stems before splitting');
  assert.equal(d.cost, '6 credits/song', 'stem cost advertised');
  assert.equal((await req('/api/tracks/0123456789abcdef/stems', { user: 'carol' })).status, 404, 'stems of unknown track -> 404');
  assert.equal((await req(`/api/tracks/${carolTrackA}/stems`, { method: 'POST', user: 'carol', noCsrf: true, body: {} })).status, 403, 'stem split needs CSRF');

  // debit-first split
  r = await req(`/api/tracks/${carolTrackA}/stems`, { method: 'POST', user: 'carol', body: {} });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  assert.equal(d.charged, true, 'first split charges');
  assert.equal(d.stems.length, 4, 'four stems created');
  assert.deepEqual(d.stems.map((s) => s.name).sort(), ['bass', 'drums', 'other', 'vocals']);
  assert.equal((await meOf('carol')).credits, 2, '6 credits debited for separation');

  // the demucs input got the mixed audio as a data URI + the htdemucs variant
  const demucsCall = seen.find((b) => b.version === 'ver-demucs');
  assert.ok(demucsCall, 'a demucs prediction was created');
  assert.match(demucsCall.input.audio, /^data:audio\/mpeg;base64,/, 'mixed audio sent as data URI');
  assert.equal(demucsCall.input.model_name, 'htdemucs', 'htdemucs variant selected');
  assert.equal(demucsCall.input.output_format, 'mp3', 'mp3 output selected');

  // wait for stems to finish, then they stream like track audio
  let stems;
  for (let i = 0; i < 60; i++) {
    stems = (await j(await req(`/api/tracks/${carolTrackA}/stems`, { user: 'carol' }))).stems;
    if (stems.length === 4 && stems.every((s) => s.status === 'ready')) break;
    await sleep(200);
  }
  assert.ok(stems.every((s) => s.status === 'ready'), 'all four stems finished');
  assert.ok(stems.every((s) => s.audioUrl), 'every stem has an audio URL');
  const stemAudio = await req(stems[0].audioUrl, { user: 'carol' });
  assert.equal(stemAudio.status, 200, 'stem audio streams');
  assert.equal(stemAudio.headers.get('content-length'), '5000');
  assert.equal((await req(stems[0].audioUrl, { user: 'alice' })).status, 404, 'other users cannot stream stems');

  // idempotent: splitting again charges nothing
  r = await req(`/api/tracks/${carolTrackA}/stems`, { method: 'POST', user: 'carol', body: {} });
  d = await j(r);
  assert.equal(d.charged, false, 're-split of ready stems is free');
  assert.equal((await meOf('carol')).credits, 2, 'no double charge');

  // 400 when the song is not ready yet
  r = await req('/api/auth/signup', { method: 'POST', user: 'dave', body: { email: 'dave@example.com', password: 'dave-pass-22' } });
  assert.equal(r.status, 200);
  await verifyUser('dave@example.com');
  r = await req('/api/generate', { method: 'POST', user: 'dave', body: { providerId: 'ace-step', style: 'rock', lyrics: 'loud', takes: 1 } });
  const daveTrack = (await j(r)).tracks[0].id;
  r = await req(`/api/tracks/${daveTrack}/stems`, { method: 'POST', user: 'dave', body: {} });
  assert.equal(r.status, 400, 'cannot split an unfinished song');
  await waitForReady('dave');

  // 402 when broke: carol has 2 credits, splitting needs 6
  r = await req('/api/generate', { method: 'POST', user: 'carol', body: { providerId: 'ace-step', style: 'jazz', lyrics: 'smooth', takes: 1 } });
  assert.equal(r.status, 200);
  const carolTrackB = (await j(r)).tracks[0].id;
  await waitForReady('carol');
  assert.equal((await meOf('carol')).credits, 0, 'carol spent her last credits');
  r = await req(`/api/tracks/${carolTrackB}/stems`, { method: 'POST', user: 'carol', body: {} });
  assert.equal(r.status, 402, 'out of credits -> 402 for stems');
  assert.match((await j(r)).error, /credits/i);

  // refund path: a separation that fails after it started ('processing' -> 'failed') must refund once
  {
    const carol = dbm.getUserByEmail('carol@example.com');
    const sepId = 'f'.repeat(16);
    dbm.addCredits(carol.id, 6, 'test-topup');
    dbm.addCredits(carol.id, -6, 'stems');
    dbm.addSeparation({ id: sepId, userId: carol.id, trackId: carolTrackB, model: 'ryan5453/demucs', creditsDebited: 6, estCostUsd: 0 });
    dbm.updateSeparation(sepId, { status: 'processing', replicate_prediction_id: 'predX' });
    const credBefore = (await meOf('carol')).credits;
    dbm.updateSeparation(sepId, { status: 'failed', finished_at: Date.now() }); // what failSeparation does first
    assert.equal(dbm.refundSeparation(sepId), 6, 'failed separation refunds its credits');
    assert.equal((await meOf('carol')).credits, credBefore + 6, 'credits returned to the user');
    assert.equal(dbm.refundSeparation(sepId), 0, 'refund happens exactly once');
    assert.equal(dbm.getSeparation(sepId).status, 'refunded');
  }

  // ---- studio mixer: NAM capture library ----
{
  const carol = dbm.getUserByEmail('carol@example.com');
  const sepId = 'f'.repeat(16);
  dbm.addCredits(carol.id, 6, 'test-topup');
  dbm.addCredits(carol.id, -6, 'stems');
  dbm.addSeparation({ id: sepId, userId: carol.id, trackId: carolTrackB, model: 'ryan5453/demucs', creditsDebited: 6, estCostUsd: 0 });
  dbm.updateSeparation(sepId, { status: 'processing', replicate_prediction_id: 'predX' });
  const credBefore = (await meOf('carol')).credits;
  dbm.updateSeparation(sepId, { status: 'failed', finished_at: Date.now() }); // what failSeparation does first
  assert.equal(dbm.refundSeparation(sepId), 6, 'failed separation refunds its credits');
  assert.equal((await meOf('carol')).credits, credBefore + 6, 'credits returned to the user');
  assert.equal(dbm.refundSeparation(sepId), 0, 'refund happens exactly once');
  assert.equal(dbm.getSeparation(sepId).status, 'refunded');
}

// ---- studio mixer: NAM capture library ----
  const namJson = { architecture: 'WaveNet', config: { input_gain: 1 }, weights: [0.1, 0.2, 0.3], version: '1.0' };
  const namB64 = Buffer.from(JSON.stringify(namJson)).toString('base64');
  r = await req('/api/nam', { method: 'POST', user: 'carol', noCsrf: true, body: { name: 'My Capture', data: namB64 } });
  assert.equal(r.status, 403, 'NAM upload needs CSRF');
  r = await req('/api/nam', { method: 'POST', user: 'carol', body: { name: 'My Capture', data: namB64 } });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  const capId = d.capture.id;
  assert.equal(d.capture.name, 'My Capture');
  assert.ok(d.capture.size > 0);

  d = await j(await req('/api/nam', { user: 'carol' }));
  assert.equal(d.captures.length, 1, 'one capture listed');
  assert.equal(d.captures[0].name, 'My Capture');
  d = await j(await req('/api/nam?q=my', { user: 'carol' }));
  assert.equal(d.captures.length, 1, 'search matches by name');
  d = await j(await req('/api/nam?q=zzz-no-match', { user: 'carol' }));
  assert.equal(d.captures.length, 0, 'search filters');

  // per-user isolation
  assert.equal((await req('/api/nam/' + capId, { user: 'dave' })).status, 404, 'dave cannot download carol capture');
  assert.equal((await req('/api/nam/' + capId, { method: 'DELETE', user: 'dave' })).status, 404, 'dave cannot delete carol capture');

  // download round-trips the file
  r = await req('/api/nam/' + capId, { user: 'carol' });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition'), /attachment/);
  assert.deepEqual(JSON.parse(await r.text()), namJson, 'downloaded capture matches upload');

  // validation
  r = await req('/api/nam', { method: 'POST', user: 'carol', body: { name: 'bad', data: Buffer.from('not json').toString('base64') } });
  assert.equal(r.status, 400, 'non-JSON rejected');
  r = await req('/api/nam', { method: 'POST', user: 'carol', body: { name: 'bad', data: Buffer.from(JSON.stringify({ foo: 1 })).toString('base64') } });
  assert.equal(r.status, 400, 'JSON without weights rejected');
  r = await req('/api/nam', { method: 'POST', user: 'carol', body: { name: 'bad' } });
  assert.equal(r.status, 400, 'missing data rejected');

  // delete
  r = await req('/api/nam/' + capId, { method: 'DELETE', user: 'carol' });
  assert.equal(r.status, 200);
  assert.equal((await j(await req('/api/nam', { user: 'carol' }))).captures.length, 0, 'capture deleted');
  assert.equal((await req('/api/nam/' + capId, { method: 'DELETE', user: 'carol' })).status, 404, 'double delete -> 404');
  assert.equal((await req('/api/nam', { user: 'anon' })).status, 401, 'NAM list needs a session');

  // ---- creator referrals ----
  // dave (existing user) generates a code
  r = await req('/api/referrals/code', { method: 'POST', user: 'dave' });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  const daveCode = d.code;
  assert.match(daveCode, /^[A-Za-z0-9_-]{8}$/, 'code is 8 url-safe chars');
  assert.ok(d.link.endsWith('/r/' + daveCode), 'link ends with /r/CODE');
  r = await req('/api/referrals/code', { method: 'POST', user: 'dave' });
  assert.equal((await j(r)).code, daveCode, 'code generation is idempotent');
  assert.equal((await req('/api/referrals/code', { method: 'POST', user: 'anon' })).status, 401, 'code needs a session');
  assert.equal((await req('/api/referrals/code', { method: 'POST', user: 'dave', noCsrf: true, body: {} })).status, 403, 'code needs CSRF');

  // /r/CODE: click counted, cookie set, redirect to /
  r = await req('/r/' + daveCode, { user: 'visitor' });
  assert.equal(r.status, 302, 'referral link redirects');
  assert.equal(r.headers.get('location'), '/', 'redirects to landing page');
  const refCookie = r.headers.get('set-cookie') || '';
  assert.match(refCookie, /ich_ref=/, 'attribution cookie set');
  assert.ok(refCookie.includes(daveCode), 'cookie carries the code');
  assert.match(refCookie, /Max-Age=7776000/, '90-day attribution window');
  r = await req('/r/NOPE1234', { user: 'anonX' });
  assert.equal(r.status, 302, 'unknown code still redirects');
  assert.ok(!(r.headers.get('set-cookie') || '').includes('ich_ref'), 'no cookie for unknown code');

  // signup in the same browser -> attributed to dave
  r = await req('/api/auth/signup', { method: 'POST', user: 'visitor', body: { email: 'frank@example.com', password: 'frank-pass-1' } });
  assert.equal(r.status, 200, JSON.stringify(await j(r.clone())));
  const frankId = (await j(r)).user.id;
  const frankAttr = dbm.getAttribution(frankId);
  assert.ok(frankAttr, 'signup attributed');
  assert.equal(frankAttr.code, daveCode, "attributed to dave's code");

  // uniqueness: frank's code differs; users without a code get nulls
  r = await req('/api/referrals/code', { method: 'POST', user: 'visitor' });
  assert.notEqual((await j(r)).code, daveCode, 'codes are unique per user');
  d = await j(await req('/api/referrals/me', { user: 'bob' }));
  assert.equal(d.code, null, 'no code yet -> null');
  assert.equal(d.link, null);

  // self-referral is rejected; invalid codes are ignored silently
  assert.equal(dbm.attributeUser((await meOf('dave')).id, daveCode), null, 'self-referral rejected');
  assert.equal(dbm.attributeUser(frankId, 'NOPE1234'), null, 'invalid code ignored');

  // dashboard stats
  d = await j(await req('/api/referrals/me', { user: 'dave' }));
  assert.equal(d.clicks, 1, 'one click counted');
  assert.equal(d.signups, 1, 'one signup attributed');
  assert.equal(d.activeSubscribers, 0, 'no paying subscribers yet');
  assert.equal(d.balanceCents, 0, 'no earnings yet');
  assert.equal(d.payoutThresholdCents, 5000, 'payout threshold advertised');
  assert.equal(d.connectReady, false, 'no payout account yet');
  assert.deepEqual(d.rates, { subscription: 0.25, pack: 0.10, windowMonths: 12 }, 'rates advertised');

  // commission: frank subscribes to Creator ($8.99) -> dave earns 25% = 225c
  r = await postWebhook(evt('evt_ref_sub_1', 'checkout.session.completed', {
    id: 'cs_ref_1', mode: 'subscription', customer: 'cus_test_frank', subscription: 'sub_test_frank',
    metadata: { userId: frankId, kind: 'subscription', plan: 'creator' },
  }));
  assert.equal(r.status, 200, 'webhook accepted');
  d = await j(await req('/api/referrals/me', { user: 'dave' }));
  assert.equal(d.balanceCents, 225, '25% of $8.99 Creator sub = 225c');
  assert.equal(d.activeSubscribers, 1, 'frank counts as a paying subscriber');

  // idempotency: the same event twice accrues once
  r = await postWebhook(evt('evt_ref_sub_1', 'checkout.session.completed', {
    id: 'cs_ref_1', mode: 'subscription', customer: 'cus_test_frank', subscription: 'sub_test_frank',
    metadata: { userId: frankId, kind: 'subscription', plan: 'creator' },
  }));
  assert.deepEqual(await j(r), { received: true, ok: true, duplicate: true });
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, 225, 'replay accrues nothing');

  // renewal -> another 25%
  r = await postWebhook(evt('evt_ref_inv_1', 'invoice.paid', {
    id: 'in_ref_1', customer: 'cus_test_frank', subscription: 'sub_test_frank',
    billing_reason: 'subscription_cycle', amount_paid: 899,
  }));
  assert.equal(r.status, 200);
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, 450, 'renewal accrues another 225c');

  // credit pack -> 10% of $6.99 = 70c
  r = await postWebhook(evt('evt_ref_pack_1', 'checkout.session.completed', {
    id: 'cs_ref_2', mode: 'payment', customer: 'cus_test_frank', payment_intent: 'pi_ref_1',
    amount_total: 699, metadata: { userId: frankId, kind: 'pack', credits: '100' },
  }));
  assert.equal(r.status, 200);
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, 520, '10% of $6.99 pack = 70c');

  // 12-month window: first paid 13 months ago -> no accrual
  dbm.setAttributionFirstPaid(frankId, Date.now() - 13 * 30 * 24 * 3600 * 1000);
  r = await postWebhook(evt('evt_ref_inv_2', 'invoice.paid', {
    id: 'in_ref_2', customer: 'cus_test_frank', subscription: 'sub_test_frank',
    billing_reason: 'subscription_cycle', amount_paid: 899,
  }));
  assert.equal(r.status, 200);
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, 520, 'no accrual after the 12-month window');
  dbm.setAttributionFirstPaid(frankId, Date.now()); // back inside the window

  // refund of the pack charge -> claw back the 70c commission
  r = await postWebhook(evt('evt_ref_refund_1', 'charge.refunded', {
    id: 'ch_ref_1', customer: 'cus_test_frank', amount: 699, amount_refunded: 699,
  }));
  assert.equal(r.status, 200);
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, 450, 'pack commission clawed back');

  // payout below the $50 threshold -> 400
  r = await req('/api/referrals/payout', { method: 'POST', user: 'dave' });
  assert.equal(r.status, 400, 'payout below threshold rejected');
  assert.match((await j(r)).error, /50/);

  // connect onboarding (mock)
  r = await req('/api/referrals/connect', { user: 'dave' });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  assert.match(d.url, /^https:\/\/connect\.stripe\.com/, 'mock connect onboarding url');
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).connectReady, true, 'connect account recorded');

  // payout without a connected account -> 400 (disconnect at the DB level, then accrue past $50)
  const daveId = (await meOf('dave')).id;
  dbm.setStripeConnectId(daveId, null);
  for (let i = 0; i < 21; i++) {
    r = await postWebhook(evt('evt_ref_bulk_' + i, 'invoice.paid', {
      id: 'in_ref_bulk_' + i, customer: 'cus_test_frank', subscription: 'sub_test_frank',
      billing_reason: 'subscription_cycle', amount_paid: 899,
    }));
    assert.equal(r.status, 200, 'bulk renewal ' + i + ' accepted');
  }
  const bulkTotal = 450 + 21 * 225;
  assert.equal((await j(await req('/api/referrals/me', { user: 'dave' }))).balanceCents, bulkTotal, 'bulk renewals accrued');
  r = await req('/api/referrals/payout', { method: 'POST', user: 'dave' });
  assert.equal(r.status, 400, 'payout without a payout account rejected');
  assert.match((await j(r)).error, /connect/i);

  // reconnect and pay out the full balance
  r = await req('/api/referrals/connect', { user: 'dave' });
  assert.equal(r.status, 200);
  r = await req('/api/referrals/payout', { method: 'POST', user: 'dave' });
  d = await j(r);
  assert.equal(r.status, 200, JSON.stringify(d));
  assert.match(d.transferId, /^tr_mock_/, 'mock transfer created');
  assert.equal(d.amountCents, bulkTotal, 'full balance paid out');
  const afterPayout = await j(await req('/api/referrals/me', { user: 'dave' }));
  assert.equal(afterPayout.balanceCents, 0, 'balance zeroed after payout');
  assert.equal(afterPayout.paidOutCents, bulkTotal, 'paid-out total recorded');
  r = await req('/api/referrals/payout', { method: 'POST', user: 'dave' });
  assert.equal(r.status, 400, 'empty balance cannot pay out');

  // concurrent payouts must pay a given balance once, never twice
  for (let i = 0; i < 23; i++) {
    r = await postWebhook(evt('evt_ref_race_' + i, 'invoice.paid', {
      id: 'in_ref_race_' + i, customer: 'cus_test_frank', subscription: 'sub_test_frank',
      billing_reason: 'subscription_cycle', amount_paid: 899,
    }));
    assert.equal(r.status, 200, 'race renewal ' + i + ' accepted');
  }
  const raceTotal = 23 * 225;
  const racers = await Promise.all([1, 2, 3].map(() => req('/api/referrals/payout', { method: 'POST', user: 'dave' })));
  const raceOk = racers.filter((x) => x.status === 200);
  assert.equal(raceOk.length, 1, 'exactly one concurrent payout succeeds: ' + racers.map((x) => x.status));
  const afterRace = await j(await req('/api/referrals/me', { user: 'dave' }));
  assert.equal(afterRace.paidOutCents, bulkTotal + raceTotal, 'balance paid exactly once');
  assert.equal(afterRace.balanceCents, 0, 'nothing left unpaid');

  // admin spend view includes referral liabilities
  d = await j(await req('/api/admin/spend', { user: 'alice' }));
  const daveLiab = (d.referrals || []).find((x) => x.email === 'dave@example.com');
  assert.ok(daveLiab, 'dave appears in referral liabilities');
  assert.equal(daveLiab.paid_cents, bulkTotal + raceTotal, 'liability shows paid total');
  assert.equal(daveLiab.signups, 1, 'liability shows signup count');

  // ---- billing disabled without keys: graceful 503s ----
  const dataDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ich-nokey-'));
  const app2 = spawn(process.execPath, ['server.mjs'], {
    cwd: path.join(path.dirname(new URL(import.meta.url).pathname), '..'),
    env: {
      ...process.env, PORT: String(APP_PORT + 1), DATA_DIR: dataDir2,
      SESSION_SECRET: 'test-secret-2', EMAIL_AUTO_VERIFY: '1',
      // no STRIPE_* vars on purpose
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    const base2 = `http://127.0.0.1:${APP_PORT + 1}`;
    for (let i = 0; i < 50; i++) { try { await fetch(base2 + '/api/health'); break; } catch { await sleep(100); } }
    assert.equal((await (await fetch(base2 + '/api/billing/config')).json()).enabled, false, 'billing disabled without keys');
    const rs = await fetch(base2 + '/api/auth/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'nokey@example.com', password: 'nokey-pass-1' }) });
    assert.equal(rs.status, 200);
    const ck2 = (rs.headers.get('set-cookie') || '').split(';')[0];
    const me2 = await (await fetch(base2 + '/api/me', { headers: { Cookie: ck2 } })).json();
    const rc = await fetch(base2 + '/api/billing/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: ck2, 'X-CSRF-Token': me2.csrfToken }, body: JSON.stringify({ kind: 'pack' }) });
    assert.equal(rc.status, 503, 'checkout is 503 without keys');
    const rw = await fetch(base2 + '/api/billing/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(rw.status, 503, 'webhook is 503 without webhook secret');

    // ---- rate limiting: 10 auth attempts/min per IP (1 used above) ----
    for (let i = 0; i < 9; i++) {
      const rr = await fetch(base2 + '/api/auth/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: `rl${i}@example.com`, password: 'rate-limit-1' }) });
      assert.equal(rr.status, 200, `auth attempt ${i + 2}/10 allowed`);
    }
    const limited = await fetch(base2 + '/api/auth/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'rl-last@example.com', password: 'rate-limit-1' }) });
    assert.equal(limited.status, 429, '11th auth attempt within a minute is rate-limited');
    assert.ok(Number(limited.headers.get('retry-after')) >= 1, 'Retry-After header present');
    assert.match((await limited.json()).error, /too many/i);
    const limitedLogin = await fetch(base2 + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'nokey@example.com', password: 'wrong' }) });
    assert.equal(limitedLogin.status, 429, 'login shares the auth rate-limit bucket');
  } finally {
    app2.kill();
  }

  // ---- logout / login ----
  await req('/api/auth/logout', { user: 'alice', method: 'POST' });
  delete jar.alice; delete csrf.alice;
  assert.equal((await req('/api/me', { user: 'alice' })).status, 401, 'logged out');
  r = await req('/api/auth/login', { method: 'POST', user: 'alice', body: { email: 'alice@example.com', password: 'alice-pass-1' } });
  assert.equal(r.status, 200, 'login works again');

  // ---- wait for everything to finish (alice: 4 tracks, bob: 1) ----
  let tracks;
  for (let i = 0; i < 40; i++) {
    const a = (await j(await req('/api/tracks', { user: 'alice' }))).tracks;
    const b = (await j(await req('/api/tracks', { user: 'bob' }))).tracks;
    tracks = [...a, ...b];
    if (tracks.every((t) => t.status === 'ready')) break;
    await sleep(200);
  }
  assert.ok(tracks.every((t) => t.status === 'ready'), 'all tracks finished: ' + JSON.stringify(tracks.map((t) => [t.status, t.error])));

  const a0 = (await j(await req('/api/tracks', { user: 'alice' }))).tracks[0];
  const a = await req(a0.audioUrl, { user: 'alice', headers: { Range: 'bytes=0-99' } });
  assert.equal(a.status, 206); assert.equal((await a.arrayBuffer()).byteLength, 100);
  assert.equal((await req(a0.audioUrl, { user: 'alice' })).headers.get('content-length'), '5000');

  // validation + delete (per-user audio dir)
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: {} });
  assert.equal(r.status, 400);
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y', duration: -5 } });
  assert.equal(r.status, 400, 'negative duration rejected');
  r = await req('/api/generate', { method: 'POST', user: 'alice', body: { providerId: 'ace-step', style: 'x', lyrics: 'y', duration: 'not-a-number' } });
  assert.equal(r.status, 400, 'NaN duration rejected');
  r = await req('/api/tracks/' + a0.id, { user: 'alice', method: 'DELETE' });
  assert.equal(r.status, 200);
  assert.equal((await req('/api/tracks/' + a0.id, { user: 'alice' })).status, 404);
  const audioDir = path.join(dataDir, 'audio', aliceId);
  assert.ok(!fs.existsSync(path.join(audioDir, a0.id + '.mp3')), 'audio file removed from per-user dir');

  // ---- migration script: old library.json -> SQLite + per-user audio ----
  const migDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ich-mig-'));
  const oldTracks = [
    { id: 'a1b2c3d4e5f60718', title: 'Old Song', style: 'trap', lyrics: 'yo', instrumental: false, duration: 120, seed: 42, providerId: 'ace-step', take: null, status: 'ready', error: null, notes: ['imported'], audioFile: 'a1b2c3d4e5f60718.mp3', createdAt: Date.now() - 100000, finishedAt: Date.now() - 90000 },
    { id: 'b1b2c3d4e5f60719', title: 'No Audio', style: 'lofi', lyrics: '', instrumental: true, duration: 30, seed: null, providerId: 'musicgen', take: null, status: 'ready', error: null, notes: [], audioFile: 'gone.mp3', createdAt: Date.now(), finishedAt: Date.now() },
  ];
  fs.writeFileSync(path.join(migDir, 'library.json'), JSON.stringify(oldTracks));
  fs.mkdirSync(path.join(migDir, 'audio'), { recursive: true });
  fs.writeFileSync(path.join(migDir, 'audio', 'a1b2c3d4e5f60718.mp3'), Buffer.alloc(100, 9));
  const saasRoot = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
  const mig = spawnSync(process.execPath, ['scripts/migrate-json.mjs', '--data-dir', migDir, '--email', 'mig@example.com'], { cwd: saasRoot, encoding: 'utf8' });
  assert.equal(mig.status, 0, 'migrate exits 0: ' + mig.stderr);
  const migSummary = JSON.parse(mig.stdout.trim().split('\n').pop());
  assert.equal(migSummary.migrated, 2, 'both tracks migrated');
  assert.equal(migSummary.audioMoved, 1, 'one audio file moved');
  assert.equal(migSummary.audioMissing, 1, 'one audio file reported missing');
  const migUserId = migSummary.userId;
  assert.ok(!fs.existsSync(path.join(migDir, 'audio', 'a1b2c3d4e5f60718.mp3')), 'old flat audio file is gone');
  assert.ok(fs.existsSync(path.join(migDir, 'audio', migUserId, 'a1b2c3d4e5f60718.mp3')), 'audio moved to per-user dir');
  // re-run is idempotent
  const mig2 = spawnSync(process.execPath, ['scripts/migrate-json.mjs', '--data-dir', migDir, '--email', 'mig@example.com'], { cwd: saasRoot, encoding: 'utf8' });
  assert.equal(mig2.status, 0, 're-run exits 0: ' + mig2.stderr);
  assert.equal(JSON.parse(mig2.stdout.trim().split('\n').pop()).migrated, 0, 're-run migrates nothing');
  // dry-run changes nothing
  const mig3 = spawnSync(process.execPath, ['scripts/migrate-json.mjs', '--data-dir', migDir, '--email', 'dry@example.com', '--dry-run'], { cwd: saasRoot, encoding: 'utf8' });
  assert.equal(mig3.status, 0, 'dry-run exits 0');
  assert.match(mig3.stdout, /DRY RUN/, 'dry-run says so');

  console.log('All smoke tests passed.');
} catch (e) {
  console.error('FAILED:', e.message, '\n--- server log ---\n' + log);
  process.exitCode = 1;
} finally {
  app.kill(); mock.close();
}
