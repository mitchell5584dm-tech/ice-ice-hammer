// Ice Ice Hammer: multi-user SaaS (Phase 1).
// email+password accounts, per-user libraries, credit-metered generation.
// Zero npm dependencies: Node 22.5+ only (node:sqlite). Start with `node server.mjs`.
import './lib/env.mjs';
import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { PROVIDERS, getProvider } from './lib/providers.mjs';
import { getModelInfo, buildInput, createPrediction, getPrediction, cancelPrediction, pickAudioUrl } from './lib/replicate.mjs';
import {
  initDb, transact, userCount, createUser, getUserById, getUserByEmail, getUserByVerifyToken,
  addCredits, setUserVerified, setUserPlan, cryptoId,
  addTrack, getTrack, listTracks, listActiveTracks, listStuckTracks, updateTrack, removeTrack,
  activeCountForUser, addLedgerEntry, markLedgerDone, refundLedger, spendSummary, AUDIO_DIR,
} from './lib/db.mjs';
import {
  hashPassword, verifyPassword, signSession, getSessionUserId, parseCookies,
  sessionCookieHeader, newVerifyToken, sendVerifyLinkStub, autoVerify, publicUser, isValidEmail,
  csrfTokenFor, verifyCsrfToken,
} from './lib/auth.mjs';
import { checkRateLimit, clientIp } from './lib/ratelimit.mjs';
import { costFor, canUseModel, estUsdFor, FREE_SIGNUP_CREDITS, ELEVENLABS_MAX_DURATION, ELEVENLABS_CREDITS_PER_SEC, costLabel, PLANS } from './lib/costs.mjs';
import {
  billingEnabled, billingConfig, createCheckoutSession, createPortalSession,
  verifyWebhookSignature, handleWebhookEvent,
} from './lib/billing.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);
const MAX_ACTIVE = Number(process.env.MAX_ACTIVE_GENERATIONS || 6); // global backstop
const USER_MAX_ACTIVE = Number(process.env.USER_MAX_ACTIVE_GENERATIONS || 2); // per-user cap
const POLL_MS = Number(process.env.POLL_MS || 4000);
const GIVE_UP_MS = 25 * 60 * 1000;

const LIMITS = { style: 1000, lyrics: 5000, title: 80, email: 254, password: 128 };
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
const AUDIO_MIME = { mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', ogg: 'audio/ogg', m4a: 'audio/mp4', aac: 'audio/aac' };

// ---------- helpers ----------
// Baseline security headers on every response. Cache-Control is set per
// route: 'no-store' for all API responses (they carry per-user data),
// 'no-cache' for the HTML shell (revalidate each load), and
// 'private, max-age=…' only for per-user audio streams.
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

const send = (res, code, body, headers = {}) => {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(code, {
    ...SECURITY_HEADERS,
    'Content-Type': isObj ? 'application/json' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(isObj ? JSON.stringify(body) : body);
};

async function readJson(req, max = 64 * 1024) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > max) throw Object.assign(new Error('Request too large'), { status: 413 }); chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw Object.assign(new Error('Body must be JSON'), { status: 400 }); }
}

// Raw bytes for Stripe webhook signature verification (must NOT be JSON-parsed first).
async function readRaw(req, max = 256 * 1024) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > max) throw Object.assign(new Error('Request too large'), { status: 413 }); chunks.push(c); }
  return Buffer.concat(chunks);
}

// Session -> user. Throws { status: 401 } when not signed in.
function requireUser(req) {
  const userId = getSessionUserId(req);
  const user = userId ? getUserById(userId) : null;
  if (!user) throw Object.assign(new Error('Sign in to continue.'), { status: 401 });
  return user;
}

function requireAdmin(req) {
  const user = requireUser(req);
  if (user.role !== 'admin') throw Object.assign(new Error('Admin only.'), { status: 403 });
  return user;
}

// Brute-force backstop on the auth endpoints: 10 signup+login attempts per
// minute per IP (shared bucket). Answers 429 with Retry-After.
function checkAuthRateLimit(req, res) {
  const { allowed, retryAfter } = checkRateLimit(`auth:${clientIp(req)}`, { limit: 10, windowMs: 60 * 1000 });
  if (!allowed) {
    send(res, 429, { error: 'Too many attempts. Try again shortly.' }, { 'Retry-After': String(retryAfter) });
    return false;
  }
  return true;
}

// CSRF: cookie-authenticated POST/PUT/DELETE must carry the per-user token
// from GET /api/me as X-CSRF-Token. Skipped for signup/login (no session yet)
// and the Stripe webhook (HMAC-signature auth instead). Unauthenticated
// requests are left alone here — requireUser answers 401 for them.
const CSRF_SKIP = new Set(['/api/auth/signup', '/api/auth/login', '/api/billing/webhook']);
function checkCsrf(req, pathname) {
  const method = req.method;
  if (method !== 'POST' && method !== 'PUT' && method !== 'DELETE') return;
  if (CSRF_SKIP.has(pathname)) return;
  const userId = getSessionUserId(req);
  const user = userId ? getUserById(userId) : null;
  if (!user) return; // no valid session: requireUser will 401
  const got = req.headers['x-csrf-token'];
  if (!verifyCsrfToken(user.id, got))
    throw Object.assign(new Error('Invalid or missing CSRF token. Refresh the page and try again.'), { status: 403 });
}

const newId = () => crypto.randomBytes(8).toString('hex');
const clean = (s, max) => String(s ?? '').replace(/\r\n/g, '\n').slice(0, max);

function autoTitle(lyrics, style) {
  const lines = String(lyrics || '').split('\n').map((l) => l.trim()).filter((l) => l && !/^[\[(]/.test(l));
  const src = lines[0] || String(style || '').split(',')[0] || 'Untitled';
  const words = src.replace(/[^\p{L}\p{N}' ]/gu, '').split(/\s+/).filter(Boolean).slice(0, 4).join(' ');
  return (words || 'Untitled').replace(/\b\p{L}/gu, (c) => c.toUpperCase());
}

const publicTrack = (t) => ({
  id: t.id, title: t.title, style: t.style, lyrics: t.lyrics, instrumental: t.instrumental, duration: t.duration,
  seed: t.seed, providerId: t.providerId, take: t.take, status: t.status, error: t.error || null, notes: t.notes || [],
  createdAt: t.createdAt, finishedAt: t.finishedAt || null, audioUrl: t.audioFile ? `/api/audio/${t.id}` : null,
});

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return `${proto}://${req.headers.host || 'localhost'}`;
}

// ---------- auth routes ----------
async function handleSignup(req, res) {
  const body = await readJson(req);
  if (!checkAuthRateLimit(req, res)) return;
  const email = clean(body.email, LIMITS.email).trim().toLowerCase();
  if (typeof body.password !== 'string' || !body.password)
    return send(res, 400, { error: 'Password must be at least 8 characters.' });
  const password = body.password.slice(0, LIMITS.password);
  if (!isValidEmail(email)) return send(res, 400, { error: 'Enter a valid email address.' });
  let passwordHash;
  try { passwordHash = hashPassword(password); }
  catch (e) { return send(res, e.status || 400, { error: e.message }); }
  if (getUserByEmail(email)) return send(res, 409, { error: 'An account with that email already exists.' });

  const isFirstUser = userCount() === 0;
  const role = (isFirstUser || (process.env.ADMIN_EMAIL && process.env.ADMIN_EMAIL.toLowerCase() === email)) ? 'admin' : 'user';
  const verifyToken = autoVerify() ? null : newVerifyToken();
  const user = createUser({ id: newId(), email, passwordHash, role, verified: autoVerify() ? 1 : 0, verifyToken });

  if (autoVerify()) {
    addCredits(user.id, FREE_SIGNUP_CREDITS, 'grant');
  } else {
    sendVerifyLinkStub(email, verifyToken, baseUrl(req));
  }
  const me = publicUser(getUserById(user.id));
  return send(res, 200, { user: me, verified: me.verified }, { 'Set-Cookie': sessionCookieHeader(signSession(user.id)) });
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  if (!checkAuthRateLimit(req, res)) return;
  const email = clean(body.email, LIMITS.email).trim().toLowerCase();
  // Non-string passwords can never match; cap length as a cheap DoS guard.
  const password = typeof body.password === 'string' ? body.password.slice(0, 1024) : '';
  const user = getUserByEmail(email);
  if (!user || !verifyPassword(password, user.password_hash))
    return send(res, 401, { error: 'Wrong email or password.' });
  return send(res, 200, { user: publicUser(user) }, { 'Set-Cookie': sessionCookieHeader(signSession(user.id)) });
}

async function handleLogout(req, res) {
  return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookieHeader('', { clear: true }) });
}

async function handleVerify(req, res) {
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  // Tokens are 24 random bytes hex-encoded; anything else is a 404, not a DB lookup.
  if (typeof token !== 'string' || !/^[0-9a-f]{48}$/.test(token))
    return send(res, 404, { error: 'That verification link is invalid or already used.' });
  const user = getUserByVerifyToken(token);
  if (!user) return send(res, 404, { error: 'That verification link is invalid or already used.' });
  transact(() => {
    const fresh = getUserById(user.id);
    if (!fresh.verified) {
      setUserVerified(user.id);
      addCredits(user.id, FREE_SIGNUP_CREDITS, 'grant');
    }
  });
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(`<!doctype html><html><body style="font-family:system-ui;background:#0a0f15;color:#e4edf5;display:grid;place-items:center;min-height:90vh;text-align:center">
    <div><h1>Email verified ✓</h1><p>${FREE_SIGNUP_CREDITS} free credits are on your account.</p><p><a href="/" style="color:#9adcff">Open Ice Ice Hammer</a></p></div></body></html>`);
}

// ---------- billing routes ----------
const mePayload = (user) => ({
  ...publicUser(user),
  monthlyCredits: (PLANS[user.plan] || PLANS.free).monthlyCredits,
  hasBilling: !!user.stripe_customer_id,
});

async function handleBillingCheckout(req, res, user) {
  const body = await readJson(req);
  const kind = body.kind === 'pack' ? 'pack' : 'subscription';
  const plan = kind === 'subscription' ? String(body.plan || '') : null;
  try {
    const session = await createCheckoutSession({ user, kind, plan, baseUrl: baseUrl(req) });
    return send(res, 200, { url: session.url });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message });
  }
}

async function handleBillingWebhook(req, res) {
  const raw = await readRaw(req);
  let event;
  try {
    verifyWebhookSignature(raw, req.headers['stripe-signature']);
    event = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    return send(res, e.status || 400, { error: e.message });
  }
  try {
    const out = handleWebhookEvent(event);
    return send(res, 200, { received: true, ...out });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message });
  }
}

async function handleBillingPortal(req, res, user) {
  try {
    const session = await createPortalSession({ user, returnUrl: baseUrl(req) + '/' });
    return send(res, 200, { url: session.url });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message });
  }
}

// ---------- generation ----------
const activeCountGlobal = () => listActiveTracks().length + listStuckTracks().filter((t) => t.status === 'queued' && !t.predictionId).length;

// Mark a track failed and refund its debited credits exactly once.
function failTrack(userId, trackId, error) {
  updateTrack(userId, trackId, { status: 'failed', error: String(error || 'Generation failed').slice(0, 400) });
  const refunded = refundLedger(trackId);
  if (refunded) console.log(`[credits] refunded ${refunded} credits for failed track ${trackId}`);
}

async function startTake(user, track, provider) {
  try {
    const info = await getModelInfo(provider.model);
    const { input, notes, applied } = buildInput(info, provider, track);
    const pred = await createPrediction(provider, input);
    updateTrack(user.id, track.id, { status: 'generating', predictionId: pred.id, notes, duration: applied.duration, seed: applied.seed });
  } catch (e) {
    failTrack(user.id, track.id, e.message);
  }
}

async function downloadAudio(track, url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Could not download the finished audio (HTTP ${res.status}).`);
  const extFromUrl = (url.split('?')[0].match(/\.(mp3|wav|flac|ogg|m4a|aac)$/i) || [])[1];
  const ext = (extFromUrl || 'mp3').toLowerCase();
  const file = `${track.id}.${ext}`;
  const userDir = path.join(AUDIO_DIR, track.userId);
  await fsp.mkdir(userDir, { recursive: true });
  const buf = Buffer.from(await res.arrayBuffer());
  await fsp.writeFile(path.join(userDir, file), buf);
  return file;
}

let polling = false;
async function pollOnce() {
  if (polling) return; polling = true;
  try {
    for (const t of listActiveTracks()) {
      try {
        if (Date.now() - t.createdAt > GIVE_UP_MS) {
          await cancelPrediction(t.predictionId);
          failTrack(t.userId, t.id, 'Timed out after 25 minutes.');
          continue;
        }
        const p = await getPrediction(t.predictionId);
        if (p.status === 'succeeded') {
          const url = pickAudioUrl(p.output);
          if (!url) { failTrack(t.userId, t.id, 'The model finished but returned no audio.'); continue; }
          const audioFile = await downloadAudio(t, url);
          updateTrack(t.userId, t.id, { status: 'ready', audioFile, finishedAt: Date.now() });
          markLedgerDone(t.id);
        } else if (p.status === 'failed' || p.status === 'canceled') {
          failTrack(t.userId, t.id, p.error ? String(p.error).slice(0, 400) : `Generation ${p.status}.`);
        }
      } catch (e) {
        if (e.status === 404) failTrack(t.userId, t.id, 'Replicate no longer has this job.');
        else console.warn(`poll ${t.id}:`, e.message);
      }
    }
  } finally { polling = false; }
}

// ---------- routes ----------
let providerCache = { at: 0, data: null };
async function providerStatus(plan) {
  if (providerCache.data && Date.now() - providerCache.at < 10 * 60 * 1000) {
    return providerCache.data.map((p) => ({ ...p, allowed: canUseModel(plan, p.id) }));
  }
  const data = await Promise.all(PROVIDERS.map(async (p) => {
    const base = {
      id: p.id, label: p.label, blurb: p.blurb, model: p.model, vocals: p.vocals,
      creditCost: costFor(p.id, 1), creditCostLabel: costLabel(p.id),
      perSecond: p.id === 'elevenlabs', creditsPerSec: p.id === 'elevenlabs' ? ELEVENLABS_CREDITS_PER_SEC : null,
    };
    try {
      const info = await getModelInfo(p.model);
      const d = info.props.duration || info.props.audio_duration || info.props.duration_seconds || info.props.seconds;
      return { ...base, ok: true, durationMin: d?.minimum ?? null, durationMax: d?.maximum ?? null, hasLyrics: !!(info.props.lyrics || info.props.lyric) };
    } catch (e) {
      return { ...base, ok: false, error: e.message };
    }
  }));
  if (data.some((p) => p.ok)) providerCache = { at: Date.now(), data };
  return data.map((p) => ({ ...p, allowed: canUseModel(plan, p.id) }));
}

async function handleGenerate(req, res, user) {
  const body = await readJson(req);
  const provider = getProvider(body.providerId) || PROVIDERS[0];

  // Gate 1: verified email before any spend.
  if (!user.verified) return send(res, 403, { error: 'Verify your email before generating. Check the server log for your verification link.' });
  // Gate 2: tier model access.
  if (!canUseModel(user.plan, provider.id))
    return send(res, 403, { error: `${provider.label} needs a paid plan. Your plan: ${user.plan}.` });

  const style = clean(body.style, LIMITS.style).trim();
  const lyrics = clean(body.lyrics, LIMITS.lyrics);
  const instrumental = !!body.instrumental || !lyrics.trim();
  if (!style && !lyrics.trim()) return send(res, 400, { error: 'Add a style or some lyrics first.' });

  const takes = Math.min(2, Math.max(1, Number(body.takes) || 2));
  if (activeCountForUser(user.id) + takes > USER_MAX_ACTIVE)
    return send(res, 429, { error: `You can only generate ${USER_MAX_ACTIVE} songs at once. Wait for some to finish.` });
  if (activeCountGlobal() + takes > MAX_ACTIVE)
    return send(res, 429, { error: 'The server is busy. Try again in a minute.' });

  // Duration first: cost depends on it for per-second models (ElevenLabs).
  // A provided duration must be a real non-negative number; garbage is a 400,
  // not a silent clamp to the default.
  let duration = 120;
  if (body.duration !== undefined && body.duration !== null && body.duration !== '') {
    const n = Number(body.duration);
    if (!Number.isFinite(n) || n < 0)
      return send(res, 400, { error: 'Duration must be a positive number of seconds.' });
    duration = Math.min(600, Math.max(5, n));
  }
  // ElevenLabs bills per second of audio — cap it on every plan that can use it.
  if (provider.id === 'elevenlabs' && duration > ELEVENLABS_MAX_DURATION) duration = ELEVENLABS_MAX_DURATION;

  // THE choke point: debit BEFORE any Replicate call. 402 when broke.
  const total = costFor(provider.id, takes, duration);
  try {
    addCredits(user.id, -total, 'generation');
  } catch (e) {
    return send(res, e.status || 500, { error: e.status === 402 ? `Out of credits (${user.credits} left, this needs ${total}).` : e.message });
  }

  const title = clean(body.title, LIMITS.title).trim() || autoTitle(provider.vocals && !instrumental ? lyrics : '', style);
  const baseSeed = Number.isFinite(Number(body.seed)) && body.seed !== '' && body.seed != null ? Number(body.seed) : crypto.randomInt(1, 2 ** 31 - 1);
  const now = Date.now();
  const made = [];
  transact(() => {
    for (let k = 0; k < takes; k++) {
      const t = addTrack(user.id, {
        id: newId(), title, style, lyrics, instrumental, duration,
        seed: (baseSeed + k * 7919) % (2 ** 31 - 1),
        providerId: provider.id, take: takes > 1 ? 'AB'[k] : null, status: 'queued', createdAt: now + k,
      });
      addLedgerEntry({
        id: cryptoId(), userId: user.id, trackId: t.id, providerId: provider.id, model: provider.model,
        creditsDebited: costFor(provider.id, 1, duration), estCostUsd: estUsdFor(provider.id, 1),
      });
      made.push(t);
    }
  });
  await Promise.all(made.map((t) => startTake(user, t, provider)));
  send(res, 200, { tracks: made.map((t) => publicTrack(getTrack(user.id, t.id))) });
}

async function handleAudio(req, res, user, id) {
  const t = getTrack(user.id, id);
  if (!t || !t.audioFile) return send(res, 404, { error: 'No audio for this track.' });
  const file = path.join(AUDIO_DIR, user.id, t.audioFile);
  let stat;
  try { stat = await fsp.stat(file); } catch { return send(res, 404, { error: 'Audio file is missing.' }); }
  const ext = path.extname(file).slice(1);
  const type = AUDIO_MIME[ext] || 'application/octet-stream';
  const safeName = t.title.replace(/[^\w\- ]+/g, '').trim() || 'song';
  const headers = { ...SECURITY_HEADERS, 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, max-age=86400' };
  if (new URL(req.url, 'http://x').searchParams.has('download')) headers['Content-Disposition'] = `attachment; filename="${safeName}${t.take ? ' (' + t.take + ')' : ''}.${ext}"`;
  const range = req.headers.range && req.headers.range.match(/bytes=(\d*)-(\d*)/);
  if (range) {
    let start = range[1] ? Number(range[1]) : stat.size - Number(range[2]);
    let end = range[1] && range[2] ? Number(range[2]) : stat.size - 1;
    start = Math.max(0, start); end = Math.min(stat.size - 1, end);
    if (start > end) { res.writeHead(416, { ...SECURITY_HEADERS, 'Content-Range': `bytes */${stat.size}` }); return res.end(); }
    res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${stat.size}`, 'Content-Length': end - start + 1 });
    return fs.createReadStream(file, { start, end }).pipe(res);
  }
  res.writeHead(200, { ...headers, 'Content-Length': stat.size });
  fs.createReadStream(file).pipe(res);
}

async function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, 'Forbidden');
  try {
    const data = await fsp.readFile(file);
    send(res, 200, data, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  } catch { send(res, 404, 'Not found'); }
}

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, 'http://x');
    const m = pathname.match(/^\/api\/(tracks|audio)\/([a-f0-9]{16})$/);

    // CSRF gate for cookie-authenticated state changes (skips signup/login,
    // the signature-authenticated Stripe webhook, and sessionless requests).
    checkCsrf(req, pathname);

    if (pathname === '/api/health') return send(res, 200, { ok: true });

    if (pathname === '/api/auth/signup' && req.method === 'POST') return await handleSignup(req, res);
    if (pathname === '/api/auth/login' && req.method === 'POST') return await handleLogin(req, res);
    if (pathname === '/api/auth/logout' && req.method === 'POST') return await handleLogout(req, res);
    if (pathname === '/api/auth/verify' && req.method === 'GET') return await handleVerify(req, res);

    if (pathname === '/api/providers' && req.method === 'GET') {
      const userId = getSessionUserId(req);
      const plan = userId ? (getUserById(userId)?.plan || 'free') : 'free';
      return send(res, 200, { providers: await providerStatus(plan), tokenSet: !!process.env.REPLICATE_API_TOKEN });
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      const user = requireUser(req);
      return send(res, 200, { user: mePayload(user), csrfToken: csrfTokenFor(user.id) });
    }
    if (pathname === '/api/admin/spend' && req.method === 'GET') {
      requireAdmin(req);
      return send(res, 200, spendSummary());
    }

    // Billing (Phase 2). Webhook is unauthenticated by design — Stripe signs it.
    if (pathname === '/api/billing/config' && req.method === 'GET') return send(res, 200, billingConfig());
    if (pathname === '/api/billing/webhook' && req.method === 'POST') return await handleBillingWebhook(req, res);
    if (pathname === '/api/billing/checkout' && req.method === 'POST') return await handleBillingCheckout(req, res, requireUser(req));
    if (pathname === '/api/billing/portal' && req.method === 'GET') return await handleBillingPortal(req, res, requireUser(req));

    // Everything below requires a signed-in user; tracks are scoped to them.
    if (pathname === '/api/tracks' && req.method === 'GET') {
      const user = requireUser(req);
      return send(res, 200, { tracks: listTracks(user.id).map(publicTrack) });
    }
    if (pathname === '/api/generate' && req.method === 'POST') return await handleGenerate(req, res, requireUser(req));
    if (m && m[1] === 'tracks' && req.method === 'GET') {
      const user = requireUser(req);
      const t = getTrack(user.id, m[2]); return t ? send(res, 200, { track: publicTrack(t) }) : send(res, 404, { error: 'Not found' });
    }
    if (m && m[1] === 'tracks' && req.method === 'DELETE') {
      const user = requireUser(req);
      const t = getTrack(user.id, m[2]);
      if (!t) return send(res, 404, { error: 'Not found' });
      const wasQueued = t.status === 'queued';
      if (t.status === 'generating' && t.predictionId) await cancelPrediction(t.predictionId);
      await removeTrack(user.id, t.id);
      if (wasQueued) refundLedger(t.id); // never started: full refund
      if (t.audioFile) await fsp.rm(path.join(AUDIO_DIR, user.id, t.audioFile), { force: true });
      return send(res, 200, { ok: true });
    }
    if (m && m[1] === 'audio' && req.method === 'GET') return await handleAudio(req, res, requireUser(req), m[2]);
    if (pathname.startsWith('/api/')) return send(res, 404, { error: 'Unknown endpoint' });
    if (req.method === 'GET') return await serveStatic(req, res, pathname);
    send(res, 405, 'Method not allowed');
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e.message || 'Server error' });
  }
});

initDb();
// Tracks left mid-generation by a restart are failed AND refunded (no result, no charge).
for (const t of listStuckTracks()) {
  if (t.status === 'generating' && t.predictionId) await cancelPrediction(t.predictionId);
  failTrack(t.userId, t.id, 'Server restarted before this job finished.');
}
setInterval(pollOnce, POLL_MS).unref();
server.listen(PORT, () => {
  console.log(`Ice Ice Hammer running on http://localhost:${PORT}`);
  if (!process.env.REPLICATE_API_TOKEN) console.warn('Warning: REPLICATE_API_TOKEN is not set, so songs cannot be generated yet.');
  if (!process.env.SESSION_SECRET) console.warn('Warning: SESSION_SECRET is not set. Set it in production so sessions survive restarts.');
  if (!billingEnabled()) console.warn('Warning: STRIPE_SECRET_KEY is not set. Billing endpoints return 503 until it is configured (see .env.example).');
});
