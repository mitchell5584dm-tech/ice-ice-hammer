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
import { getModelInfo, buildInput, createPrediction, getPrediction, cancelPrediction, pickAudioUrl, buildSeparationInput, pickStemUrls } from './lib/replicate.mjs';
import {
  initDb, transact, userCount, createUser, getUserById, getUserByEmail, getUserByVerifyToken,
  addCredits, setUserVerified, setUserPlan, cryptoId,
  addTrack, getTrack, listTracks, listActiveTracks, listStuckTracks, updateTrack, removeTrack,
  activeCountForUser, addLedgerEntry, markLedgerDone, refundLedger, spendSummary, AUDIO_DIR,
  addSeparation, updateSeparation, getSeparation, refundSeparation, markSeparationDone, listActiveSeparations,
  listStuckSeparations, activeSeparationCountForUser,
  addStem, getStemForUser, listStemsForTrack, updateStem, removeStemsForTrack, stemStatusForTrack,
  addNamCapture, getNamCapture, listNamCaptures, removeNamCapture,
  createReferralCode, getReferralByCode, recordReferralClick, attributeUser,
  referralStats, markEarningsPaidOut, listUnpaidEarnings,
} from './lib/db.mjs';
import {
  hashPassword, verifyPassword, signSession, getSessionUserId, parseCookies,
  sessionCookieHeader, newVerifyToken, sendVerifyLinkStub, autoVerify, publicUser, isValidEmail,
  csrfTokenFor, verifyCsrfToken,
} from './lib/auth.mjs';
import { checkRateLimit, clientIp } from './lib/ratelimit.mjs';
import { costFor, canUseModel, estUsdFor, FREE_SIGNUP_CREDITS, ELEVENLABS_MAX_DURATION, ELEVENLABS_CREDITS_PER_SEC, costLabel, PLANS, STEM_MODEL, STEM_MODEL_VARIANT, STEM_SEPARATION_CREDITS, STEM_NAMES, STEM_USER_MAX_ACTIVE, stemCostLabel, EST_USD_PER_CREDIT, REFERRAL_ATTRIBUTION_DAYS, REFERRAL_PAYOUT_THRESHOLD_CENTS, REFERRAL_SUBSCRIPTION_RATE, REFERRAL_PACK_RATE, REFERRAL_WINDOW_MONTHS } from './lib/costs.mjs';
import {
  billingEnabled, billingConfig, createCheckoutSession, createPortalSession,
  verifyWebhookSignature, handleWebhookEvent,
  createConnectOnboardingLink, createPayoutTransfer,
} from './lib/billing.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);
const MAX_ACTIVE = Number(process.env.MAX_ACTIVE_GENERATIONS || 6); // global backstop
const USER_MAX_ACTIVE = Number(process.env.USER_MAX_ACTIVE_GENERATIONS || 2); // per-user cap
const POLL_MS = Number(process.env.POLL_MS || 4000);
const GIVE_UP_MS = 25 * 60 * 1000;

const LIMITS = { style: 1000, lyrics: 5000, title: 80, email: 254, password: 128 };
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg', '.m4a': 'audio/mp4' };
const AUDIO_MIME = { mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', ogg: 'audio/ogg', m4a: 'audio/mp4', aac: 'audio/aac' };

// ---------- helpers ----------
// Best-effort cancel: a Replicate error must never abort a delete, a poll
// tick, or server startup.
async function safeCancel(predictionId) {
  try { await cancelPrediction(predictionId); }
  catch (e) { console.warn(`cancel ${predictionId}:`, e.message); }
}

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
  stemStatus: stemStatusForTrack(t.userId, t.id),
});

const publicStem = (s) => ({
  id: s.id, name: s.name, status: s.status, error: s.error || null,
  createdAt: s.createdAt, finishedAt: s.finishedAt || null,
  audioUrl: s.audioFile ? `/api/audio/${s.id}` : null,
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

  // Referral attribution: the ich_ref cookie was set by visiting /r/CODE.
  // Self-referral (the code owner's own session creating another account with
  // their link) is ignored; invalid codes are ignored silently by attributeUser.
  const refCode = parseCookies(req)['ich_ref'];
  if (refCode) {
    const ref = getReferralByCode(refCode);
    const sessionUserId = getSessionUserId(req);
    if (!(ref && sessionUserId && sessionUserId === ref.owner_user_id)) {
      attributeUser(user.id, refCode);
    }
  }

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

// ---------- Studio Mixer: stem separation ----------
// Mark a separation failed, fail its stems, and refund its debited credits exactly once.
function failSeparation(userId, separationId, error) {
  updateSeparation(separationId, { status: 'failed', finished_at: Date.now() });
  const trackId = (getSeparation(separationId) || {}).track_id;
  for (const s of listStemsForTrack(userId, trackId)) {
    if (s.separationId === separationId && s.status !== 'ready')
      updateStem(s.id, { status: 'failed', error: String(error || 'Separation failed').slice(0, 400), finished_at: Date.now() });
  }
  const refunded = refundSeparation(separationId);
  if (refunded) console.log(`[credits] refunded ${refunded} credits for failed separation ${separationId}`);
}

// The track's mixed audio goes to the model as a data URI: /api/audio URLs are
// login-walled, so a public URL is not an option. Guard the size so one huge
// file can't blow up the prediction JSON.
async function audioDataUri(userId, audioFile) {
  const file = path.join(AUDIO_DIR, userId, audioFile);
  const stat = await fsp.stat(file);
  const MAX_BYTES = 32 * 1024 * 1024;
  if (stat.size > MAX_BYTES) throw Object.assign(new Error('This song file is too large to separate (32 MB limit).'), { status: 400 });
  const ext = path.extname(audioFile).slice(1).toLowerCase();
  const mime = AUDIO_MIME[ext] || 'audio/mpeg';
  const b64 = (await fsp.readFile(file)).toString('base64');
  return `data:${mime};base64,${b64}`;
}

async function startSeparation(user, track, separation) {
  try {
    const info = await getModelInfo(STEM_MODEL);
    const input = buildSeparationInput(info, {
      audioDataUri: await audioDataUri(user.id, track.audioFile),
      modelName: STEM_MODEL_VARIANT,
    });
    const pred = await createPrediction({ model: STEM_MODEL }, input);
    updateSeparation(separation.id, { status: 'processing', replicate_prediction_id: pred.id });
  } catch (e) {
    failSeparation(user.id, separation.id, e.message);
  }
}

async function downloadStemAudio(stem, url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Could not download the ${stem.name} stem (HTTP ${res.status}).`);
  const extFromUrl = (url.split('?')[0].match(/\.(mp3|wav|flac|ogg|m4a|aac)$/i) || [])[1];
  const ext = (extFromUrl || 'mp3').toLowerCase();
  const file = `${stem.id}.${ext}`;
  await fsp.mkdir(path.join(AUDIO_DIR, stem.userId), { recursive: true });
  await fsp.writeFile(path.join(AUDIO_DIR, stem.userId, file), Buffer.from(await res.arrayBuffer()));
  return file;
}

// POST /api/tracks/:id/stems — split a finished song into stems. Debits credits
// FIRST (same choke point as generation); refunds on failure. Idempotent: if the
// track already has ready stems they are returned without charging again.
async function handleStemSeparation(req, res, user, trackId) {
  const track = getTrack(user.id, trackId);
  if (!track) return send(res, 404, { error: 'Not found' });
  if (!user.verified) return send(res, 403, { error: 'Verify your email before splitting stems. Check the server log for your verification link.' });
  if (track.status !== 'ready' || !track.audioFile)
    return send(res, 400, { error: 'This song is not finished yet. Split stems once it is ready.' });

  const existing = listStemsForTrack(user.id, trackId);
  if (existing.length && existing.every((s) => s.status === 'ready'))
    return send(res, 200, { stems: existing.map(publicStem), charged: false });
  if (existing.some((s) => s.status === 'queued' || s.status === 'processing'))
    return send(res, 200, { stems: existing.map(publicStem), charged: false, separating: true });
  // A previous attempt failed: clear its rows so this run starts clean.
  if (existing.length) {
    for (const s of removeStemsForTrack(user.id, trackId)) {
      if (s.audioFile) await fsp.rm(path.join(AUDIO_DIR, user.id, s.audioFile), { force: true });
    }
  }

  if (activeSeparationCountForUser(user.id) >= STEM_USER_MAX_ACTIVE)
    return send(res, 429, { error: `You can only separate ${STEM_USER_MAX_ACTIVE} songs at once. Wait for one to finish.` });
  if (listActiveSeparations().length + listActiveTracks().length >= MAX_ACTIVE)
    return send(res, 429, { error: 'The server is busy. Try again in a minute.' });

  // THE choke point: debit BEFORE any Replicate call. 402 when broke. The debit
  // and the rows that justify it commit together, so a failed insert rolls the
  // debit back instead of silently losing credits.
  let separation;
  try {
    separation = transact(() => {
      addCredits(user.id, -STEM_SEPARATION_CREDITS, 'stems');
      const sep = addSeparation({
        id: newId(), userId: user.id, trackId: track.id, model: STEM_MODEL,
        creditsDebited: STEM_SEPARATION_CREDITS, estCostUsd: STEM_SEPARATION_CREDITS * EST_USD_PER_CREDIT,
      });
      for (const name of STEM_NAMES) addStem({ id: newId(), userId: user.id, trackId: track.id, separationId: sep.id, name });
      return sep;
    });
  } catch (e) {
    return send(res, e.status || 500, { error: e.status === 402 ? `Out of credits (${user.credits} left, stem splitting needs ${STEM_SEPARATION_CREDITS}).` : e.message });
  }
  await startSeparation(user, track, separation);
  const sep = getSeparation(separation.id);
  const failed = sep.status === 'failed'; // synchronous failure: already refunded
  send(res, 200, {
    stems: listStemsForTrack(user.id, trackId).map(publicStem),
    charged: !failed,
    separating: !failed,
  });
}

// GET /api/tracks/:id/stems — list a track's stems (empty until separated).
async function handleStemList(req, res, user, trackId) {
  const track = getTrack(user.id, trackId);
  if (!track) return send(res, 404, { error: 'Not found' });
  return send(res, 200, { stems: listStemsForTrack(user.id, trackId).map(publicStem), cost: stemCostLabel() });
}

// ---------- Studio Mixer: NAM capture library ----------
const NAM_MAX_BYTES = 2 * 1024 * 1024; // .nam files are small JSON; 2 MB is generous

// A .nam file is JSON with a "weights" array (and usually "architecture").
// Light validation: it must parse, be an object, and carry weights.
function validateNamUpload(dataB64) {
  let buf;
  try { buf = Buffer.from(String(dataB64 || ''), 'base64'); }
  catch { throw Object.assign(new Error('Capture data must be base64.'), { status: 400 }); }
  if (!buf.length || buf.length > NAM_MAX_BYTES)
    throw Object.assign(new Error('Capture file must be under 2 MB.'), { status: 400 });
  let parsed;
  try { parsed = JSON.parse(buf.toString('utf8')); }
  catch { throw Object.assign(new Error('This does not look like a .nam file (not JSON).'), { status: 400 }); }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.weights))
    throw Object.assign(new Error('This does not look like a .nam file (no weights found).'), { status: 400 });
  return buf;
}

async function handleNamUpload(req, res, user) {
  const body = await readJson(req, 4 * 1024 * 1024);
  const name = clean(body.name, 80).trim() || 'Untitled capture';
  const buf = validateNamUpload(body.data);
  const id = newId();
  const dir = path.join(AUDIO_DIR, user.id, 'nam');
  await fsp.mkdir(dir, { recursive: true });
  await fsp.writeFile(path.join(dir, `${id}.nam`), buf);
  const cap = addNamCapture({ id, userId: user.id, name, file: `${id}.nam`, size: buf.length });
  return send(res, 200, { capture: { id: cap.id, name: cap.name, size: cap.size, createdAt: cap.created_at } });
}

async function handleNamList(req, res, user) {
  const q = (new URL(req.url, 'http://x').searchParams.get('q') || '').toLowerCase();
  const all = listNamCaptures(user.id)
    .filter((c) => !q || c.name.toLowerCase().includes(q))
    .map((c) => ({ id: c.id, name: c.name, size: c.size, createdAt: c.created_at, downloadUrl: `/api/nam/${c.id}` }));
  return send(res, 200, { captures: all });
}

async function handleNamDownload(req, res, user, id) {
  const cap = getNamCapture(user.id, id);
  if (!cap) return send(res, 404, { error: 'Not found' });
  const file = path.join(AUDIO_DIR, user.id, 'nam', cap.file);
  let stat;
  try { stat = await fsp.stat(file); } catch { return send(res, 404, { error: 'Capture file is missing.' }); }
  const safeName = cap.name.replace(/[^\w\- ]+/g, '').trim() || 'capture';
  res.writeHead(200, {
    ...SECURITY_HEADERS, 'Content-Type': 'application/json', 'Content-Length': stat.size,
    'Cache-Control': 'private, max-age=86400',
    'Content-Disposition': `attachment; filename="${safeName}.nam"`,
  });
  fs.createReadStream(file).pipe(res);
}

async function handleNamDelete(req, res, user, id) {
  const cap = getNamCapture(user.id, id);
  if (!cap) return send(res, 404, { error: 'Not found' });
  removeNamCapture(user.id, id);
  await fsp.rm(path.join(AUDIO_DIR, user.id, 'nam', cap.file), { force: true });
  return send(res, 200, { ok: true });
}

// ---------- Creator referral program ----------
// Public base URL for referral links; APP_BASE_URL overrides the Host header
// (set it to the canonical domain, e.g. https://ice-ice-hammer.com).
function appBaseUrl(req) {
  return (process.env.APP_BASE_URL || baseUrl(req)).replace(/\/$/, '');
}

function referralCookieHeader(code) {
  const maxAge = REFERRAL_ATTRIBUTION_DAYS * 24 * 60 * 60;
  return `ich_ref=${encodeURIComponent(code)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

// GET /r/CODE — counts the click, sets the 90-day attribution cookie, and
// sends the visitor to the landing page. Unknown codes redirect silently.
async function handleReferralRedirect(req, res, code) {
  const ref = getReferralByCode(code);
  if (ref) recordReferralClick(code);
  res.writeHead(302, {
    ...SECURITY_HEADERS,
    'Location': '/',
    'Cache-Control': 'no-store',
    ...(ref ? { 'Set-Cookie': referralCookieHeader(code) } : {}),
  });
  res.end();
}

// POST /api/referrals/code — get (or create) my referral code.
async function handleReferralCode(req, res, user) {
  const code = createReferralCode(user.id);
  return send(res, 200, { code, link: `${appBaseUrl(req)}/r/${code}` });
}

// GET /api/referrals/me — dashboard data: link, clicks, signups, earnings.
async function handleReferralMe(req, res, user) {
  const stats = referralStats(user.id);
  return send(res, 200, {
    code: stats.code,
    link: stats.code ? `${appBaseUrl(req)}/r/${stats.code}` : null,
    clicks: stats.clicks,
    signups: stats.signups,
    activeSubscribers: stats.activeSubscribers,
    balanceCents: stats.balanceCents,
    paidOutCents: stats.paidOutCents,
    payoutThresholdCents: REFERRAL_PAYOUT_THRESHOLD_CENTS,
    connectReady: !!user.stripe_connect_id,
    rates: {
      subscription: REFERRAL_SUBSCRIPTION_RATE,
      pack: REFERRAL_PACK_RATE,
      windowMonths: REFERRAL_WINDOW_MONTHS,
    },
  });
}

// GET /api/referrals/connect — Stripe Connect Express onboarding link.
async function handleReferralConnect(req, res, user) {
  try {
    const { url } = await createConnectOnboardingLink({ user: getUserById(user.id), baseUrl: baseUrl(req) });
    return send(res, 200, { url });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message });
  }
}

// POST /api/referrals/payout — pay out the unpaid balance (>= $50 threshold)
// to the referrer's connected Express account. The Stripe transfer is created
// first; earnings are marked paid after it succeeds.
// One payout per user at a time (single-process server), plus a Stripe
// idempotency key derived from the exact earnings being claimed, so a double
// click or a retry can never create a second transfer for the same earnings.
const payoutsInFlight = new Set();
async function handleReferralPayout(req, res, user) {
  if (payoutsInFlight.has(user.id)) return send(res, 409, { error: 'A payout is already in progress.' });
  payoutsInFlight.add(user.id);
  try {
    const claimed = listUnpaidEarnings(user.id);
    const balanceCents = claimed.reduce((n, e) => n + e.amount_cents, 0);
    if (balanceCents < REFERRAL_PAYOUT_THRESHOLD_CENTS) {
      return send(res, 400, {
        error: `Your balance is $${(balanceCents / 100).toFixed(2)} — payouts need at least $${(REFERRAL_PAYOUT_THRESHOLD_CENTS / 100).toFixed(2)}.`,
      });
    }
    const ids = claimed.map((e) => e.id);
    const idempotencyKey = 'payout-' + user.id + '-' + crypto.createHash('sha256').update(ids.join(',')).digest('hex').slice(0, 32);
    const transfer = await createPayoutTransfer({ user: getUserById(user.id), amountCents: balanceCents, idempotencyKey });
    // Mark exactly the rows that were transferred; earnings that accrued while
    // the transfer was in flight stay unpaid for the next payout.
    const marked = markEarningsPaidOut(user.id, transfer.id, ids);
    const paidTotal = marked.reduce((n, e) => n + e.amount_cents, 0);
    console.log(`[referrals] payout $${(paidTotal / 100).toFixed(2)} to ${user.email} (transfer ${transfer.id})`);
    return send(res, 200, { ok: true, transferId: transfer.id, amountCents: paidTotal });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message });
  } finally {
    payoutsInFlight.delete(user.id);
  }
}

let polling = false;
async function pollOnce() {
  if (polling) return; polling = true;
  try {
    for (const t of listActiveTracks()) {
      try {
        if (Date.now() - t.createdAt > GIVE_UP_MS) {
          await safeCancel(t.predictionId);
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
    // Studio Mixer: stem separations finish on the same poll loop.
    for (const s of listActiveSeparations()) {
      try {
        if (Date.now() - s.created_at > GIVE_UP_MS) {
          await safeCancel(s.replicate_prediction_id);
          failSeparation(s.user_id, s.id, 'Timed out after 25 minutes.');
          continue;
        }
        const p = await getPrediction(s.replicate_prediction_id);
        if (p.status === 'succeeded') {
          const urls = pickStemUrls(p.output, STEM_NAMES);
          const missing = STEM_NAMES.filter((n) => !urls[n]);
          if (missing.length) { failSeparation(s.user_id, s.id, `The model finished but returned no audio for: ${missing.join(', ')}.`); continue; }
          const stems = listStemsForTrack(s.user_id, s.track_id).filter((st) => st.separationId === s.id);
          for (const name of STEM_NAMES) {
            const stem = stems.find((st) => st.name === name);
            if (!stem) continue;
            try {
              const audioFile = await downloadStemAudio(stem, urls[name]);
              updateStem(stem.id, { status: 'ready', audio_file: audioFile, finished_at: Date.now() });
            } catch (e) {
              updateStem(stem.id, { status: 'failed', error: String(e.message).slice(0, 400), finished_at: Date.now() });
            }
          }
          const after = listStemsForTrack(s.user_id, s.track_id).filter((st) => st.separationId === s.id);
          if (after.every((st) => st.status === 'ready')) {
            markSeparationDone(s.id);
          } else {
            failSeparation(s.user_id, s.id, 'One or more stems could not be downloaded.');
          }
        } else if (p.status === 'failed' || p.status === 'canceled') {
          failSeparation(s.user_id, s.id, p.error ? String(p.error).slice(0, 400) : `Separation ${p.status}.`);
        }
      } catch (e) {
        if (e.status === 404) failSeparation(s.user_id, s.id, 'Replicate no longer has this job.');
        else console.warn(`poll separation ${s.id}:`, e.message);
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

  const total = costFor(provider.id, takes, duration);
  const title = clean(body.title, LIMITS.title).trim() || autoTitle(provider.vocals && !instrumental ? lyrics : '', style);
  const baseSeed = Number.isFinite(Number(body.seed)) && body.seed !== '' && body.seed != null ? Number(body.seed) : crypto.randomInt(1, 2 ** 31 - 1);
  const now = Date.now();
  const made = [];
  // THE choke point: debit BEFORE any Replicate call. 402 when broke. The debit
  // and the track/ledger rows commit together: if any insert fails the debit
  // rolls back, so credits can never be taken without a track to refund against.
  try {
    transact(() => {
      addCredits(user.id, -total, 'generation');
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
  } catch (e) {
    made.length = 0;
    return send(res, e.status || 500, { error: e.status === 402 ? `Out of credits (${user.credits} left, this needs ${total}).` : e.message });
  }
  await Promise.all(made.map((t) => startTake(user, t, provider)));
  send(res, 200, { tracks: made.map((t) => publicTrack(getTrack(user.id, t.id))) });
}

async function handleAudio(req, res, user, id) {
  // Tracks and stems share the /api/audio/:id namespace (both are 16-hex ids).
  const t = getTrack(user.id, id) || getStemForUser(user.id, id);
  if (!t || !t.audioFile) return send(res, 404, { error: 'No audio for this track.' });
  const file = path.join(AUDIO_DIR, user.id, t.audioFile);
  let stat;
  try { stat = await fsp.stat(file); } catch { return send(res, 404, { error: 'Audio file is missing.' }); }
  const ext = path.extname(file).slice(1);
  const type = AUDIO_MIME[ext] || 'application/octet-stream';
  const safeName = (t.title || t.name || 'stem').replace(/[^\w\- ]+/g, '').trim() || 'audio';
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
  const rel = pathname === '/' ? 'landing.html' : pathname === '/studio' ? 'index.html' : pathname.slice(1);
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, 'Forbidden');
  try {
    const data = await fsp.readFile(file);
    const type = MIME[path.extname(file)] || 'application/octet-stream';
    // Audio samples need byte ranges (Safari refuses to play audio without them).
    const range = type.startsWith('audio/') && req.headers.range && req.headers.range.match(/^bytes=(\d*)-(\d*)$/);
    if (range && (range[1] || range[2])) {
      let start = range[1] ? Number(range[1]) : data.length - Number(range[2]);
      let end = range[1] && range[2] ? Number(range[2]) : data.length - 1;
      start = Math.max(0, start); end = Math.min(data.length - 1, end);
      if (start > end) return send(res, 416, '', { 'Content-Range': `bytes */${data.length}` });
      return send(res, 206, data.subarray(start, end + 1), { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Content-Range': `bytes ${start}-${end}/${data.length}`, 'Cache-Control': 'no-cache' });
    }
    send(res, 200, data, { 'Content-Type': type, 'Cache-Control': 'no-cache', ...(type.startsWith('audio/') ? { 'Accept-Ranges': 'bytes' } : {}) });
  } catch { send(res, 404, 'Not found'); }
}

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, 'http://x');
    const m = pathname.match(/^\/api\/(tracks|audio)\/([a-f0-9]{16})$/);
    const sm = pathname.match(/^\/api\/tracks\/([a-f0-9]{16})\/stems$/); // stem list + split
    const nm = pathname.match(/^\/api\/nam(?:\/([a-f0-9]{16}))?$/);      // NAM library
    const rm = pathname.match(/^\/r\/([A-Za-z0-9_-]{4,24})$/);          // referral links

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
      if (t.status === 'generating' && t.predictionId) await safeCancel(t.predictionId);
      // Cancel any in-flight separation and remove its stems (files + rows).
      for (const s of listStemsForTrack(user.id, t.id)) {
        if (s.audioFile) await fsp.rm(path.join(AUDIO_DIR, user.id, s.audioFile), { force: true });
      }
      removeStemsForTrack(user.id, t.id);
      for (const s of listStuckSeparations().filter((x) => x.user_id === user.id && x.track_id === t.id)) {
        if (s.replicate_prediction_id) await safeCancel(s.replicate_prediction_id);
        updateSeparation(s.id, { status: 'failed', finished_at: Date.now() });
        refundSeparation(s.id);
      }
      await removeTrack(user.id, t.id);
      if (wasQueued) refundLedger(t.id); // never started: full refund
      if (t.audioFile) await fsp.rm(path.join(AUDIO_DIR, user.id, t.audioFile), { force: true });
      return send(res, 200, { ok: true });
    }
    if (m && m[1] === 'audio' && req.method === 'GET') return await handleAudio(req, res, requireUser(req), m[2]);

    // Studio Mixer: stems.
    if (sm && req.method === 'GET') return await handleStemList(req, res, requireUser(req), sm[1]);
    if (sm && req.method === 'POST') return await handleStemSeparation(req, res, requireUser(req), sm[1]);

    // Studio Mixer: NAM capture library.
    if (nm && !nm[1] && req.method === 'GET') return await handleNamList(req, res, requireUser(req));
    if (nm && !nm[1] && req.method === 'POST') return await handleNamUpload(req, res, requireUser(req));
    if (nm && nm[1] && req.method === 'GET') return await handleNamDownload(req, res, requireUser(req), nm[1]);
    if (nm && nm[1] && req.method === 'DELETE') return await handleNamDelete(req, res, requireUser(req), nm[1]);

    // Creator referral program.
    if (pathname === '/api/referrals/code' && req.method === 'POST') return await handleReferralCode(req, res, requireUser(req));
    if (pathname === '/api/referrals/me' && req.method === 'GET') return await handleReferralMe(req, res, requireUser(req));
    if (pathname === '/api/referrals/connect' && req.method === 'GET') return await handleReferralConnect(req, res, requireUser(req));
    if (pathname === '/api/referrals/payout' && req.method === 'POST') return await handleReferralPayout(req, res, requireUser(req));

    // Public referral links: /r/CODE counts the click, sets the attribution
    // cookie, and redirects to the landing page.
    if (rm && req.method === 'GET') return await handleReferralRedirect(req, res, rm[1]);

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
  if (t.status === 'generating' && t.predictionId) await safeCancel(t.predictionId);
  failTrack(t.userId, t.id, 'Server restarted before this job finished.');
}
// Same for stem separations left mid-run.
for (const s of listStuckSeparations()) {
  if (s.replicate_prediction_id) await safeCancel(s.replicate_prediction_id);
  failSeparation(s.user_id, s.id, 'Server restarted before this separation finished.');
}
setInterval(pollOnce, POLL_MS).unref();
server.listen(PORT, () => {
  console.log(`Ice Ice Hammer running on http://localhost:${PORT}`);
  if (!process.env.REPLICATE_API_TOKEN) console.warn('Warning: REPLICATE_API_TOKEN is not set, so songs cannot be generated yet.');
  if (!process.env.SESSION_SECRET) console.warn('Warning: SESSION_SECRET is not set. Set it in production so sessions survive restarts.');
  if (!billingEnabled()) console.warn('Warning: STRIPE_SECRET_KEY is not set. Billing endpoints return 503 until it is configured (see .env.example).');
});
