// Auth for Ice Ice Hammer SaaS (Phase 1): email+password accounts, signed
// HTTP-only cookie sessions, email-verification magic links (stub: logged).
// Zero dependencies — scrypt via node:crypto, HMAC-SHA256 for session signing.
import crypto from 'node:crypto';

const COOKIE_NAME = 'ich_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

let secretWarned = false;
export function getSessionSecret() {
  const s = process.env.SESSION_SECRET;
  if (s) return s;
  if (!secretWarned) {
    secretWarned = true;
    console.warn('Warning: SESSION_SECRET is not set. Sessions will not survive restarts. Set it in production.');
  }
  // Ephemeral fallback for dev; stored on the module so it stays stable per process.
  if (!globalThis.__ichSessionSecret) globalThis.__ichSessionSecret = crypto.randomBytes(32).toString('hex');
  return globalThis.__ichSessionSecret;
}

// ---------- passwords (scrypt, OWASP-recommended parameters) ----------
const SCRYPT_N = 16384, SCRYPT_R = 8, SCRYPT_P = 1, KEY_LEN = 64;

export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8)
    throw Object.assign(new Error('Password must be at least 8 characters.'), { status: 400 });
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  try {
    const [, n, r, p, saltHex, hashHex] = String(stored).split('$');
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(String(password), salt, expected.length, {
      N: Number(n), r: Number(r), p: Number(p),
    });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ---------- sessions ----------
// Cookie value: base64url(userId).expiryEpochMs.hexHmac
export function signSession(userId, ttlMs = SESSION_TTL_MS) {
  const exp = Date.now() + ttlMs;
  const payload = `${Buffer.from(userId, 'utf8').toString('base64url')}.${exp}`;
  const sig = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [b64, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  if (!/^[0-9a-f]{64}$/.test(sig)) return null; // strict: no trailing-junk tricks
  const payload = `${b64}.${expStr}`;
  const want = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('hex');
  const a = Buffer.from(sig, 'hex'), b = Buffer.from(want, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    return Buffer.from(b64, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

export function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function sessionCookieHeader(token, { clear = false } = {}) {
  const attrs = [`${COOKIE_NAME}=${clear ? '' : encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  attrs.push(clear ? 'Expires=Thu, 01 Jan 1970 00:00:00 GMT' : `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
  if (process.env.COOKIE_SECURE === '1') attrs.push('Secure');
  return attrs.join('; ');
}

export function getSessionUserId(req) {
  return verifySession(parseCookies(req)[COOKIE_NAME]);
}

// ---------- CSRF (synchronizer token) ----------
// The session cookie is SameSite=Lax, but state-changing API calls also require
// a per-user token that a cross-origin attacker cannot read: GET /api/me
// returns it, and POST/PUT/DELETE must send it back as X-CSRF-Token.
// Deterministic per user (HMAC of the session secret) so no storage is needed;
// rotating SESSION_SECRET invalidates all tokens.
export function csrfTokenFor(userId) {
  return crypto.createHmac('sha256', getSessionSecret()).update(`csrf:v1:${userId}`).digest('hex');
}

export function verifyCsrfToken(userId, token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return false;
  const want = csrfTokenFor(userId);
  const a = Buffer.from(token, 'hex'), b = Buffer.from(want, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- email verification (stub) ----------
// Phase 1: no mail provider wired up. The magic link is logged to the console;
// EMAIL_AUTO_VERIFY=1 skips the dance entirely (dev / tests).
export function newVerifyToken() {
  return crypto.randomBytes(24).toString('hex');
}

export function sendVerifyLinkStub(email, token, baseUrl) {
  const link = `${baseUrl}/api/auth/verify?token=${token}`;
  console.log(`\n[auth] Verification link for ${email}:\n${link}\n`);
}

export const autoVerify = () => process.env.EMAIL_AUTO_VERIFY === '1';

// Public shape for /api/me and auth responses — never leaks the hash.
export const publicUser = (u) => ({
  id: u.id, email: u.email, plan: u.plan, credits: u.credits,
  role: u.role, verified: !!u.verified, createdAt: u.created_at,
});

export const isValidEmail = (e) =>
  typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e.trim());
