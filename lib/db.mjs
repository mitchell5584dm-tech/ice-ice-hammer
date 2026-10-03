// SQLite store (node:sqlite, no npm deps) replacing lib/store.mjs.
// One process, one file at DATA_DIR/ice.db. Synchronous writes; the app's
// request flow is async anyway, so sync DB calls just work inline.
//
// Tables:
//   users               — accounts with plans, credit balances, roles
//   tracks              — songs, every row owned by exactly one user
//   generation_ledger   — append-only money trail, one row per generated track
//   credit_transactions — append-only, every balance change has a receipt
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
export const AUDIO_DIR = path.join(DATA_DIR, 'audio');
const DB_FILE = path.join(DATA_DIR, 'ice.db');

let db = null;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  credits INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  verified INTEGER NOT NULL DEFAULT 0,
  verify_token TEXT,
  stripe_customer_id TEXT,
  period_reset_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tracks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL DEFAULT '',
  style TEXT DEFAULT '',
  lyrics TEXT DEFAULT '',
  instrumental INTEGER NOT NULL DEFAULT 0,
  duration REAL,
  seed INTEGER,
  provider_id TEXT,
  take TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT,
  notes TEXT NOT NULL DEFAULT '[]',
  audio_file TEXT,
  prediction_id TEXT,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tracks_user ON tracks(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tracks_status ON tracks(status);
CREATE TABLE IF NOT EXISTS generation_ledger (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  track_id TEXT NOT NULL UNIQUE,
  provider_id TEXT,
  model TEXT,
  credits_debited INTEGER NOT NULL,
  est_cost_usd REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  replicate_prediction_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON generation_ledger(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS credit_transactions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL,
  balance_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ctx_user ON credit_transactions(user_id, created_at DESC);
-- Phase 2: idempotency for Stripe webhook retries.
CREATE TABLE IF NOT EXISTS stripe_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
-- Studio Mixer Phase 1: stem separations (one row per paid run) and the
-- resulting stems (one row per separated audio file).
CREATE TABLE IF NOT EXISTS separations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  track_id TEXT NOT NULL REFERENCES tracks(id),
  model TEXT,
  credits_debited INTEGER NOT NULL,
  est_cost_usd REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  replicate_prediction_id TEXT,
  created_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE TABLE IF NOT EXISTS stems (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  track_id TEXT NOT NULL REFERENCES tracks(id),
  separation_id TEXT REFERENCES separations(id),
  name TEXT NOT NULL,
  audio_file TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT,
  created_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_stems_track ON stems(track_id);
CREATE INDEX IF NOT EXISTS idx_sep_user ON separations(user_id, created_at DESC);
-- Studio Mixer Phase 1: NAM capture library (user-uploaded .nam files).
CREATE TABLE IF NOT EXISTS nam_captures (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  file TEXT NOT NULL,
  size INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nam_user ON nam_captures(user_id, created_at DESC);
-- Creator referral program: codes, click tracking, signup attribution, and
-- commission earnings (idempotent per Stripe event; negatives are clawbacks).
CREATE TABLE IF NOT EXISTS referrals (
  code TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS referral_clicks (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL REFERENCES referrals(code),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rclicks_code ON referral_clicks(code);
CREATE TABLE IF NOT EXISTS referral_attributions (
  user_id TEXT PRIMARY KEY,
  code TEXT NOT NULL REFERENCES referrals(code),
  first_paid_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS referral_earnings (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  attributed_user_id TEXT NOT NULL REFERENCES users(id),
  stripe_event_id TEXT UNIQUE NOT NULL,
  stripe_object_id TEXT,
  kind TEXT NOT NULL DEFAULT 'subscription',
  amount_cents INTEGER NOT NULL,
  paid_out INTEGER NOT NULL DEFAULT 0,
  payout_transfer_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rearn_owner ON referral_earnings(owner_user_id, paid_out);
`;

// Phase 2 migration: older DBs created before stripe_subscription_id existed.
function migrateStripeColumns() {
  const cols = db.prepare(`PRAGMA table_info(users)`).all().map((c) => c.name);
  if (!cols.includes('stripe_subscription_id')) {
    db.exec('ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT');
  }
  if (!cols.includes('referred_by')) {
    db.exec('ALTER TABLE users ADD COLUMN referred_by TEXT');
  }
  if (!cols.includes('stripe_connect_id')) {
    db.exec('ALTER TABLE users ADD COLUMN stripe_connect_id TEXT');
  }
}

export function initDb() {
  if (db) return db;
  fs.mkdirSync(AUDIO_DIR, { recursive: true });
  db = new DatabaseSync(DB_FILE);
  db.exec(SCHEMA);
  migrateStripeColumns();
  return db;
}

function mustDb() {
  if (!db) throw new Error('Database not initialised. Call initDb() first.');
  return db;
}

// Run fn inside a transaction; rolls back on throw. Re-entrant: nested calls
// join the outer transaction (single-process sync code, so a counter is safe).
let txDepth = 0;
export function transact(fn) {
  const d = mustDb();
  if (txDepth > 0) return fn();
  txDepth++;
  d.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    d.exec('COMMIT');
    return out;
  } catch (e) {
    try { d.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw e;
  } finally {
    txDepth--;
  }
}

// ---------- users ----------
export function userCount() {
  return mustDb().prepare('SELECT COUNT(*) AS n FROM users').get().n;
}

export function createUser({ id, email, passwordHash, plan = 'free', role = 'user', verified = 0, verifyToken = null }) {
  const now = Date.now();
  mustDb().prepare(
    'INSERT INTO users (id, email, password_hash, plan, credits, role, verified, verify_token, created_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)'
  ).run(id, email.toLowerCase(), passwordHash, plan, role, verified ? 1 : 0, verifyToken, now);
  return getUserById(id);
}

export function getUserById(id) {
  return mustDb().prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

export function getUserByEmail(email) {
  return mustDb().prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase()) || null;
}

export function getUserByVerifyToken(token) {
  if (!token) return null;
  return mustDb().prepare('SELECT * FROM users WHERE verify_token = ?').get(token) || null;
}

// Adds delta credits (negative to debit) and writes the receipt row, atomically.
// Throws { status: 402 } when the balance would go negative.
export function addCredits(userId, delta, reason) {
  return transact(() => {
    const u = getUserById(userId);
    if (!u) { const e = new Error('User not found'); e.status = 404; throw e; }
    const after = u.credits + delta;
    if (after < 0) { const e = new Error('Not enough credits'); e.status = 402; throw e; }
    mustDb().prepare('UPDATE users SET credits = ? WHERE id = ?').run(after, userId);
    mustDb().prepare(
      'INSERT INTO credit_transactions (id, user_id, delta, reason, balance_after, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(cryptoId(), userId, delta, reason, after, Date.now());
    return after;
  });
}

export function setUserVerified(id) {
  mustDb().prepare('UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?').run(id);
}

export function setUserPlan(id, plan) {
  mustDb().prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, id);
}

// ---------- Phase 2: Stripe ----------
export function setStripeCustomer(id, customerId) {
  mustDb().prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, id);
}

export function setStripeSubscription(id, { customerId = null, subscriptionId = null, plan = null, periodResetAt = null }) {
  const sets = [], vals = [];
  if (customerId !== null) { sets.push('stripe_customer_id = ?'); vals.push(customerId); }
  if (subscriptionId !== null) { sets.push('stripe_subscription_id = ?'); vals.push(subscriptionId); }
  if (plan !== null) { sets.push('plan = ?'); vals.push(plan); }
  if (periodResetAt !== null) { sets.push('period_reset_at = ?'); vals.push(periodResetAt); }
  if (!sets.length) return;
  vals.push(id);
  mustDb().prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
}

export function clearStripeSubscription(id) {
  mustDb().prepare(`UPDATE users SET stripe_subscription_id = NULL, plan = 'free' WHERE id = ?`).run(id);
}

export function getUserByStripeSubscription(subscriptionId) {
  if (!subscriptionId) return null;
  return mustDb().prepare('SELECT * FROM users WHERE stripe_subscription_id = ?').get(subscriptionId) || null;
}

export function getUserByStripeCustomer(customerId) {
  if (!customerId) return null;
  return mustDb().prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(customerId) || null;
}

// Idempotency for Stripe webhook retries. Returns true if this event id was
// already processed (caller should skip it).
export function stripeEventSeen(id) {
  return !!mustDb().prepare('SELECT 1 FROM stripe_events WHERE id = ?').get(id);
}

export function recordStripeEvent(id, type) {
  mustDb().prepare('INSERT OR IGNORE INTO stripe_events (id, type, created_at) VALUES (?, ?, ?)')
    .run(id, type, Date.now());
}

export function cryptoId() {
  return crypto.randomBytes(8).toString('hex');
}

// ---------- tracks ----------
function rowToTrack(r) {
  if (!r) return null;
  return {
    id: r.id, userId: r.user_id, title: r.title, style: r.style, lyrics: r.lyrics,
    instrumental: !!r.instrumental, duration: r.duration, seed: r.seed,
    providerId: r.provider_id, take: r.take, status: r.status, error: r.error,
    notes: JSON.parse(r.notes || '[]'), audioFile: r.audio_file, predictionId: r.prediction_id,
    createdAt: r.created_at, finishedAt: r.finished_at, updatedAt: r.updated_at,
  };
}

export function addTrack(userId, t) {
  const now = Date.now();
  mustDb().prepare(
    `INSERT INTO tracks (id, user_id, title, style, lyrics, instrumental, duration, seed, provider_id, take, status, error, notes, audio_file, prediction_id, created_at, finished_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    t.id, userId, t.title || '', t.style || '', t.lyrics || '', t.instrumental ? 1 : 0,
    t.duration ?? null, t.seed ?? null, t.providerId || null, t.take || null,
    t.status || 'queued', t.error || null, JSON.stringify(t.notes || []), t.audioFile || null,
    t.predictionId || null, t.createdAt || now, t.finishedAt || null, now
  );
  return getTrack(userId, t.id);
}

export function getTrack(userId, id) {
  const r = mustDb().prepare('SELECT * FROM tracks WHERE id = ? AND user_id = ?').get(id, userId);
  return rowToTrack(r);
}

export function listTracks(userId) {
  return mustDb().prepare('SELECT * FROM tracks WHERE user_id = ? ORDER BY created_at DESC').all(userId).map(rowToTrack);
}

// All in-flight tracks across users (for the background poller).
export function listActiveTracks() {
  return mustDb().prepare(`SELECT * FROM tracks WHERE status IN ('queued','generating') AND prediction_id IS NOT NULL`).all().map(rowToTrack);
}

// Tracks stuck without ever starting (for boot recovery).
export function listStuckTracks() {
  return mustDb().prepare(`SELECT * FROM tracks WHERE status IN ('queued','generating')`).all().map(rowToTrack);
}

export function updateTrack(userId, id, patch) {
  const cur = getTrack(userId, id);
  if (!cur) return null;
  const merged = { ...cur, ...patch };
  mustDb().prepare(
    `UPDATE tracks SET title=?, style=?, lyrics=?, instrumental=?, duration=?, seed=?, provider_id=?, take=?, status=?, error=?, notes=?, audio_file=?, prediction_id=?, finished_at=?, updated_at=? WHERE id=? AND user_id=?`
  ).run(
    merged.title, merged.style, merged.lyrics, merged.instrumental ? 1 : 0,
    merged.duration ?? null, merged.seed ?? null, merged.providerId, merged.take,
    merged.status, merged.error || null, JSON.stringify(merged.notes || []),
    merged.audioFile || null, merged.predictionId || null, merged.finishedAt || null,
    Date.now(), id, userId
  );
  return getTrack(userId, id);
}

// Deletes the row and returns the track (caller removes the audio file).
export function removeTrack(userId, id) {
  const t = getTrack(userId, id);
  if (!t) return null;
  mustDb().prepare('DELETE FROM tracks WHERE id = ? AND user_id = ?').run(id, userId);
  return t;
}

export function activeCountForUser(userId) {
  return mustDb().prepare(`SELECT COUNT(*) AS n FROM tracks WHERE user_id = ? AND status IN ('queued','generating')`).get(userId).n;
}

// ---------- generation ledger ----------
export function addLedgerEntry({ id, userId, trackId, providerId, model, creditsDebited, estCostUsd, replicatePredictionId = null }) {
  mustDb().prepare(
    'INSERT INTO generation_ledger (id, user_id, track_id, provider_id, model, credits_debited, est_cost_usd, status, replicate_prediction_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, userId, trackId, providerId, model, creditsDebited, estCostUsd ?? null, 'pending', replicatePredictionId, Date.now());
}

export function markLedgerDone(trackId) {
  mustDb().prepare(`UPDATE generation_ledger SET status = 'done' WHERE track_id = ? AND status = 'pending'`).run(trackId);
}

// Refunds a pending ledger entry exactly once. Returns refunded credits (0 if already done/refunded).
export function refundLedger(trackId) {
  return transact(() => {
    const row = mustDb().prepare('SELECT * FROM generation_ledger WHERE track_id = ?').get(trackId);
    if (!row || row.status !== 'pending') return 0;
    mustDb().prepare(`UPDATE generation_ledger SET status = 'refunded' WHERE track_id = ?`).run(trackId);
    addCredits(row.user_id, row.credits_debited, 'refund');
    return row.credits_debited;
  });
}

// Ledger summary for a time window (used by scripts/reconcile.mjs).
// Refunded generations are excluded: a refunded credit means we do not expect
// Replicate to have billed us for it.
export function ledgerSummarySince(sinceMs) {
  const row = mustDb().prepare(`
    SELECT COUNT(*) AS generations,
           COALESCE(SUM(credits_debited), 0) AS credits_debited,
           COALESCE(SUM(est_cost_usd), 0) AS est_cost_usd
    FROM generation_ledger WHERE created_at >= ? AND status != 'refunded'`).get(sinceMs);
  const perModel = mustDb().prepare(`
    SELECT provider_id, model, COUNT(*) AS generations,
           COALESCE(SUM(est_cost_usd), 0) AS est_cost_usd
    FROM generation_ledger WHERE created_at >= ? AND status != 'refunded'
    GROUP BY provider_id, model ORDER BY est_cost_usd DESC`).all(sinceMs);
  return { generations: row.generations, creditsDebited: row.credits_debited, estCostUsd: row.est_cost_usd, perModel };
}

// ---------- separations & stems (Studio Mixer) ----------
export function addSeparation({ id, userId, trackId, model, creditsDebited, estCostUsd }) {
  mustDb().prepare(
    'INSERT INTO separations (id, user_id, track_id, model, credits_debited, est_cost_usd, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, userId, trackId, model || null, creditsDebited, estCostUsd ?? null, 'pending', Date.now());
  return getSeparation(id);
}

export function getSeparation(id) {
  return mustDb().prepare('SELECT * FROM separations WHERE id = ?').get(id) || null;
}

export function updateSeparation(id, patch) {
  const sets = [], vals = [];
  for (const k of ['status', 'replicate_prediction_id', 'finished_at']) {
    if (patch[k] !== undefined) { sets.push(`${k} = ?`); vals.push(patch[k]); }
  }
  if (!sets.length) return getSeparation(id);
  vals.push(id);
  mustDb().prepare(`UPDATE separations SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  return getSeparation(id);
}

// Refunds a pending separation exactly once (mirror of refundLedger).
export function refundSeparation(separationId) {
  return transact(() => {
    const row = mustDb().prepare('SELECT * FROM separations WHERE id = ?').get(separationId);
    if (!row || row.status !== 'pending') return 0;
    mustDb().prepare(`UPDATE separations SET status = 'refunded' WHERE id = ?`).run(separationId);
    addCredits(row.user_id, row.credits_debited, 'refund');
    return row.credits_debited;
  });
}

export function markSeparationDone(id) {
  mustDb().prepare(`UPDATE separations SET status = 'done', finished_at = ? WHERE id = ?`).run(Date.now(), id);
}

export function listActiveSeparations() {
  return mustDb().prepare(`SELECT * FROM separations WHERE status IN ('pending','processing') AND replicate_prediction_id IS NOT NULL`).all();
}

export function listStuckSeparations() {
  return mustDb().prepare(`SELECT * FROM separations WHERE status IN ('pending','processing')`).all();
}

export function activeSeparationCountForUser(userId) {
  return mustDb().prepare(`SELECT COUNT(*) AS n FROM separations WHERE user_id = ? AND status IN ('pending','processing')`).get(userId).n;
}

function rowToStem(r) {
  if (!r) return null;
  return {
    id: r.id, userId: r.user_id, trackId: r.track_id, separationId: r.separation_id,
    name: r.name, audioFile: r.audio_file, status: r.status, error: r.error,
    createdAt: r.created_at, finishedAt: r.finished_at,
  };
}

export function addStem({ id, userId, trackId, separationId, name }) {
  mustDb().prepare(
    'INSERT INTO stems (id, user_id, track_id, separation_id, name, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, userId, trackId, separationId || null, name, 'queued', Date.now());
  return getStem(id);
}

export function getStem(id) {
  return rowToStem(mustDb().prepare('SELECT * FROM stems WHERE id = ?').get(id));
}

export function getStemForUser(userId, id) {
  return rowToStem(mustDb().prepare('SELECT * FROM stems WHERE id = ? AND user_id = ?').get(id, userId));
}

export function listStemsForTrack(userId, trackId) {
  return mustDb().prepare('SELECT * FROM stems WHERE user_id = ? AND track_id = ? ORDER BY name').all(userId, trackId).map(rowToStem);
}

export function updateStem(id, patch) {
  const sets = [], vals = [];
  for (const k of ['status', 'audio_file', 'error', 'finished_at']) {
    if (patch[k] !== undefined) { sets.push(`${k} = ?`); vals.push(patch[k]); }
  }
  if (!sets.length) return getStem(id);
  vals.push(id);
  mustDb().prepare(`UPDATE stems SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  return getStem(id);
}

export function removeStemsForTrack(userId, trackId) {
  const rows = listStemsForTrack(userId, trackId);
  mustDb().prepare('DELETE FROM stems WHERE user_id = ? AND track_id = ?').run(userId, trackId);
  return rows;
}

// 'none' | 'separating' | 'ready' | 'failed' — drives the Split/Mix buttons in the UI.
export function stemStatusForTrack(userId, trackId) {
  const rows = mustDb().prepare('SELECT status FROM stems WHERE user_id = ? AND track_id = ?').all(userId, trackId);
  if (!rows.length) return 'none';
  if (rows.every((r) => r.status === 'ready')) return 'ready';
  if (rows.some((r) => r.status === 'failed')) return 'failed';
  return 'separating';
}

// ---------- NAM captures (Studio Mixer) ----------
export function addNamCapture({ id, userId, name, file, size }) {
  mustDb().prepare(
    'INSERT INTO nam_captures (id, user_id, name, file, size, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, userId, name, file, size ?? null, Date.now());
  return getNamCapture(userId, id);
}

export function getNamCapture(userId, id) {
  return mustDb().prepare('SELECT * FROM nam_captures WHERE id = ? AND user_id = ?').get(id, userId) || null;
}

export function listNamCaptures(userId) {
  return mustDb().prepare('SELECT * FROM nam_captures WHERE user_id = ? ORDER BY created_at DESC').all(userId);
}

export function removeNamCapture(userId, id) {
  const c = getNamCapture(userId, id);
  if (!c) return null;
  mustDb().prepare('DELETE FROM nam_captures WHERE id = ? AND user_id = ?').run(id, userId);
  return c;
}

// ---------- Creator referral program ----------
// Short URL-safe codes: 6 random bytes -> 8 base62-ish chars (base64url).
function newReferralCode() {
  return crypto.randomBytes(6).toString('base64url');
}

// Creates the user's code, or returns the existing one (idempotent).
export function createReferralCode(userId) {
  const existing = mustDb().prepare('SELECT code FROM referrals WHERE owner_user_id = ?').get(userId);
  if (existing) return existing.code;
  for (let i = 0; i < 10; i++) {
    const code = newReferralCode();
    try {
      mustDb().prepare('INSERT INTO referrals (code, owner_user_id, created_at) VALUES (?, ?, ?)')
        .run(code, userId, Date.now());
      return code;
    } catch (e) {
      if (!String(e.message).includes('UNIQUE')) throw e; // collision: try again
    }
  }
  throw new Error('Could not generate a unique referral code.');
}

export function getReferralByCode(code) {
  if (typeof code !== 'string' || !/^[A-Za-z0-9_-]{4,24}$/.test(code)) return null;
  return mustDb().prepare('SELECT * FROM referrals WHERE code = ?').get(code) || null;
}

export function recordReferralClick(code) {
  mustDb().prepare('INSERT INTO referral_clicks (id, code, created_at) VALUES (?, ?, ?)')
    .run(cryptoId(), code, Date.now());
}

// Attribute a signup to a referral code. Rules:
// - invalid/unknown codes are ignored silently
// - no self-referral: the code owner's own signup never attributes
// - one attribution per account (user_id is the primary key)
export function attributeUser(userId, code) {
  const ref = getReferralByCode(code);
  if (!ref) return null;
  if (ref.owner_user_id === userId) return null; // self-referral
  mustDb().prepare('INSERT OR IGNORE INTO referral_attributions (user_id, code, created_at) VALUES (?, ?, ?)')
    .run(userId, code, Date.now());
  mustDb().prepare('UPDATE users SET referred_by = ? WHERE id = ? AND referred_by IS NULL').run(code, userId);
  return mustDb().prepare('SELECT * FROM referral_attributions WHERE user_id = ?').get(userId) || null;
}

export function getAttribution(userId) {
  return mustDb().prepare('SELECT * FROM referral_attributions WHERE user_id = ?').get(userId) || null;
}

// Marks the attribution's first paid invoice (starts the 12-month window).
export function markAttributionFirstPaid(userId) {
  mustDb().prepare('UPDATE referral_attributions SET first_paid_at = ? WHERE user_id = ? AND first_paid_at IS NULL')
    .run(Date.now(), userId);
}

// Test/ops helper: set an attribution's first_paid_at directly (e.g. to
// simulate an aged-out 12-month window).
export function setAttributionFirstPaid(userId, ts) {
  mustDb().prepare('UPDATE referral_attributions SET first_paid_at = ? WHERE user_id = ?').run(ts, userId);
}

// Commission earning. Idempotent per Stripe event: a retried webhook inserts
// nothing the second time (UNIQUE on stripe_event_id). amount_cents may be
// negative for clawbacks.
export function addReferralEarning({ ownerUserId, attributedUserId, stripeEventId, stripeObjectId = null, kind = 'subscription', amountCents }) {
  if (!ownerUserId || !attributedUserId || !stripeEventId || !Number.isFinite(amountCents)) return null;
  const r = mustDb().prepare(
    `INSERT OR IGNORE INTO referral_earnings
     (id, owner_user_id, attributed_user_id, stripe_event_id, stripe_object_id, kind, amount_cents, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(cryptoId(), ownerUserId, attributedUserId, stripeEventId, stripeObjectId, kind, Math.round(amountCents), Date.now());
  if (r.changes === 0) return null; // duplicate event: already accrued
  return mustDb().prepare('SELECT * FROM referral_earnings WHERE stripe_event_id = ?').get(stripeEventId);
}

// Dashboard stats for a referrer.
export function referralStats(ownerUserId) {
  const d = mustDb();
  const codeRow = d.prepare('SELECT code FROM referrals WHERE owner_user_id = ?').get(ownerUserId);
  const code = codeRow ? codeRow.code : null;
  const clicks = code ? d.prepare('SELECT COUNT(*) AS n FROM referral_clicks WHERE code = ?').get(code).n : 0;
  const signups = code ? d.prepare('SELECT COUNT(*) AS n FROM referral_attributions WHERE code = ?').get(code).n : 0;
  const activeSubscribers = code
    ? d.prepare(`SELECT COUNT(DISTINCT a.user_id) AS n FROM referral_attributions a
                 JOIN users u ON u.id = a.user_id WHERE a.code = ? AND u.plan != 'free'`).get(code).n : 0;
  const bal = d.prepare(`SELECT COALESCE(SUM(amount_cents), 0) AS s FROM referral_earnings
                         WHERE owner_user_id = ? AND paid_out = 0`).get(ownerUserId).s;
  const paid = d.prepare(`SELECT COALESCE(SUM(amount_cents), 0) AS s FROM referral_earnings
                          WHERE owner_user_id = ? AND paid_out = 1`).get(ownerUserId).s;
  return { code, clicks, signups, activeSubscribers, balanceCents: bal, paidOutCents: paid };
}

// Per-referrer liability for the admin view.
export function referralLiabilities() {
  return mustDb().prepare(`
    SELECT u.id AS user_id, u.email,
           (SELECT code FROM referrals r WHERE r.owner_user_id = u.id) AS code,
           (SELECT COUNT(*) FROM referral_attributions a
              JOIN referrals r ON r.code = a.code WHERE r.owner_user_id = u.id) AS signups,
           COALESCE(SUM(CASE WHEN e.paid_out = 0 THEN e.amount_cents ELSE 0 END), 0) AS owed_cents,
           COALESCE(SUM(CASE WHEN e.paid_out = 1 THEN e.amount_cents ELSE 0 END), 0) AS paid_cents
    FROM users u LEFT JOIN referral_earnings e ON e.owner_user_id = u.id
    GROUP BY u.id HAVING owed_cents != 0 OR paid_cents != 0 OR signups > 0
    ORDER BY owed_cents DESC`).all();
}

// Marks all unpaid earnings for a referrer as paid out (after a transfer).
// Returns the rows that were marked (for the payout receipt).
export function markEarningsPaidOut(ownerUserId, transferId) {
  return transact(() => {
    const rows = mustDb().prepare(
      'SELECT * FROM referral_earnings WHERE owner_user_id = ? AND paid_out = 0').all(ownerUserId);
    if (!rows.length) return [];
    mustDb().prepare(
      'UPDATE referral_earnings SET paid_out = 1, payout_transfer_id = ? WHERE owner_user_id = ? AND paid_out = 0'
    ).run(transferId, ownerUserId);
    return rows;
  });
}

// Unpaid positive earnings for one attributed user (for refund clawbacks).
export function listUnpaidReferralEarnings(ownerUserId, attributedUserId) {
  return mustDb().prepare(
    `SELECT * FROM referral_earnings
     WHERE owner_user_id = ? AND attributed_user_id = ? AND paid_out = 0 AND amount_cents > 0
     ORDER BY created_at DESC`
  ).all(ownerUserId, attributedUserId);
}

export function setStripeConnectId(userId, connectId) {
  mustDb().prepare('UPDATE users SET stripe_connect_id = ? WHERE id = ?').run(connectId, userId);
}

// ---------- admin ----------
export function spendSummary() {
  const perModel = mustDb().prepare(`
    SELECT provider_id, model, COUNT(*) AS generations,
           SUM(credits_debited) AS credits_debited,
           SUM(CASE WHEN status='done' THEN credits_debited ELSE 0 END) AS credits_succeeded,
           SUM(CASE WHEN status='refunded' THEN credits_debited ELSE 0 END) AS credits_refunded,
           SUM(est_cost_usd) AS est_cost_usd
    FROM generation_ledger GROUP BY provider_id, model ORDER BY credits_debited DESC`).all();
  const perUser = mustDb().prepare(`
    SELECT u.email, u.plan, COUNT(l.id) AS generations, SUM(l.credits_debited) AS credits_debited
    FROM generation_ledger l JOIN users u ON u.id = l.user_id
    GROUP BY l.user_id ORDER BY credits_debited DESC LIMIT 100`).all();
  const totals = mustDb().prepare(`
    SELECT COUNT(*) AS generations,
           COALESCE(SUM(credits_debited), 0) AS credits_debited,
           COALESCE(SUM(est_cost_usd), 0) AS est_cost_usd
    FROM generation_ledger`).get();
  const txTotals = mustDb().prepare(`
    SELECT reason, SUM(delta) AS total FROM credit_transactions GROUP BY reason`).all();
  return { perModel, perUser, totals, transactions: txTotals, referrals: referralLiabilities() };
}
