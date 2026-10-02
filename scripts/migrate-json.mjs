// One-shot migration: Phase 0 single-user library (DATA_DIR/library.json +
// DATA_DIR/audio/) -> Phase 1 SQLite (DATA_DIR/ice.db) with per-user audio dirs.
//
// Usage:
//   node scripts/migrate-json.mjs --email you@example.com [--data-dir ./data] [--dry-run]
//
// - --email is required: every migrated track is assigned to this user. The
//   user is created (verified, role=user, random password printed once) if it
//   does not exist yet.
// - The old library.json may be an array of tracks or { tracks: [...] }.
//   Track fields are accepted in camelCase or snake_case.
// - Audio files are moved from DATA_DIR/audio/<file> to
//   DATA_DIR/audio/<userId>/<file>. Tracks whose file is missing keep their
//   row but get audioFile=null (with a warning).
// - Idempotent: tracks whose id already exists in the DB are skipped, so it is
//   safe to re-run. The old library.json is left in place.
import '../lib/env.mjs';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
process.chdir(path.join(ROOT, '..'));

const args = process.argv.slice(2);
const opt = (name, def = null) => {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : def;
};
const flag = (name) => args.includes(name);

const email = opt('--email');
const dataDir = path.resolve(opt('--data-dir') || process.env.DATA_DIR || './data');
const dryRun = flag('--dry-run');

if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
  console.error('Usage: node scripts/migrate-json.mjs --email you@example.com [--data-dir ./data] [--dry-run]');
  process.exit(2);
}
if (dryRun) console.log('[migrate] DRY RUN — no writes will happen.\n');

process.env.DATA_DIR = dataDir;
const db = await import('../lib/db.mjs');
const { hashPassword } = await import('../lib/auth.mjs');
db.initDb();

const libPath = path.join(dataDir, 'library.json');
let raw;
try {
  raw = JSON.parse(await fsp.readFile(libPath, 'utf8'));
} catch (e) {
  console.error(`[migrate] Cannot read ${libPath}: ${e.message}`);
  process.exit(1);
}
const list = Array.isArray(raw) ? raw : Array.isArray(raw.tracks) ? raw.tracks : null;
if (!list) {
  console.error('[migrate] library.json is neither an array nor { tracks: [...] }. Nothing to do.');
  process.exit(1);
}

// Accept camelCase (Phase 0) or snake_case (Phase 1) field names.
const pick = (o, camel, snake) => o[camel] ?? o[snake] ?? null;

let user = db.getUserByEmail(email);
if (!user) {
  const password = crypto.randomBytes(16).toString('hex');
  if (!dryRun) {
    user = db.createUser({
      id: crypto.randomBytes(8).toString('hex'),
      email, passwordHash: hashPassword(password), role: 'user', verified: 1, verifyToken: null,
    });
  }
  console.log(`[migrate] Created user ${email}${dryRun ? ' (not really — dry run)' : ''}.`);
  console.log(`[migrate] One-time password: ${password}  (change it after first login)`);
} else {
  console.log(`[migrate] Assigning tracks to existing user ${email} (${user.id}).`);
}
const userId = user?.id || '<new-user>';

const stats = { migrated: 0, skipped: 0, audioMoved: 0, audioMissing: 0 };
const userAudioDir = path.join(dataDir, 'audio', String(userId));
if (!dryRun) await fsp.mkdir(userAudioDir, { recursive: true });

for (const t of list) {
  if (!t || typeof t !== 'object') { stats.skipped++; continue; }
  const id = pick(t, 'id', 'id');
  if (typeof id !== 'string' || !id) { stats.skipped++; console.log('[migrate] Skipped a track with no id.'); continue; }
  if (!dryRun && db.getTrack(userId, id)) { stats.skipped++; continue; }

  let audioFile = pick(t, 'audioFile', 'audio_file');
  if (audioFile) {
    const base = path.basename(String(audioFile));
    const src = path.join(dataDir, 'audio', base);
    const dst = path.join(userAudioDir, base);
    let exists = false;
    try { await fsp.access(src); exists = true; } catch { /* missing */ }
    if (exists) {
      if (!dryRun) await fsp.rename(src, dst);
      audioFile = base;
      stats.audioMoved++;
    } else {
      console.log(`[migrate] Warning: audio file missing for track ${id} (${base}); keeping the row without audio.`);
      audioFile = null;
      stats.audioMissing++;
    }
  }

  const notes = pick(t, 'notes', 'notes');
  const row = {
    id,
    title: String(pick(t, 'title', 'title') ?? ''),
    style: String(pick(t, 'style', 'style') ?? ''),
    lyrics: String(pick(t, 'lyrics', 'lyrics') ?? ''),
    instrumental: !!pick(t, 'instrumental', 'instrumental'),
    duration: Number.isFinite(Number(pick(t, 'duration', 'duration'))) ? Number(pick(t, 'duration', 'duration')) : null,
    seed: Number.isFinite(Number(pick(t, 'seed', 'seed'))) ? Number(pick(t, 'seed', 'seed')) : null,
    providerId: pick(t, 'providerId', 'provider_id') || null,
    take: pick(t, 'take', 'take') || null,
    status: pick(t, 'status', 'status') || 'ready',
    error: pick(t, 'error', 'error') || null,
    notes: Array.isArray(notes) ? notes.map(String).slice(0, 20) : [],
    audioFile,
    predictionId: pick(t, 'predictionId', 'prediction_id') || null,
    createdAt: Number(pick(t, 'createdAt', 'created_at')) || Date.now(),
    finishedAt: Number(pick(t, 'finishedAt', 'finished_at')) || null,
  };
  if (!dryRun) db.addTrack(userId, row);
  stats.migrated++;
}

console.log('\n[migrate] Done.');
console.log(`[migrate] Tracks migrated: ${stats.migrated}, skipped (existing/invalid): ${stats.skipped}`);
console.log(`[migrate] Audio moved: ${stats.audioMoved}, missing: ${stats.audioMissing}`);
console.log('[migrate] The old library.json was left in place. Re-running is safe (existing ids are skipped).');
console.log(JSON.stringify({ email, userId, dryRun, ...stats }));
