// Nightly Replicate spend reconciliation.
//
// Compares our ledger's estimated Replicate cost for the last N hours against
// the actual Replicate-side spend, and alerts when they drift apart — the
// signal that our per-model credit prices (lib/costs.mjs) have gone stale.
//
// Usage:
//   node scripts/reconcile.mjs [--data-dir ./data] [--window-hours 24]
//
// Replicate-side spend sources, in order of preference:
//   1. REPLICATE_EXPECTED_SPEND_USD — operator-pasted 24h figure from
//      https://replicate.com/account/billing (Replicate exposes NO public
//      billing API as of 2026-10; the web UI is the source of truth).
//   2. The Replicate REST API is probed for any account/billing fields when
//      REPLICATE_API_TOKEN is set (best effort; currently returns nothing
//      usable, which is logged, not treated as an error).
//   3. Neither -> prints UNVERIFIED with the ledger summary and exits 0.
//
// Exit codes: 0 = OK or unverified, 2 = ALERT (drift > 15%).
// Cron example: 0 3 * * * cd /opt/ice-ice-hammer && node scripts/reconcile.mjs >> logs/reconcile.log 2>&1
import '../lib/env.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
process.chdir(path.join(ROOT, '..'));

const args = process.argv.slice(2);
const opt = (name, def = null) => {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : def;
};
if (opt('--data-dir')) process.env.DATA_DIR = path.resolve(opt('--data-dir'));
const windowHours = Math.max(1, Number(opt('--window-hours')) || 24);
const DRIFT_THRESHOLD = 0.15;

const db = await import('../lib/db.mjs');
db.initDb();

const since = Date.now() - windowHours * 3600 * 1000;
const ledger = db.ledgerSummarySince(since);

console.log(`[reconcile] Window: last ${windowHours}h (since ${new Date(since).toISOString()})`);
console.log(`[reconcile] Ledger: ${ledger.generations} generations, ${ledger.creditsDebited} credits debited, est $${ledger.estCostUsd.toFixed(2)} Replicate cost`);

// ---- Replicate-side actual spend ----
let actual = null;
let source = null;

const envOverride = Number(process.env.REPLICATE_EXPECTED_SPEND_USD);
if (Number.isFinite(envOverride) && envOverride >= 0) {
  actual = envOverride;
  source = 'REPLICATE_EXPECTED_SPEND_USD';
} else if (process.env.REPLICATE_API_TOKEN) {
  actual = await probeReplicateBilling(process.env.REPLICATE_API_TOKEN);
  source = actual != null ? 'replicate-api' : null;
}

if (actual == null) {
  console.log('[reconcile] UNVERIFIED — no Replicate spend source available.');
  console.log('[reconcile] Set REPLICATE_EXPECTED_SPEND_USD to the 24h figure from https://replicate.com/account/billing to enable drift checks.');
  process.exit(0);
}

const drift = actual > 0 ? Math.abs(actual - ledger.estCostUsd) / actual : (ledger.estCostUsd > 0 ? 1 : 0);
console.log(`[reconcile] Replicate actual: $${actual.toFixed(2)} (source: ${source})`);
console.log(`[reconcile] Drift: ${(drift * 100).toFixed(1)}% (threshold ${(DRIFT_THRESHOLD * 100).toFixed(0)}%)`);
if (drift > DRIFT_THRESHOLD) {
  console.error(`[reconcile] ALERT — ledger estimate $${ledger.estCostUsd.toFixed(2)} vs actual $${actual.toFixed(2)} drifted ${(drift * 100).toFixed(1)}%. Re-tune lib/costs.mjs from the latest invoice.`);
  process.exit(2);
}
console.log('[reconcile] OK — ledger estimates are within tolerance.');

// Best-effort probe of the Replicate REST API for anything billing-shaped.
// Returns a USD number or null. Never throws.
async function probeReplicateBilling(token) {
  const base = (process.env.REPLICATE_API_BASE || 'https://api.replicate.com/v1').replace(/\/$/, '');
  const candidates = ['/accounts/current', '/account', '/billing'];
  for (const p of candidates) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10000);
      const res = await fetch(base + p, {
        headers: { Authorization: `Bearer ${token}` },
        signal: ctrl.signal,
      }).finally(() => clearTimeout(t));
      if (!res.ok) continue;
      const data = await res.json().catch(() => ({}));
      const found = findSpend(data);
      if (found != null) return found;
    } catch { /* try next candidate */ }
  }
  console.log('[reconcile] Replicate API probe: no billing fields found (expected — Replicate has no public billing API).');
  return null;
}

// Walk a JSON blob looking for a plausible spend/balance field.
function findSpend(obj, depth = 0) {
  if (obj == null || depth > 4) return null;
  if (typeof obj === 'number') return null;
  if (Array.isArray(obj)) {
    for (const v of obj) { const f = findSpend(v, depth + 1); if (f != null) return f; }
    return null;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'number' && v >= 0 && /spend|spent|cost|amount|balance|total/i.test(k)) return v;
      const f = findSpend(v, depth + 1);
      if (f != null) return f;
    }
  }
  return null;
}
