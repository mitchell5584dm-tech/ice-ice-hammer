// In-memory per-IP sliding-window rate limiter. Zero dependencies.
// Not shared across processes or restarts — it is a brute-force backstop,
// not a distributed quota system.
const buckets = new Map(); // key -> array of attempt timestamps (ms)

function prune(now) {
  for (const [key, hits] of buckets) {
    const fresh = hits.filter((t) => now - t < 10 * 60 * 1000);
    if (fresh.length) buckets.set(key, fresh);
    else buckets.delete(key);
  }
}
setInterval(() => prune(Date.now()), 5 * 60 * 1000).unref();

// Best-effort client IP: first hop of X-Forwarded-For (set by Render/proxies),
// falling back to the socket address. Never trust it for security decisions
// beyond throttling.
export function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) {
    const first = fwd.split(',')[0].trim();
    if (first) return first.slice(0, 64);
  }
  return (req.socket?.remoteAddress || 'unknown').slice(0, 64);
}

// Returns { allowed: true } or { allowed: false, retryAfter } (seconds).
// Callers are expected to answer 429 with a Retry-After header.
export function checkRateLimit(key, { limit = 10, windowMs = 60 * 1000 } = {}) {
  const now = Date.now();
  let hits = buckets.get(key) || [];
  hits = hits.filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    const retryAfter = Math.max(1, Math.ceil((hits[0] + windowMs - now) / 1000));
    buckets.set(key, hits);
    return { allowed: false, retryAfter };
  }
  hits.push(now);
  buckets.set(key, hits);
  return { allowed: true };
}

// Test/dev escape hatch: clears all buckets. Not exposed over HTTP.
export function _resetRateLimits() {
  buckets.clear();
}
