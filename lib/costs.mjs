// Credit pricing and plan tiers for Ice Ice Hammer SaaS (Phase 2).
//
// Credits are the single choke point for Replicate spend: every generation debits
// credits BEFORE any Replicate call happens. No credits -> no spend. Ever.
//
// Pricing rule of thumb: 1 credit ≈ 2.5–3× measured Replicate cost per song, so
// gross margin survives failed generations, retries, and price drift. These are
// estimates — validate against real Replicate invoices (see the nightly
// reconciliation note in the SaaS plan) before locking them for launch.
export const CREDIT_COST_PER_TAKE = {
  'ace-step': 2,       // open-source, GPU-time billed, a few cents/song
  'musicgen': 2,       // open-source, GPU-time billed
  'stable-audio': 3,   // open-source, slightly heavier
  'elevenlabs': 10,    // hosted, per-second billing — the money pit, Pro-only
  'minimax-2.5': 12,   // hosted, fixed per-song price, best vocals
};

// Fallback for models added later without an explicit price: conservative.
const DEFAULT_COST_PER_TAKE = 6;

// Plan tiers (Phase 2, refined from Replicate pricing research 2026-10-02).
// ElevenLabs bills per second of audio (~$1.00/take at the 120s default), so it is
// Pro-only and duration-capped; MiniMax is fixed ~$0.15/song and safe on Creator+.
export const PLANS = {
  free: {
    label: 'Free', price: 0, monthlyCredits: 0,
    models: ['ace-step', 'musicgen'],
    blurb: '10 one-time credits to try it out',
  },
  starter: {
    label: 'Starter', price: 4.99, monthlyCredits: 60,
    models: ['ace-step', 'musicgen', 'stable-audio'],
    blurb: 'For steady sketching on the cheap engines',
  },
  creator: {
    label: 'Creator', price: 8.99, monthlyCredits: 150,
    models: ['ace-step', 'musicgen', 'stable-audio', 'minimax-2.5'],
    blurb: 'Adds MiniMax — the best-sounding vocals',
  },
  pro: {
    label: 'Pro', price: 19.99, monthlyCredits: 400,
    models: ['ace-step', 'musicgen', 'stable-audio', 'minimax-2.5', 'elevenlabs'],
    blurb: 'Everything, incl. ElevenLabs + priority queue',
  },
};

// One-time credit pack: never expires, stacks on top of any plan.
export const CREDIT_PACK = { credits: 100, price: 6.99 };

// Max seconds per take for ElevenLabs (per-second billing). Enforced server-side.
export const ELEVENLABS_MAX_DURATION = 180;
// Credits per second of audio for ElevenLabs. At 1 credit ≈ $0.05 this is ~3x the
// measured ~$0.0083/s Replicate cost.
export const ELEVENLABS_CREDITS_PER_SEC = 0.5;

// Tier gating derived from PLANS so pricing page and generation gates agree.
export const MODEL_ACCESS = Object.fromEntries(
  Object.entries(PLANS).map(([plan, p]) => [plan, p.models])
);

export const PLAN_IDS = Object.keys(PLANS).filter((p) => p !== 'free');

// One-time credit grant on verified signup (free trial).
export const FREE_SIGNUP_CREDITS = 10;

// ---------- Studio Mixer: stem separation (Phase 1) ----------
// Demucs (ryan5453/demucs, htdemucs variant) on Replicate, GPU-time billed.
// A 2–4 minute song takes roughly 60–180 s of T4-class GPU; at Replicate's
// published GPU rates that is ~$0.05–0.13 per run, so 6 credits at the
// ~$0.02/credit estimate keeps the same 2.5–3× margin as generation prices.
// Re-tune from real invoices before launch (see scripts/reconcile.mjs).
export const STEM_MODEL = 'ryan5453/demucs';
export const STEM_MODEL_VARIANT = 'htdemucs'; // 4-stem v4 base: fastest of the htdemucs family
export const STEM_SEPARATION_CREDITS = 6;
export const STEM_NAMES = ['vocals', 'drums', 'bass', 'other'];
export const STEM_USER_MAX_ACTIVE = 2; // simultaneous separations per user

export const stemCostLabel = () => `${STEM_SEPARATION_CREDITS} credits/song`;

export const costFor = (providerId, takes = 1, durationSec = null) => {
  const n = Math.max(1, Math.min(2, takes));
  if (providerId === 'elevenlabs') {
    const secs = Math.max(5, Math.min(ELEVENLABS_MAX_DURATION, Math.round(Number(durationSec) || 120)));
    return Math.max(1, Math.ceil(secs * ELEVENLABS_CREDITS_PER_SEC)) * n;
  }
  return (CREDIT_COST_PER_TAKE[providerId] ?? DEFAULT_COST_PER_TAKE) * n;
};

export const costLabel = (providerId) =>
  providerId === 'elevenlabs' ? `${ELEVENLABS_CREDITS_PER_SEC} credits/sec` : `${costFor(providerId, 1)} credits/take`;

export const canUseModel = (plan, providerId) =>
  (MODEL_ACCESS[plan] || MODEL_ACCESS.free).includes(providerId);

// Rough USD estimate per credit, for the admin spend dashboard only.
// Tune from real invoices; do not use for billing math.
export const EST_USD_PER_CREDIT = 0.02;

// ---------- Creator referral program ----------
// FLAG FOR DAVID: these commission rates are defaults — confirm before launch.
// Referrers earn a cut of what their referred users pay, accruing for
// REFERRAL_WINDOW_MONTHS from the referred user's first paid invoice.
export const REFERRAL_SUBSCRIPTION_RATE = 0.25; // 25% of subscription payments (initial + renewals)
export const REFERRAL_PACK_RATE = 0.10;         // 10% of one-time credit pack purchases
export const REFERRAL_WINDOW_MONTHS = 12;       // commissions accrue for 12 months from first paid invoice
export const REFERRAL_ATTRIBUTION_DAYS = 90;    // /r/CODE cookie attribution window
export const REFERRAL_PAYOUT_THRESHOLD_CENTS = 5000; // $50 minimum balance before a payout can be requested

export const estUsdFor = (providerId, takes = 1) => costFor(providerId, takes) * EST_USD_PER_CREDIT;
