// Stripe billing for Ice Ice Hammer SaaS (Phase 2).
//
// Subscriptions (Starter/Creator/Pro) grant monthly credits on purchase and on
// every renewal; one-time credit packs grant credits immediately and never expire.
// Credits remain the single choke point for Replicate spend — billing only ever
// ADDS credits, generation only ever debits them.
//
// Design notes:
// - Webhook signature verification is done by hand with node:crypto (no network,
//   no stripe package needed), so /api/billing/webhook works even in tests.
// - The stripe npm package is only needed for creating Checkout/Portal sessions.
//   Set STRIPE_MOCK=1 to use an in-process fake (tests / local dev without keys).
// - All webhook processing is idempotent: Stripe retries are recorded in the
//   stripe_events table, so a duplicate delivery can never double-grant credits.
// - checkout.session.completed grants the FIRST month's credits; invoice.paid
//   only grants on billing_reason === 'subscription_cycle' (renewals), so the
//   first invoice (billing_reason 'subscription_create') is not double-counted.
import crypto from 'node:crypto';
import {
  transact, getUserById, addCredits, setStripeCustomer, setStripeSubscription,
  clearStripeSubscription, getUserByStripeSubscription, getUserByStripeCustomer,
  stripeEventSeen, recordStripeEvent, setStripeConnectId,
  getAttribution, getReferralByCode, markAttributionFirstPaid, addReferralEarning,
  listUnpaidReferralEarnings,
} from './db.mjs';
import {
  PLANS, PLAN_IDS, CREDIT_PACK, FREE_SIGNUP_CREDITS,
  REFERRAL_SUBSCRIPTION_RATE, REFERRAL_PACK_RATE, REFERRAL_WINDOW_MONTHS,
} from './costs.mjs';

export { PLANS, PLAN_IDS, CREDIT_PACK };

const MONTH_MS = 30 * 24 * 60 * 60 * 1000;
const WEBHOOK_TOLERANCE_S = 600;

export const billingEnabled = () => !!process.env.STRIPE_SECRET_KEY;

function requireBilling() {
  if (!billingEnabled()) {
    throw Object.assign(new Error('Billing is not configured on this server (STRIPE_SECRET_KEY is missing).'), { status: 503 });
  }
}

export function priceIdForPlan(plan) {
  const env = { starter: 'STRIPE_PRICE_STARTER', creator: 'STRIPE_PRICE_CREATOR', pro: 'STRIPE_PRICE_PRO' }[plan];
  const id = env && process.env[env];
  if (!id) throw Object.assign(new Error(`Missing price id: set ${env} to the Stripe Price for the ${plan} plan.`), { status: 503 });
  return id;
}

export function priceIdForPack() {
  const id = process.env.STRIPE_PRICE_PACK;
  if (!id) throw Object.assign(new Error('Missing price id: set STRIPE_PRICE_PACK to the Stripe Price for the 100-credit pack.'), { status: 503 });
  return id;
}

// Public pricing info for the frontend (prices are public by design).
export function billingConfig() {
  return {
    enabled: billingEnabled(),
    plans: PLAN_IDS.map((id) => ({
      id, label: PLANS[id].label, price: PLANS[id].price,
      monthlyCredits: PLANS[id].monthlyCredits, blurb: PLANS[id].blurb, models: PLANS[id].models,
    })),
    pack: { price: CREDIT_PACK.price, credits: CREDIT_PACK.credits },
    freeCredits: FREE_SIGNUP_CREDITS,
  };
}

// ---------- Stripe client (real or mock) ----------
let cachedClient = null;
let mockCounter = 0;

function mockStripeClient() {
  return {
    __mock: true,
    customers: {
      create: async ({ email, metadata }) => ({ id: `cus_mock_${++mockCounter}`, email, metadata: metadata || {} }),
    },
    checkout: {
      sessions: {
        create: async (params) => ({
          id: `cs_mock_${++mockCounter}`,
          url: `https://checkout.stripe.com/pay/cs_mock_${mockCounter}`,
          mode: params.mode,
          customer: params.customer,
          metadata: params.metadata || {},
        }),
      },
    },
    billingPortal: {
      sessions: {
        create: async ({ customer }) => ({ url: `https://billing.stripe.com/p/session/mock_${++mockCounter}?customer=${customer}` }),
      },
    },
    accounts: {
      create: async ({ email, metadata }) => ({ id: `acct_mock_${++mockCounter}`, email, metadata: metadata || {} }),
    },
    accountLinks: {
      create: async ({ account }) => ({ url: `https://connect.stripe.com/setup/mock_${++mockCounter}?account=${account}` }),
    },
    transfers: {
      create: async (params) => {
        // STRIPE_MOCK_TRANSFER_DELAY_MS widens the in-flight window so tests can race payouts.
        const delay = Number(process.env.STRIPE_MOCK_TRANSFER_DELAY_MS || 0);
        if (delay > 0) await new Promise((r) => setTimeout(r, delay));
        return {
        id: `tr_mock_${++mockCounter}`, amount: params.amount, currency: params.currency,
        destination: params.destination, metadata: params.metadata || {},
        };
      },
    },
  };
}

export async function getStripeClient() {
  if (cachedClient) return cachedClient;
  if (process.env.STRIPE_MOCK === '1') {
    cachedClient = mockStripeClient();
    return cachedClient;
  }
  let StripeCtor;
  try {
    StripeCtor = (await import('stripe')).default;
  } catch {
    throw Object.assign(new Error('The "stripe" npm package is not installed. Run: npm install'), { status: 503 });
  }
  cachedClient = new StripeCtor(process.env.STRIPE_SECRET_KEY);
  return cachedClient;
}

// Test/dev helper: drop the cached client (e.g. between test servers).
export function resetStripeClient() { cachedClient = null; }

async function ensureCustomer(user, stripe) {
  if (user.stripe_customer_id) return user.stripe_customer_id;
  const customer = await stripe.customers.create({ email: user.email, metadata: { userId: user.id } });
  setStripeCustomer(user.id, customer.id);
  return customer.id;
}

// ---------- Checkout + Customer Portal ----------
export async function createCheckoutSession({ user, kind, plan = null, baseUrl }) {
  requireBilling();
  const stripe = await getStripeClient();
  const customerId = await ensureCustomer(user, stripe);
  const successUrl = `${baseUrl}/?billing=success&session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${baseUrl}/?billing=cancelled`;

  if (kind === 'subscription') {
    if (!PLANS[plan] || plan === 'free') throw Object.assign(new Error('Unknown plan.'), { status: 400 });
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customerId,
      line_items: [{ price: priceIdForPlan(plan), quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: { userId: user.id, kind: 'subscription', plan },
      subscription_data: { metadata: { userId: user.id, plan } },
    });
    return session;
  }
  if (kind === 'pack') {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer: customerId,
      line_items: [{ price: priceIdForPack(), quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: { userId: user.id, kind: 'pack', credits: String(CREDIT_PACK.credits) },
    });
    return session;
  }
  throw Object.assign(new Error('Unknown checkout kind. Use "subscription" or "pack".'), { status: 400 });
}

export async function createPortalSession({ user, returnUrl }) {
  requireBilling();
  const stripe = await getStripeClient();
  if (!user.stripe_customer_id) {
    throw Object.assign(new Error('No billing account yet — buy a plan or credit pack first.'), { status: 400 });
  }
  const session = await stripe.billingPortal.sessions.create({ customer: user.stripe_customer_id, return_url: returnUrl });
  return session;
}

// ---------- Webhook signature verification (hand-rolled, no stripe package) ----------
// Stripe sends:  Stripe-Signature: t=<unix_ts>,v1=<hex hmac>
// signed payload: "<t>.<raw body>", keyed with STRIPE_WEBHOOK_SECRET.
export function verifyWebhookSignature(rawBody, sigHeader) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw Object.assign(new Error('STRIPE_WEBHOOK_SECRET is not set.'), { status: 503 });
  if (!sigHeader) throw Object.assign(new Error('Missing Stripe-Signature header.'), { status: 400 });

  let t = null;
  const v1s = [];
  for (const part of String(sigHeader).split(',')) {
    const [k, v] = part.trim().split('=');
    if (k === 't') t = v;
    else if (k === 'v1' && v) v1s.push(v);
  }
  if (!t || v1s.length === 0) throw Object.assign(new Error('Malformed Stripe-Signature header.'), { status: 400 });

  const expected = crypto.createHmac('sha256', secret).update(`${t}.${rawBody.toString('utf8')}`).digest('hex');
  const ok = v1s.some((v) => v.length === expected.length && crypto.timingSafeEqual(Buffer.from(v, 'utf8'), Buffer.from(expected, 'utf8')));
  if (!ok) throw Object.assign(new Error('Invalid webhook signature.'), { status: 400 });

  const age = Math.abs(Date.now() / 1000 - Number(t));
  if (!Number.isFinite(age) || age > WEBHOOK_TOLERANCE_S) {
    throw Object.assign(new Error('Webhook timestamp too old.'), { status: 400 });
  }
  return true;
}

// ---------- Webhook event handling (idempotent) ----------
export function handleWebhookEvent(event) {
  return transact(() => {
    if (!event || !event.id || !event.type) throw Object.assign(new Error('Malformed event.'), { status: 400 });
    if (stripeEventSeen(event.id)) return { ok: true, duplicate: true };

    const obj = (event.data && event.data.object) || {};
    try {
      if (event.type === 'checkout.session.completed') handleCheckoutCompleted(obj, event.id);
      else if (event.type === 'invoice.paid') handleInvoicePaid(obj, event.id);
      else if (event.type === 'customer.subscription.deleted') handleSubscriptionDeleted(obj);
      else if (event.type === 'charge.refunded') handleChargeRefunded(obj, event.id);
      else if (event.type === 'invoice.payment_failed') {
        console.warn(`[billing] payment failed for customer ${obj.customer}, invoice ${obj.id}`);
      } else {
        console.log(`[billing] ignoring event type ${event.type}`);
      }
    } catch (e) {
      // Record the event so a poison event doesn't retry forever, but keep the
      // 500 so Stripe/operators can see something went wrong.
      console.error(`[billing] error handling ${event.type} ${event.id}:`, e.message);
      recordStripeEvent(event.id, event.type + ':error');
      throw e;
    }
    recordStripeEvent(event.id, event.type);
    return { ok: true };
  });
}

function handleCheckoutCompleted(obj, eventId) {
  const md = obj.metadata || {};
  const user = md.userId ? getUserById(md.userId) : null;
  if (!user) { console.warn(`[billing] checkout completed for unknown user ${md.userId}`); return; }
  if (obj.customer && obj.customer !== user.stripe_customer_id) setStripeCustomer(user.id, obj.customer);

  if (md.kind === 'subscription' && PLANS[md.plan] && md.plan !== 'free') {
    const plan = PLANS[md.plan];
    setStripeSubscription(user.id, {
      customerId: obj.customer || user.stripe_customer_id,
      subscriptionId: obj.subscription || null,
      plan: md.plan,
      periodResetAt: Date.now() + MONTH_MS,
    });
    addCredits(user.id, plan.monthlyCredits, 'purchase');
    accrueReferralCommission(user, {
      kind: 'subscription', grossCents: Math.round(plan.price * 100),
      stripeEventId: `ref:${eventId}`, stripeObjectId: obj.subscription || null,
    });
    console.log(`[billing] ${user.email} subscribed to ${md.plan} (+${plan.monthlyCredits} credits)`);
  } else if (md.kind === 'pack') {
    const credits = Number(md.credits) || CREDIT_PACK.credits;
    addCredits(user.id, credits, 'purchase');
    accrueReferralCommission(user, {
      kind: 'pack',
      grossCents: Number(obj.amount_total) || Math.round(CREDIT_PACK.price * 100),
      stripeEventId: `ref:${eventId}`, stripeObjectId: obj.payment_intent || null,
    });
    console.log(`[billing] ${user.email} bought a ${credits}-credit pack`);
  } else {
    console.warn(`[billing] checkout completed with unknown kind/plan: ${JSON.stringify(md)}`);
  }
}

function handleInvoicePaid(obj, eventId) {
  // The first invoice of a new subscription (billing_reason 'subscription_create')
  // is already covered by checkout.session.completed — only renewals grant credits.
  if (obj.billing_reason !== 'subscription_cycle') return;
  const user = obj.subscription
    ? getUserByStripeSubscription(obj.subscription)
    : getUserByStripeCustomer(obj.customer);
  if (!user) { console.warn(`[billing] renewal invoice for unknown subscription ${obj.subscription}`); return; }
  const plan = PLANS[user.plan];
  if (!plan || user.plan === 'free') return;
  addCredits(user.id, plan.monthlyCredits, 'purchase');
  accrueReferralCommission(user, {
    kind: 'subscription',
    grossCents: Number(obj.amount_paid) || Math.round(plan.price * 100),
    stripeEventId: `ref:${eventId}`, stripeObjectId: obj.id || null,
  });
  setStripeSubscription(user.id, { periodResetAt: Date.now() + MONTH_MS });
  console.log(`[billing] ${user.email} renewal: +${plan.monthlyCredits} credits (${user.plan})`);
}

function handleSubscriptionDeleted(obj) {
  const user = getUserByStripeSubscription(obj.id);
  if (!user) { console.warn(`[billing] subscription.deleted for unknown subscription ${obj.id}`); return; }
  // Downgrade to free; already-paid credits stay on the account.
  clearStripeSubscription(user.id);
  console.log(`[billing] ${user.email} subscription ended; downgraded to free (credits kept)`);
}

// ---------- Creator referral program ----------
// Accrues a commission when a referred user pays. Deliberately defensive:
// referral bugs must NEVER break credit grants, so everything is wrapped.
function accrueReferralCommission(user, { kind, grossCents, stripeEventId, stripeObjectId }) {
  try {
    const rate = kind === 'pack' ? REFERRAL_PACK_RATE : REFERRAL_SUBSCRIPTION_RATE;
    const attr = getAttribution(user.id);
    if (!attr) return; // not a referred signup
    const ref = getReferralByCode(attr.code);
    if (!ref || ref.owner_user_id === user.id) return; // unknown code or self
    const owner = getUserById(ref.owner_user_id);
    if (!owner) return;
    // 12-month window from the referred user's FIRST paid invoice.
    const windowMs = REFERRAL_WINDOW_MONTHS * 30 * 24 * 60 * 60 * 1000;
    if (attr.first_paid_at && Date.now() - attr.first_paid_at > windowMs) return;
    const amountCents = Math.round(Number(grossCents) * rate);
    if (!Number.isFinite(amountCents) || amountCents <= 0) return;
    const earning = addReferralEarning({
      ownerUserId: owner.id, attributedUserId: user.id,
      stripeEventId, stripeObjectId: stripeObjectId || null, kind, amountCents,
    });
    if (earning) {
      markAttributionFirstPaid(user.id); // starts the window on the first paid invoice
      console.log(`[referrals] +${amountCents}c to ${owner.email} for ${user.email} (${kind})`);
    }
  } catch (e) {
    console.error('[referrals] accrual failed (credits unaffected):', e.message);
  }
}

// Clawback: a refunded charge reverses the commission that was accrued on it.
// Matches the refund to the earning via the implied gross (pack: 10%, sub: 25%)
// so we reverse the right earning, not just the newest one.
function handleChargeRefunded(obj, eventId) {
  try {
    const user = obj.customer ? getUserByStripeCustomer(obj.customer) : null;
    if (!user) return;
    const attr = getAttribution(user.id);
    if (!attr) return;
    const ref = getReferralByCode(attr.code);
    if (!ref) return;
    const refunded = Number(obj.amount_refunded) || 0;
    const charged = Number(obj.amount) || 0;
    if (refunded <= 0 || charged <= 0) return;
    for (const e of listUnpaidReferralEarnings(ref.owner_user_id, user.id)) {
      const rate = e.kind === 'pack' ? REFERRAL_PACK_RATE : REFERRAL_SUBSCRIPTION_RATE;
      const impliedGross = Math.round(e.amount_cents / rate);
      if (Math.abs(impliedGross - charged) <= 1) {
        const clawback = Math.min(e.amount_cents, Math.round(refunded * rate));
        if (clawback > 0) {
          addReferralEarning({
            ownerUserId: ref.owner_user_id, attributedUserId: user.id,
            stripeEventId: `clawback:${eventId}:${e.id}`, stripeObjectId: obj.id,
            kind: e.kind, amountCents: -clawback,
          });
          console.log(`[referrals] clawback -${clawback}c from ${ref.owner_user_id} (refund of ${charged}c)`);
        }
        break; // one reversal per refund event
      }
    }
  } catch (e) {
    console.error('[referrals] clawback failed:', e.message);
  }
}

// ---------- Stripe Connect (referral payouts) ----------
// NOTE: Stripe Connect must be enabled in the Stripe dashboard before these
// endpoints work against the real API. In STRIPE_MOCK=1 they return fakes.
export async function createConnectOnboardingLink({ user, baseUrl }) {
  requireBilling();
  const stripe = await getStripeClient();
  let accountId = user.stripe_connect_id;
  if (!accountId) {
    const account = await stripe.accounts.create({
      type: 'express',
      email: user.email,
      metadata: { userId: user.id },
      capabilities: { transfers: { requested: true } },
    });
    accountId = account.id;
    setStripeConnectId(user.id, accountId);
  }
  const link = await stripe.accountLinks.create({
    account: accountId,
    refresh_url: `${baseUrl}/?connect=refresh`,
    return_url: `${baseUrl}/?connect=done`,
    type: 'account_onboarding',
  });
  return { url: link.url, accountId };
}

export async function createPayoutTransfer({ user, amountCents, idempotencyKey }) {
  requireBilling();
  if (!user.stripe_connect_id)
    throw Object.assign(new Error('Connect a payout account first.'), { status: 400 });
  const stripe = await getStripeClient();
  return stripe.transfers.create({
    amount: Math.round(amountCents),
    currency: 'usd',
    destination: user.stripe_connect_id,
    metadata: { userId: user.id, kind: 'referral_payout' },
  }, idempotencyKey ? { idempotencyKey } : undefined);
}
