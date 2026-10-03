// Minimal Replicate client (no SDK) plus automatic input mapping.
// Each model publishes an OpenAPI schema for its inputs. We read it once, then map our
// generic fields (style, lyrics, duration, seed, instrumental) onto whatever names that
// model uses, clamped to its allowed ranges.

const API = (process.env.REPLICATE_API_BASE || 'https://api.replicate.com/v1').replace(/\/$/, '');
const SCHEMA_TTL_MS = 60 * 60 * 1000;
const schemaCache = new Map(); // model -> { at, info }

function token() {
  const t = process.env.REPLICATE_API_TOKEN;
  if (!t) throw new Error('REPLICATE_API_TOKEN is not set. Add it to your environment (see .env.example).');
  return t;
}

async function call(path, { method = 'GET', body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Authorization: `Bearer ${token()}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text }; }
  if (!res.ok) {
    const msg = data.detail || data.title || data.error || text || res.statusText;
    const err = new Error(`Replicate ${res.status}: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// Returns { versionId|null, props, required } for a model, cached for an hour.
export async function getModelInfo(model) {
  const hit = schemaCache.get(model);
  if (hit && Date.now() - hit.at < SCHEMA_TTL_MS) return hit.info;
  const m = await call(`/models/${model}`);
  const lv = m.latest_version || null;
  const input = lv?.openapi_schema?.components?.schemas?.Input || {};
  const info = {
    versionId: lv?.id || null,
    props: input.properties || {},
    required: input.required || [],
    description: m.description || '',
  };
  schemaCache.set(model, { at: Date.now(), info });
  return info;
}

const CANDIDATES = {
  style: ['tags', 'prompt', 'style', 'caption', 'music_description', 'description', 'text'],
  lyrics: ['lyrics', 'lyric', 'song_lyrics'],
  duration: ['duration', 'audio_duration', 'duration_seconds', 'seconds', 'length', 'music_length_ms'],
  seed: ['seed', 'manual_seed'],
  instrumental: ['instrumental', 'force_instrumental', 'is_instrumental', 'make_instrumental'],
  format: ['output_format', 'format', 'audio_format'],
};

const findKey = (props, names) => names.find((n) => Object.prototype.hasOwnProperty.call(props, n));

function fitNumber(schema, value) {
  let v = Number(value);
  if (schema?.minimum != null) v = Math.max(schema.minimum, v);
  if (schema?.maximum != null) v = Math.min(schema.maximum, v);
  if (schema?.type === 'integer') v = Math.round(v);
  return v;
}

// Builds the input object for a model. Throws with a clear message if the model
// needs something we cannot supply.
export function buildInput(info, provider, req) {
  const { props, required } = info;
  const input = {};
  const used = new Set();
  const notes = [];

  const styleKey = findKey(props, CANDIDATES.style);
  const lyricsKey = findKey(props, CANDIDATES.lyrics);
  const durKey = findKey(props, CANDIDATES.duration);
  const seedKey = findKey(props, CANDIDATES.seed);
  const instKey = findKey(props, CANDIDATES.instrumental);
  const fmtKey = findKey(props, CANDIDATES.format);

  const lyrics = (req.lyrics || '').trim();
  const instrumental = req.instrumental || !lyrics;

  if (styleKey) {
    input[styleKey] = req.style || 'catchy song';
    used.add(styleKey);
  }

  if (lyricsKey) {
    if (!instrumental) input[lyricsKey] = lyrics;
    else if (provider.instrumentalLyrics) input[lyricsKey] = provider.instrumentalLyrics;
    if (input[lyricsKey] !== undefined) used.add(lyricsKey);
  } else if (lyrics && !instrumental) {
    notes.push('This model makes instrumentals only, so your lyrics were not used.');
  }

  if (instKey && props[instKey].type === 'boolean') { input[instKey] = !!instrumental; used.add(instKey); }

  if (durKey && req.duration) {
    const ms = durKey.endsWith('_ms');
    input[durKey] = fitNumber(props[durKey], ms ? req.duration * 1000 : req.duration);
    used.add(durKey);
  }

  if (seedKey && Number.isFinite(req.seed) && ['integer', 'number'].includes(props[seedKey].type)) {
    input[seedKey] = fitNumber(props[seedKey], req.seed);
    used.add(seedKey);
  }

  if (fmtKey && Array.isArray(props[fmtKey].enum) && props[fmtKey].enum.includes('mp3')) {
    input[fmtKey] = 'mp3';
    used.add(fmtKey);
  }

  Object.assign(input, provider.extra || {});
  for (const k of Object.keys(provider.extra || {})) used.add(k);

  const missing = required.filter((k) => !used.has(k) && props[k]?.default === undefined);
  if (missing.length) {
    throw new Error(
      `${provider.label} requires input(s) this app does not fill: ${missing.join(', ')}. ` +
      `Set them under "extra" for this model in lib/providers.mjs, or pick another model.`
    );
  }
  // What the model will actually use, so the library shows real values.
  const applied = {
    duration: durKey ? (durKey.endsWith('_ms') ? input[durKey] / 1000 : input[durKey]) : null,
    seed: seedKey && input[seedKey] !== undefined ? input[seedKey] : null,
  };
  return { input, notes, applied };
}

export async function createPrediction(provider, input) {
  const info = await getModelInfo(provider.model);
  // Community models run by version id; official models run through the model endpoint.
  if (info.versionId) return call('/predictions', { method: 'POST', body: { version: info.versionId, input } });
  return call(`/models/${provider.model}/predictions`, { method: 'POST', body: { input } });
}

export const getPrediction = (id) => call(`/predictions/${encodeURIComponent(id)}`);

export async function cancelPrediction(id) {
  try { await call(`/predictions/${encodeURIComponent(id)}/cancel`, { method: 'POST' }); } catch { /* already done */ }
}

// Output shapes vary: a URL string, an array of URLs, or an object holding one.
export function pickAudioUrl(output) {
  const urls = [];
  const walk = (v) => {
    if (!v) return;
    if (typeof v === 'string') { if (/^https?:\/\//.test(v)) urls.push(v); return; }
    if (Array.isArray(v)) return v.forEach(walk);
    if (typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(output);
  return urls.find((u) => /\.(mp3|wav|flac|ogg|m4a|aac)(\?|$)/i.test(u)) || urls[0] || null;
}

// ---------- Studio Mixer: stem separation ----------
// Builds the input for a separation model (e.g. ryan5453/demucs) from its
// published schema: the mixed audio goes in as a base64 data URI (the app's
// audio URLs are login-walled, so a public URL is not an option), plus the
// model variant and output format when the schema offers them.
export function buildSeparationInput(info, { audioDataUri, modelName }) {
  const { props, required } = info;
  const input = {};
  const used = new Set();

  const audioKey = findKey(props, ['audio', 'input_audio', 'audio_file', 'music', 'song', 'track', 'file']);
  if (!audioKey) throw new Error('This separation model has no audio file input this app can fill.');
  input[audioKey] = audioDataUri; used.add(audioKey);

  const variantKey = findKey(props, ['model_name', 'model', 'separation_model', 'variant']);
  if (variantKey && Array.isArray(props[variantKey].enum)) {
    input[variantKey] = props[variantKey].enum.includes(modelName) ? modelName : props[variantKey].enum[0];
    used.add(variantKey);
  } else if (variantKey && typeof props[variantKey].default === 'string') {
    input[variantKey] = props[variantKey].default; used.add(variantKey);
  }

  const fmtKey = findKey(props, ['output_format', 'format', 'audio_format']);
  if (fmtKey && Array.isArray(props[fmtKey].enum)) {
    input[fmtKey] = props[fmtKey].enum.includes('mp3') ? 'mp3' : props[fmtKey].enum[0];
    used.add(fmtKey);
  }

  const missing = required.filter((k) => !used.has(k) && props[k]?.default === undefined);
  if (missing.length) {
    throw new Error(`The separation model requires input(s) this app does not fill: ${missing.join(', ')}.`);
  }
  return input;
}

// Pulls named stem URLs out of a separation prediction's output. Demucs-style
// models return an object like {vocals, drums, bass, other}; this tolerates
// nesting, casing differences, and 'accompaniment' standing in for 'other'.
export function pickStemUrls(output, names = ['vocals', 'drums', 'bass', 'other']) {
  const found = {};
  const ALIASES = { accompaniment: 'other', instrumental: 'other' };
  const walk = (v) => {
    if (!v) return;
    if (typeof v === 'string') return; // bare URLs carry no stem name; skip
    if (Array.isArray(v)) return v.forEach(walk);
    if (typeof v === 'object') {
      for (const [k, val] of Object.entries(v)) {
        const norm = ALIASES[String(k).toLowerCase()] || String(k).toLowerCase();
        if (names.includes(norm) && typeof val === 'string' && /^https?:\/\//.test(val) && !found[norm]) {
          found[norm] = val;
        } else walk(val);
      }
    }
  };
  walk(output);
  return Object.fromEntries(names.map((n) => [n, found[n] || null]));
}
