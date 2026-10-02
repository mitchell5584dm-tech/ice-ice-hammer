// Music models the app can call on Replicate.
// `model` is the Replicate "owner/name". Input names are discovered from each model's
// published schema at runtime (see lib/replicate.mjs), so you normally only edit this list
// to add, remove, or reorder models. `extra` lets you force specific inputs for a model.

export const PROVIDERS = [
  {
    id: 'ace-step',
    label: 'ACE-Step',
    blurb: 'Full songs with vocals from tags + lyrics. Open-source, fast, cheapest.',
    model: 'lucataco/ace-step',
    vocals: true,
    // ACE-Step convention for "no vocals": pass this as the lyrics.
    instrumentalLyrics: '[instrumental]',
    extra: {},
  },
  {
    id: 'minimax-2.5',
    label: 'MiniMax Music 2.5',
    blurb: 'Most natural singing. Higher cost per song.',
    model: 'minimax/music-2.5',
    vocals: true,
    extra: {},
  },
  {
    id: 'elevenlabs',
    label: 'ElevenLabs Music',
    blurb: 'Studio-style production, vocal or instrumental.',
    model: 'elevenlabs/music',
    vocals: true,
    extra: {},
  },
  {
    id: 'musicgen',
    label: 'MusicGen',
    blurb: 'Instrumental only. Good for beats and loops.',
    model: 'meta/musicgen',
    vocals: false,
    extra: {},
  },
  {
    id: 'stable-audio',
    label: 'Stable Audio 2.5',
    blurb: 'Instrumental only, up to about 3 minutes.',
    model: 'stability-ai/stable-audio-2.5',
    vocals: false,
    extra: {},
  },
];

export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id) || null;
}
