'use strict';

const db = require('./db');
const config = require('./config');
const phash = require('./util/phash');
const nsfw = require('./nsfw');

// --- perceptual-hash blocklist (self-managed) ------------------------------
const insertHash = db.prepare(
  'INSERT INTO phash_blocklist (phash, label, added_by, created_at) VALUES (?, ?, ?, ?)'
);
const allHashes = db.prepare('SELECT * FROM phash_blocklist ORDER BY created_at DESC');
const delHash = db.prepare('DELETE FROM phash_blocklist WHERE id = ?');

function addBlockHash(hash, label, addedBy) {
  insertHash.run(hash, label || null, addedBy || null, Date.now());
}
function listBlockHashes() {
  return allHashes.all();
}
function removeBlockHash(id) {
  delHash.run(id);
}

// Nearest blocklist entry within the configured threshold, or null. The
// blocklist can hold both hash formats: 64-hex PDQ entries (current) and
// 16-hex pHash entries. Each entry is compared against the
// matching hash for its format, with its format's threshold.
function blocklistMatch(hashes) {
  if (!hashes || (!hashes.pdq && !hashes.legacy)) return null;
  let best = null;
  for (const row of allHashes.all()) {
    const isPdq = typeof row.phash === 'string' && row.phash.length === 64;
    const candidate = isPdq ? hashes.pdq : hashes.legacy;
    const th = isPdq ? config.moderation.pdqThreshold : config.moderation.phashThreshold;
    const d = phash.hamming(candidate, row.phash);
    if (d <= th && (!best || d < best.distance)) best = { entry: row, distance: d };
  }
  return best;
}

// --- future known-CSAM hash providers (scaffolding, disabled) --------------
// Each returns { match: boolean, provider, detail } or null. All are no-ops
// until an operator obtains vetted access and enables + implements them.
async function providerKnownMatch(/* imagePath */) {
  const p = config.moderation.providers;
  if (p.cloudflare.enabled) {
    // TODO: Cloudflare CSAM Scanning Tool integration (requires CF + NCMEC setup).
  }
  if (p.photodna.enabled) {
    // TODO: Microsoft PhotoDNA match (requires vetted API access).
  }
  if (p.arachnid.enabled) {
    // TODO: Project Arachnid Shield match (requires registration).
  }
  return null;
}

/**
 * Scan an uploaded ORIGINAL image once. Returns:
 *   { status, reason, score, phash }
 * where status is one of: 'ok' | 'quarantined' | 'review'.
 * - 'quarantined': a precise match (blocklist or known-CSAM provider). Never
 *   served; awaits admin confirmation.
 * - 'review': a classifier suspicion. Routes to human review (held if
 *   holdOnReview); never an automatic account action.
 */
async function scan(imagePath) {
  if (!config.moderation.enabled) return { status: 'ok', reason: null, score: null, phash: null };

  let hash = null;
  let legacyHash = null;
  try {
    hash = await phash.compute(imagePath);
    legacyHash = await phash.computeLegacy(imagePath);
  } catch {
    hash = null;
  }

  // Tier A (precise): self-managed blocklist + provider known-hash match.
  const hit = blocklistMatch({ pdq: hash, legacy: legacyHash });
  if (hit) {
    return { status: 'quarantined', reason: `phash-blocklist (d=${hit.distance})`, score: null, phash: hash };
  }
  try {
    const prov = await providerKnownMatch(imagePath);
    if (prov && prov.match) {
      return { status: 'quarantined', reason: `known-hash:${prov.provider}`, score: null, phash: hash };
    }
  } catch { /* provider errors never block an upload */ }

  // Tier B (fuzzy): NSFW classifier -> human review only.
  if (config.moderation.nsfw.enabled) {
    const result = nsfw.classify ? await nsfw.classify(imagePath) : { score: await nsfw.score(imagePath), label: null };
    if ((!result || typeof result.score !== 'number') && config.moderation.nsfw.failClosed) {
      return { status: 'review', reason: 'nsfw-classifier:unavailable', score: null, details: null, phash: hash };
    }
    if (result && typeof result.score === 'number' && result.score >= config.moderation.nsfw.threshold) {
      const label = result.label ? `:${String(result.label).slice(0, 40)}` : '';
      return { status: 'review', reason: `nsfw-classifier${label}`, score: result.score, details: result.reports || null, phash: hash };
    }
  }

  return { status: 'ok', reason: null, score: null, phash: hash };
}

module.exports = {
  scan,
  addBlockHash,
  listBlockHashes,
  removeBlockHash,
  blocklistMatch,
  computePhash: phash.compute,
};
