'use strict';

const express = require('express');
const { getDatabase } = require('../db-runtime');
const config = require('../config');
const { requireAuth, verifyCsrf } = require('../auth');
const { limiters } = require('../ratelimit');
const { requireConsent, withScriptNonce } = require('../middleware');
const ipintel = require('../ipintel');
const logging = require('../logging');
const clientTelemetry = require('../util/client-telemetry');
const { uuidv7 } = require('../util/crypto');

const router = express.Router();

// Upper bound on blocked-attempt rows written for a single refused gallery hit:
// the block path is reachable by anyone holding the gallery token, so the
// fan-out across a large gallery has to stay small. Only the first row carries
// the captured headers.
const BLOCKED_LOG_CAP = 10;

// --- DB queries --------------------------------------------------------------
const statement = (sql) => ({
  get: (...args) => getDatabase().then((db) => db.prepare(sql).get(...args)),
  all: (...args) => getDatabase().then((db) => db.prepare(sql).all(...args)),
  run: (...args) => getDatabase().then((db) => db.prepare(sql).run(...args)),
});
const listMine = statement(
  `SELECT g.*, (SELECT COUNT(*) FROM gallery_items gi WHERE gi.gallery_id = g.id) AS item_count
   FROM galleries g
   WHERE g.owner_id = ? AND g.deleted_at IS NULL
   ORDER BY g.created_at DESC`
);

const getMineByToken = statement(
  'SELECT * FROM galleries WHERE token = ? AND owner_id = ? AND deleted_at IS NULL'
);

const insertGallery = statement(
  'INSERT INTO galleries (token, owner_id, title, created_at) VALUES (?, ?, ?, ?)'
);

const softDeleteGallery = statement(
  'UPDATE galleries SET deleted_at = ? WHERE id = ? AND owner_id = ?'
);

const clearItems = statement('DELETE FROM gallery_items WHERE gallery_id = ?');
const addItem = statement(
  'INSERT OR IGNORE INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)'
);

const getGalleryLive = statement('SELECT * FROM galleries WHERE token = ? AND deleted_at IS NULL');

const listGalleryItems = statement(
  `SELECT i.*
   FROM gallery_items gi
   JOIN images i ON i.id = gi.image_id
   WHERE gi.gallery_id = ?
     AND i.deleted_at IS NULL
     AND (i.expires_at IS NULL OR i.expires_at >= ?)
   ORDER BY COALESCE(gi.position, 2147483647) ASC, gi.added_at ASC, i.created_at ASC`
);

// For building selection UIs.
const listMineImages = statement(
  'SELECT id, token, title, mime, width, height, created_at FROM images WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC'
);
const getMineImagesByTokensSql =
  `SELECT id, token FROM images
   WHERE owner_id = ? AND deleted_at IS NULL
     AND token IN (%TOKENS%)`;

function blockMessage(reason) {
  switch (reason) {
    case 'no-public-ip':
      return 'We could not determine your public network address, so this content cannot be shown.';
    case 'proxy':
      return 'Access through VPNs, proxies, Tor or other anonymising networks is not permitted for this content.';
    case 'intel-unavailable':
      return 'We could not verify your connection right now. Because this content is only shown to fully identifiable viewers, access is blocked. Please try again later.';
    default:
      return 'Access to this content is not permitted from your connection.';
  }
}

function isViewable(img) {
  const s = img.moderation_status;
  if (s === 'ok' || s === 'approved') return true;
  if (s === 'review' && !config.moderation.holdOnReview) return true;
  return false;
}

// --- Dashboard: list + create ----------------------------------------------
router.get('/dashboard/galleries', requireAuth, async (req, res) => {
  res.render('galleries', {
    me: req.user,
    galleries: await listMine.all(req.user.id),
    images: await listMineImages.all(req.user.id),
    baseUrl: config.baseUrl,
    created: req.query.created === '1',
  });
});

router.post('/dashboard/galleries', requireAuth, verifyCsrf, async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 200) || null;
  const raw = req.body.images;
  const tokens = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const cleaned = [...new Set(tokens.map((t) => String(t)).filter((t) => /^[0-9a-f\-]{6,}$|^[A-Za-z0-9_-]{6,}$/.test(t)).slice(0, 50))];
  if (cleaned.length < 1) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'Select at least one image.' });
  }

  const placeholders = cleaned.map(() => '?').join(',');
  const rows = await statement(getMineImagesByTokensSql.replace('%TOKENS%', placeholders)).all(req.user.id, ...cleaned);
  if (!rows.length) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'No selected images were found.' });
  }

  const now = Date.now();
  const token = uuidv7(now);
  const info = await insertGallery.run(token, req.user.id, title, now);
  const galleryId = info.lastInsertRowid;
  for (let i = 0; i < rows.length; i++) {
    await addItem.run(galleryId, rows[i].id, i + 1, now);
  }
  res.redirect('/dashboard/galleries?created=1');
});

// --- Dashboard: edit items --------------------------------------------------
router.get('/dashboard/g/:token', requireAuth, async (req, res) => {
  const g = await getMineByToken.get(req.params.token, req.user.id);
  if (!g) return res.status(404).render('error', { title: 'Not found', message: 'No such gallery.' });
  const items = await listGalleryItems.all(g.id, Date.now());
  const images = await listMineImages.all(req.user.id);
  const selected = new Set(items.map((i) => i.id));
  res.render('gallery-edit', {
    me: req.user,
    gallery: g,
    items,
    images,
    selected,
    baseUrl: config.baseUrl,
    saved: req.query.saved === '1',
  });
});

router.post('/dashboard/g/:token', requireAuth, verifyCsrf, async (req, res) => {
  const g = await getMineByToken.get(req.params.token, req.user.id);
  if (!g) return res.status(404).render('error', { title: 'Not found', message: 'No such gallery.' });

  const raw = req.body.images;
  const tokens = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const cleaned = [...new Set(tokens.map((t) => String(t)).filter((t) => /^[A-Za-z0-9_-]{6,}$/.test(t)).slice(0, 50))];
  if (cleaned.length < 1) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'Select at least one image.' });
  }

  const placeholders = cleaned.map(() => '?').join(',');
  const rows = await statement(getMineImagesByTokensSql.replace('%TOKENS%', placeholders)).all(req.user.id, ...cleaned);
  if (!rows.length) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'No selected images were found.' });
  }

  const now = Date.now();
  const db = await getDatabase();
  await db.batch([
    { sql: 'DELETE FROM gallery_items WHERE gallery_id = ?', args: [g.id] },
    ...rows.map((row, i) => ({ sql: 'INSERT OR IGNORE INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)', args: [g.id, row.id, i + 1, now] })),
  ]);
  res.redirect(`/dashboard/g/${encodeURIComponent(g.token)}?saved=1`);
});

router.post('/dashboard/g/:token/delete', requireAuth, verifyCsrf, async (req, res) => {
  const g = await getMineByToken.get(req.params.token, req.user.id);
  if (g) await softDeleteGallery.run(Date.now(), g.id, req.user.id);
  res.redirect('/dashboard/galleries');
});

// --- Public view ------------------------------------------------------------
router.get('/g/:token', limiters.view, requireConsent, withScriptNonce, async (req, res) => {
  const g = await getGalleryLive.get(req.params.token);
  if (!g) return res.status(404).render('view-gone', { expired: false });

  const items = (await listGalleryItems.all(g.id, Date.now())).filter(isViewable);

  const assessment = await ipintel.assess(req);
  if (!assessment.allowed) {
    // A gallery link grants access to every image in it, so a refused attempt
    // belongs in each image's own access log (bounded, and deduped per IP).
    for (const [i, item] of items.slice(0, BLOCKED_LOG_CAP).entries()) {
      try {
        await logging.logBlocked(req, item.id, assessment, `gallery ${g.token}`, { withHeaders: i === 0 });
      } catch { /* non-fatal */ }
    }
    res.status(403);
    return res.render('view-blocked', {
      reason: assessment.reason,
      message: blockMessage(assessment.reason),
      telemetryPath: `/g/${encodeURIComponent(g.token)}/telemetry`,
      nonce: res.locals.nonce,
    });
  }

  if (!items.length) return res.status(404).render('view-gone', { expired: false });

  res.setHeader('Cache-Control', 'no-store');
  res.render('gallery-view', {
    gallery: g,
    items: items.map((i) => ({
      token: i.token,
      title: i.title,
      width: i.width,
      height: i.height,
      mediaType: i.mime && i.mime.startsWith('video/') ? 'video' : 'image',
    })),
    nonce: res.locals.nonce,
  });
});

// Beacon from the blocked gallery page. Only refused viewers ever reach it: an
// allowed viewer is redirected into the per-image view flow, which has its own
// beacon. The details merge into the refused-attempt rows the block wrote.
router.post('/g/:token/telemetry', limiters.telemetry, requireConsent, async (req, res) => {
  const g = await getGalleryLive.get(req.params.token);
  if (!g) return res.status(204).end();

  const assessment = await ipintel.assess(req);
  if (assessment.allowed) return res.status(204).end();

  const client = clientTelemetry.sanitize(req.body && req.body.client);
  const items = (await listGalleryItems.all(g.id, Date.now())).filter(isViewable);
  for (const [i, item] of items.slice(0, BLOCKED_LOG_CAP).entries()) {
    try {
      await logging.logBlocked(req, item.id, assessment, `gallery ${g.token}`, { withHeaders: i === 0, client });
    } catch { /* non-fatal */ }
  }
  res.status(204).end();
});

module.exports = router;
