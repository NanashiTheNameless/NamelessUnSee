'use strict';

const express = require('express');
const db = require('../db');
const config = require('../config');
const { requireAuth, verifyCsrf } = require('../auth');
const { limiters } = require('../ratelimit');
const { requireConsent, withScriptNonce } = require('../middleware');
const ipintel = require('../ipintel');
const { uuidv7 } = require('../util/crypto');

const router = express.Router();

// --- DB queries --------------------------------------------------------------
const listMine = db.prepare(
  `SELECT g.*, (SELECT COUNT(*) FROM gallery_items gi WHERE gi.gallery_id = g.id) AS item_count
   FROM galleries g
   WHERE g.owner_id = ? AND g.deleted_at IS NULL
   ORDER BY g.created_at DESC`
);

const getMineByToken = db.prepare(
  'SELECT * FROM galleries WHERE token = ? AND owner_id = ? AND deleted_at IS NULL'
);

const insertGallery = db.prepare(
  'INSERT INTO galleries (token, owner_id, title, created_at) VALUES (?, ?, ?, ?)'
);

const softDeleteGallery = db.prepare(
  'UPDATE galleries SET deleted_at = ? WHERE id = ? AND owner_id = ?'
);

const clearItems = db.prepare('DELETE FROM gallery_items WHERE gallery_id = ?');
const addItem = db.prepare(
  'INSERT OR IGNORE INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)'
);

const getGalleryLive = db.prepare('SELECT * FROM galleries WHERE token = ? AND deleted_at IS NULL');

const listGalleryItems = db.prepare(
  `SELECT i.*
   FROM gallery_items gi
   JOIN images i ON i.id = gi.image_id
   WHERE gi.gallery_id = ?
     AND i.deleted_at IS NULL
     AND (i.expires_at IS NULL OR i.expires_at >= ?)
   ORDER BY COALESCE(gi.position, 2147483647) ASC, gi.added_at ASC, i.created_at ASC`
);

// For building selection UIs.
const listMineImages = db.prepare(
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
router.get('/dashboard/galleries', requireAuth, (req, res) => {
  res.render('galleries', {
    me: req.user,
    galleries: listMine.all(req.user.id),
    images: listMineImages.all(req.user.id),
    baseUrl: config.baseUrl,
    created: req.query.created === '1',
  });
});

router.post('/dashboard/galleries', requireAuth, verifyCsrf, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 200) || null;
  const raw = req.body.images;
  const tokens = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const cleaned = [...new Set(tokens.map((t) => String(t)).filter((t) => /^[0-9a-f\-]{6,}$|^[A-Za-z0-9_-]{6,}$/.test(t)).slice(0, 50))];
  if (cleaned.length < 1) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'Select at least one image.' });
  }

  const placeholders = cleaned.map(() => '?').join(',');
  const stmt = db.prepare(getMineImagesByTokensSql.replace('%TOKENS%', placeholders));
  const rows = stmt.all(req.user.id, ...cleaned);
  if (!rows.length) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'No selected images were found.' });
  }

  const now = Date.now();
  const token = uuidv7(now);
  const info = insertGallery.run(token, req.user.id, title, now);
  const galleryId = info.lastInsertRowid;
  for (let i = 0; i < rows.length; i++) {
    addItem.run(galleryId, rows[i].id, i + 1, now);
  }
  res.redirect('/dashboard/galleries?created=1');
});

// --- Dashboard: edit items --------------------------------------------------
router.get('/dashboard/g/:token', requireAuth, (req, res) => {
  const g = getMineByToken.get(req.params.token, req.user.id);
  if (!g) return res.status(404).render('error', { title: 'Not found', message: 'No such gallery.' });
  const items = listGalleryItems.all(g.id, Date.now());
  const images = listMineImages.all(req.user.id);
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

router.post('/dashboard/g/:token', requireAuth, verifyCsrf, (req, res) => {
  const g = getMineByToken.get(req.params.token, req.user.id);
  if (!g) return res.status(404).render('error', { title: 'Not found', message: 'No such gallery.' });

  const raw = req.body.images;
  const tokens = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const cleaned = [...new Set(tokens.map((t) => String(t)).filter((t) => /^[A-Za-z0-9_-]{6,}$/.test(t)).slice(0, 50))];
  if (cleaned.length < 1) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'Select at least one image.' });
  }

  const placeholders = cleaned.map(() => '?').join(',');
  const stmt = db.prepare(getMineImagesByTokensSql.replace('%TOKENS%', placeholders));
  const rows = stmt.all(req.user.id, ...cleaned);
  if (!rows.length) {
    return res.status(400).render('error', { title: 'Invalid gallery', message: 'No selected images were found.' });
  }

  const now = Date.now();
  const tx = db.transaction(() => {
    clearItems.run(g.id);
    for (let i = 0; i < rows.length; i++) addItem.run(g.id, rows[i].id, i + 1, now);
  });
  tx();
  res.redirect(`/dashboard/g/${encodeURIComponent(g.token)}?saved=1`);
});

router.post('/dashboard/g/:token/delete', requireAuth, verifyCsrf, (req, res) => {
  const g = getMineByToken.get(req.params.token, req.user.id);
  if (g) softDeleteGallery.run(Date.now(), g.id, req.user.id);
  res.redirect('/dashboard/galleries');
});

// --- Public view ------------------------------------------------------------
router.get('/g/:token', limiters.view, requireConsent, withScriptNonce, async (req, res) => {
  const g = getGalleryLive.get(req.params.token);
  if (!g) return res.status(404).render('view-gone', { expired: false });

  const assessment = await ipintel.assess(req);
  if (!assessment.allowed) {
    res.status(403);
    return res.render('view-blocked', { reason: assessment.reason, message: blockMessage(assessment.reason) });
  }

  const items = listGalleryItems.all(g.id, Date.now()).filter(isViewable);
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

module.exports = router;
