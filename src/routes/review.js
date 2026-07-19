'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const db = require('../db');
const config = require('../config');
const { requireAdmin, verifyCsrf } = require('../auth');
const moderation = require('../moderation');
const bans = require('../bans');
const audit = require('../audit');
const storage = require('../storage');
const notify = require('../notify');
const watermark = require('../watermark');

const router = express.Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadBytes, files: 1 } });

const pending = db.prepare(
  `SELECT i.*, u.username AS owner_name, u.email AS owner_email
   FROM images i JOIN users u ON u.id = i.owner_id
   WHERE i.deleted_at IS NULL AND i.moderation_status IN ('review', 'quarantined')
   ORDER BY i.created_at DESC`
);
const recentUploads = db.prepare(
  `SELECT i.*, u.username AS owner_name, u.email AS owner_email
   FROM images i JOIN users u ON u.id = i.owner_id
   WHERE i.deleted_at IS NULL
   ORDER BY i.created_at DESC LIMIT 100`
);
const getByToken = db.prepare('SELECT * FROM images WHERE token = ? AND deleted_at IS NULL');
const getOwner = db.prepare('SELECT username, email FROM users WHERE id = ?');
const setApproved = db.prepare("UPDATE images SET moderation_status = 'approved' WHERE id = ?");
const flagForReview = db.prepare(
  "UPDATE images SET moderation_status = 'review', moderation_reason = 'admin-manual', moderation_score = NULL WHERE id = ? AND deleted_at IS NULL"
);
const rejectImg = db.prepare("UPDATE images SET moderation_status = 'rejected', deleted_at = ? WHERE id = ?");
const setPhash = db.prepare('UPDATE images SET phash = ? WHERE id = ?');

function unlinkOriginal(img) {
  storage.remove(img).catch(() => {});
}

router.get('/admin/review', requireAdmin, (req, res) => {
  res.render('review', {
    me: req.user,
    items: pending.all(),
    recent: recentUploads.all(),
    blocklist: moderation.listBlockHashes(),
    holdOnReview: config.moderation.holdOnReview,
    nsfwEnabled: config.moderation.nsfw.enabled,
  });
});

// Allow an administrator to manually place any live upload into the review
// queue. This is separate from the automatic classifier and is reversible via
// the normal Allow/Deny review actions.
router.post('/admin/review/:token/flag', requireAdmin, verifyCsrf, (req, res) => {
  const img = getByToken.get(req.params.token);
  if (img) {
    flagForReview.run(img.id);
    audit.record(req.user, 'moderation_manual_flag', `${img.token} (owner #${img.owner_id})`);
    const owner = getOwner.get(img.owner_id);
    if (owner) {
      notify.notifyAdminFlag({
        username: owner.username,
        email: owner.email,
        token: img.token,
        title: img.title,
        reason: 'admin-manual',
        score: null,
      }).catch(() => {});
    }
  }
  res.redirect('/admin/review');
});

// Serve the original (un-watermarked) image to admins for review only.
// Sensitive by nature- restricted to admins, never cached.
router.get('/admin/review/:token/image', requireAdmin, async (req, res) => {
  const img = getByToken.get(req.params.token);
  if (!img) return res.status(404).end();
  if (!img.mime || !img.mime.startsWith('video/')) {
    try { await storage.send(res, img); } catch { res.status(404).end(); }
    return;
  }
  let materialized;
  const outputPath = path.join(config.tempDir, `admin-review-${img.token}-${Date.now()}.mp4`);
  try {
    materialized = await storage.materialize(img);
    await watermark.transcodeVideo(materialized.path, outputPath);
    await materialized.cleanup();
    materialized = null;
    res.setHeader('Content-Type', 'video/mp4');
    res.setHeader('Content-Disposition', `inline; filename="${img.token}.mp4"`);
    res.setHeader('Content-Length', String(fs.statSync(outputPath).size));
    res.setHeader('Cache-Control', 'no-store, private, max-age=0');
    const stream = fs.createReadStream(outputPath);
    const cleanup = () => fs.unlink(outputPath, () => {});
    stream.on('close', cleanup);
    stream.on('error', cleanup);
    stream.pipe(res);
  } catch {
    if (materialized) await materialized.cleanup();
    fs.unlink(outputPath, () => {});
    if (!res.headersSent) res.status(404).end();
  }
});

async function ensurePhash(img) {
  if (img.phash) return img.phash;
  let materialized;
  try {
    materialized = await storage.materialize(img);
    const h = await moderation.computePhash(materialized.path);
    setPhash.run(h, img.id);
    return h;
  } catch {
    return null;
  } finally {
    if (materialized) await materialized.cleanup();
  }
}

router.post('/admin/review/:token/allow', requireAdmin, verifyCsrf, (req, res) => {
  const img = getByToken.get(req.params.token);
  if (img) {
    setApproved.run(img.id);
    audit.record(req.user, 'moderation_allow', `${img.token} (owner #${img.owner_id})`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/deny', requireAdmin, verifyCsrf, (req, res) => {
  const img = getByToken.get(req.params.token);
  if (img) {
    rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    audit.record(req.user, 'moderation_deny', `${img.token} (owner #${img.owner_id})`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/blocklist', requireAdmin, verifyCsrf, async (req, res) => {
  const img = getByToken.get(req.params.token);
  if (img) {
    const h = await ensurePhash(img);
    if (h) moderation.addBlockHash(h, req.body.label || `review ${img.token}`, req.user.id);
    rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    audit.record(req.user, 'moderation_blocklist', `${img.token} phash ${h || 'n/a'}`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/blocklist-ban', requireAdmin, verifyCsrf, async (req, res) => {
  const img = getByToken.get(req.params.token);
  if (img) {
    const h = await ensurePhash(img);
    if (h) moderation.addBlockHash(h, req.body.label || `review ${img.token}`, req.user.id);
    rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    if (img.owner_id !== req.user.id) {
      bans.add({ kind: 'user', value: img.owner_id, block_account: 1, block_view: 1, reason: `content: ${img.token}`, created_by: req.user.id });
    }
    audit.record(req.user, 'moderation_blocklist_ban', `${img.token} phash ${h || 'n/a'} + banned owner #${img.owner_id}`);
  }
  res.redirect('/admin/review');
});

// Add an arbitrary image to the perceptual-hash blocklist (hash only; the
// uploaded image itself is not stored).
router.post('/admin/blocklist/add', requireAdmin, (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err || !req.file) return res.redirect('/admin/review');
    if (!req.body._csrf || !req.session || req.body._csrf !== req.session.csrf_token) {
      return res.status(403).render('error', { title: 'Forbidden', message: 'Invalid CSRF token.' });
    }
    try {
      const h = await moderation.computePhash(req.file.buffer);
      moderation.addBlockHash(h, (req.body.label || '').slice(0, 120) || 'manual', req.user.id);
      audit.record(req.user, 'blocklist_add', `phash ${h}`);
    } catch { /* ignore invalid image */ }
    res.redirect('/admin/review');
  });
});

router.post('/admin/blocklist/:id/delete', requireAdmin, verifyCsrf, (req, res) => {
  moderation.removeBlockHash(req.params.id);
  audit.record(req.user, 'blocklist_remove', `#${req.params.id}`);
  res.redirect('/admin/review');
});

module.exports = router;
