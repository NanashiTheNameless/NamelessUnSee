'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const { getDatabase } = require('../db-runtime');
const config = require('../config');
const { requireAdmin, verifyCsrf } = require('../auth');
const moderation = require('../moderation');
const bans = require('../bans');
const audit = require('../audit');
const storage = require('../storage');
const notify = require('../notify');
const watermark = require('../watermark');
const { limiters } = require('../ratelimit');

const router = express.Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadBytes, files: 1 } });

const statement = (sql) => ({
  get: (...args) => getDatabase().then((db) => db.prepare(sql).get(...args)),
  all: (...args) => getDatabase().then((db) => db.prepare(sql).all(...args)),
  run: (...args) => getDatabase().then((db) => db.prepare(sql).run(...args)),
});
const pending = statement(
  `SELECT i.*, u.username AS owner_name, u.email AS owner_email
   FROM images i JOIN users u ON u.id = i.owner_id
   WHERE i.deleted_at IS NULL AND i.moderation_status IN ('review', 'quarantined')
   ORDER BY i.created_at DESC`
);
const recentUploads = statement(
  `SELECT i.*, u.username AS owner_name, u.email AS owner_email
   FROM images i JOIN users u ON u.id = i.owner_id
   WHERE i.deleted_at IS NULL
   ORDER BY i.created_at DESC LIMIT 100`
);
const getByToken = statement('SELECT * FROM images WHERE token = ? AND deleted_at IS NULL');
const getOwner = statement('SELECT username, email FROM users WHERE id = ?');
const setApproved = statement("UPDATE images SET moderation_status = 'approved' WHERE id = ?");
const flagForReview = statement(
  "UPDATE images SET moderation_status = 'review', moderation_reason = 'admin-manual', moderation_score = NULL WHERE id = ? AND deleted_at IS NULL"
);
const rejectImg = statement("UPDATE images SET moderation_status = 'rejected', deleted_at = ? WHERE id = ?");
const setPhash = statement('UPDATE images SET phash = ? WHERE id = ?');

function unlinkOriginal(img) {
  storage.remove(img).catch(() => {});
}

router.get('/admin/review', requireAdmin, async (req, res) => {
  res.render('review', {
    me: req.user,
    items: await pending.all(),
    recent: await recentUploads.all(),
    blocklist: await moderation.listBlockHashes(),
    holdOnReview: config.moderation.holdOnReview,
    nsfwEnabled: config.moderation.nsfw.enabled,
  });
});

// Allow an administrator to manually place any live upload into the review
// queue. This is separate from the automatic classifier and is reversible via
// the normal Allow/Deny review actions.
router.post('/admin/review/:token/flag', requireAdmin, verifyCsrf, async (req, res) => {
  const img = await getByToken.get(req.params.token);
  if (img) {
    await flagForReview.run(img.id);
    await audit.record(req.user, 'moderation_manual_flag', `${img.token} (owner #${img.owner_id})`);
    const owner = await getOwner.get(img.owner_id);
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
router.get('/admin/review/:token/image', limiters.admin, requireAdmin, async (req, res) => {
  const img = await getByToken.get(req.params.token);
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
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'no-store, private, max-age=0');
    const size = fs.statSync(outputPath).size;
    const range = req.headers.range;
    let stream;
    if (range) {
      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      const start = match && match[1] !== '' ? Number(match[1]) : 0;
      const end = match && match[2] !== '' ? Number(match[2]) : size - 1;
      if (!match || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || start >= size) {
        res.status(416).setHeader('Content-Range', `bytes */${size}`).end();
        fs.unlink(outputPath, () => {});
        return;
      }
      const boundedEnd = Math.min(end, size - 1);
      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${boundedEnd}/${size}`);
      res.setHeader('Content-Length', String(boundedEnd - start + 1));
      stream = fs.createReadStream(outputPath, { start, end: boundedEnd });
    } else {
      stream = fs.createReadStream(outputPath);
    }
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
    await setPhash.run(h, img.id);
    return h;
  } catch {
    return null;
  } finally {
    if (materialized) await materialized.cleanup();
  }
}

router.post('/admin/review/:token/allow', requireAdmin, verifyCsrf, async (req, res) => {
  const img = await getByToken.get(req.params.token);
  if (img) {
    await setApproved.run(img.id);
    await audit.record(req.user, 'moderation_allow', `${img.token} (owner #${img.owner_id})`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/deny', requireAdmin, verifyCsrf, async (req, res) => {
  const img = await getByToken.get(req.params.token);
  if (img) {
    await rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    await audit.record(req.user, 'moderation_deny', `${img.token} (owner #${img.owner_id})`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/blocklist', requireAdmin, verifyCsrf, async (req, res) => {
  const img = await getByToken.get(req.params.token);
  if (img) {
    const h = await ensurePhash(img);
    if (h) await moderation.addBlockHash(h, req.body.label || `review ${img.token}`, req.user.id);
    await rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    await audit.record(req.user, 'moderation_blocklist', `${img.token} phash ${h || 'n/a'}`);
  }
  res.redirect('/admin/review');
});

router.post('/admin/review/:token/blocklist-ban', requireAdmin, verifyCsrf, async (req, res) => {
  const img = await getByToken.get(req.params.token);
  if (img) {
    const h = await ensurePhash(img);
    if (h) await moderation.addBlockHash(h, req.body.label || `review ${img.token}`, req.user.id);
    await rejectImg.run(Date.now(), img.id);
    unlinkOriginal(img);
    if (img.owner_id !== req.user.id) {
      await bans.add({ kind: 'user', value: img.owner_id, block_account: 1, block_view: 1, reason: `content: ${img.token}`, created_by: req.user.id });
    }
    await audit.record(req.user, 'moderation_blocklist_ban', `${img.token} phash ${h || 'n/a'} + banned owner #${img.owner_id}`);
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
      await moderation.addBlockHash(h, (req.body.label || '').slice(0, 120) || 'manual', req.user.id);
      await audit.record(req.user, 'blocklist_add', `phash ${h}`);
    } catch { /* ignore invalid image */ }
    res.redirect('/admin/review');
  });
});

router.post('/admin/blocklist/:id/delete', requireAdmin, verifyCsrf, async (req, res) => {
  await moderation.removeBlockHash(req.params.id);
  await audit.record(req.user, 'blocklist_remove', `#${req.params.id}`);
  res.redirect('/admin/review');
});

module.exports = router;
