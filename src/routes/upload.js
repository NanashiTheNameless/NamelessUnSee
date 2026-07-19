'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const db = require('../db');
const config = require('../config');
const { requireAuth, verifyCsrf } = require('../auth');
const { randomToken, uuidv7 } = require('../util/crypto');
const { limiters } = require('../ratelimit');
const watermark = require('../watermark');
const moderation = require('../moderation');
const storage = require('../storage');
const ranks = require('../ranks');
const notify = require('../notify');

const router = express.Router();

const ALLOWED_MIME = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/avif', 'video/mp4', 'video/webm', 'video/quicktime', 'video/ogg']);
const EXT = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif', 'image/avif': '.avif', 'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov', 'video/ogg': '.ogv' };

const multerStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, config.tempDir),
  filename: (req, file, cb) => cb(null, randomToken(20) + (EXT[file.mimetype] || '.bin')),
});
function uploadFor(user) {
  const options = {
    storage: multerStorage,
    limits: { files: 1 },
    fileFilter: (req, file, cb) => cb(null, ALLOWED_MIME.has(file.mimetype)),
  };
  if (!ranks.isOwner(user)) options.limits.fileSize = config.maxUploadBytesHard;
  return multer(options);
}

const insertImage = db.prepare(
  `INSERT INTO images
     (token, owner_id, storage_name, mime, width, height, byte_size, title, created_at,
     ttl_seconds, timer_start, max_views, expires_at,
      phash, moderation_status, moderation_reason, moderation_score, moderation_details, storage_backend, storage_encrypted)
   VALUES
     (@token, @owner_id, @storage_name, @mime, @width, @height, @byte_size, @title, @created_at,
      @ttl_seconds, @timer_start, @max_views, @expires_at,
      @phash, @moderation_status, @moderation_reason, @moderation_score, @moderation_details, @storage_backend, @storage_encrypted)`
);

// Allowed retention presets (label -> seconds; null = keep until views run out / manual delete).
const TTL_PRESETS = {
  '1h': 3600,
  '6h': 6 * 3600,
  '24h': 24 * 3600,
  '3d': 3 * 86400,
  '7d': 7 * 86400,
  '30d': 30 * 86400,
  never: null,
};
const listMine = db.prepare(
  `SELECT i.*, (SELECT COUNT(*) FROM access_logs a WHERE a.image_id = i.id) AS views
   FROM images i WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC`
);
const getMineByToken = db.prepare('SELECT * FROM images WHERE token = ? AND owner_id = ? AND deleted_at IS NULL');
const softDelete = db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?');
const getDefaults = db.prepare('SELECT default_ttl, default_timer_start, default_max_views, upload_max_bytes, storage_limit_bytes, rank FROM users WHERE id = ?');
const storageUsed = db.prepare('SELECT COALESCE(SUM(byte_size), 0) AS bytes FROM images WHERE owner_id = ? AND deleted_at IS NULL');

const LOGS_PAGE_SIZE = 50;
const countLogsAll = db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?');
const pageLogsAll = db.prepare(
  `SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
   FROM access_logs a WHERE a.image_id = ? ORDER BY a.viewed_at DESC LIMIT ? OFFSET ?`
);
const LOG_SEARCH_WHERE =
  '(ip LIKE @like OR ip_country LIKE @like OR user_agent LIKE @like OR geo_json LIKE @like OR client_json LIKE @like)';
const countLogsSearch = db.prepare(
  `SELECT COUNT(*) AS n FROM access_logs WHERE image_id = @image_id AND ${LOG_SEARCH_WHERE}`
);
const pageLogsSearch = db.prepare(
  `SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
   FROM access_logs a WHERE a.image_id = @image_id AND ${LOG_SEARCH_WHERE}
   ORDER BY a.viewed_at DESC LIMIT @limit OFFSET @offset`
);

router.get('/dashboard', requireAuth, (req, res) => {
  const defaults = getDefaults.get(req.user.id) || {};
  const effective = ranks.limits({ ...req.user, ...defaults });
  res.render('dashboard', {
    me: req.user,
    images: listMine.all(req.user.id),
    baseUrl: config.baseUrl,
    ttlHours: config.imageTtlHours,
    maxMb: Number.isFinite(effective.uploadBytes) ? Math.round(effective.uploadBytes / (1024 * 1024)) : null,
    storageUsed: storageUsed.get(req.user.id).bytes,
    storageLimit: effective.storageBytes,
    rank: req.user.rank,
    defaults,
    notice: req.query.uploaded ? 'Image uploaded.' : null,
    flagged: !!req.query.flagged,
  });
});

router.post('/upload', requireAuth, limiters.upload, (req, res) => {
  // multer must parse the multipart body before we can read the CSRF field.
  uploadFor(req.user).single('image')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? `File too large (max ${Math.round(config.maxUploadBytes / (1024 * 1024))} MB).`
        : 'Upload failed.';
      return res.status(400).render('error', { title: 'Upload error', message: msg });
    }
    // CSRF check (post-parse). Delete any uploaded file if it fails.
    if (!req.session || !req.body._csrf || req.body._csrf !== req.session.csrf_token) {
      if (req.file) fs.unlink(req.file.path || path.join(config.tempDir, req.file.filename), () => {});
      return res.status(403).render('error', { title: 'Forbidden', message: 'Invalid CSRF token. Please reload and try again.' });
    }
    if (!req.file) {
      return res.status(400).render('error', { title: 'Upload error', message: 'No media file provided (allowed: PNG, JPEG, WebP, GIF, AVIF, MP4, WebM, MOV, Ogg).' });
    }
    const filePath = req.file.path || path.join(config.tempDir, req.file.filename);
    if (req.file.buffer && !fs.existsSync(filePath)) {
      try {
        await fs.promises.writeFile(filePath, req.file.buffer, { mode: 0o600 });
      } catch {
        return res.status(500).render('error', { title: 'Upload error', message: 'The upload could not be staged.' });
      }
    }
    const limits = getDefaults.get(req.user.id) || {};
    const effective = ranks.limits({ ...req.user, ...limits });
    const uploadLimit = effective.uploadBytes;
    if (req.file.size > uploadLimit) {
      fs.unlink(filePath, () => {});
      return res.status(400).render('error', { title: 'Upload error', message: `File too large (your limit is ${Math.round(uploadLimit / (1024 * 1024))} MB).` });
    }
    const used = storageUsed.get(req.user.id).bytes;
    const storageLimit = effective.storageBytes;
    if (used + req.file.size > storageLimit) {
      fs.unlink(filePath, () => {});
      return res.status(400).render('error', { title: 'Upload error', message: `Storage limit reached. You have ${Math.max(0, Math.floor((storageLimit - used) / (1024 * 1024)))} MB remaining.` });
    }

    // Verify the bytes really are a decodable image or video; delete if not.
    let dims;
    try {
      dims = await watermark.probe(filePath);
      if (!dims.format) throw new Error('unrecognised media');
    } catch (error) {
      fs.unlink(filePath, () => {});
      return res.status(400).render('error', { title: 'Upload error', message: 'That file is not a valid image or video.' });
    }

    const now = Date.now();

    // Retention: duration preset and/or a maximum view count.
    const defaults = getDefaults.get(req.user.id) || { default_ttl: '24h', default_timer_start: 'first_view', default_max_views: null };
    const requestedTtl = req.body.ttl || defaults.default_ttl;
    const ttlKey = Object.prototype.hasOwnProperty.call(TTL_PRESETS, requestedTtl) ? requestedTtl : '24h';
    const ttlSeconds = TTL_PRESETS[ttlKey];
    const timerStart = (req.body.timer_start || defaults.default_timer_start) === 'upload' ? 'upload' : 'first_view';
    const requestedMaxViews = req.body.max_views === undefined || req.body.max_views === ''
      ? defaults.default_max_views
      : req.body.max_views;
    let maxViews = parseInt(requestedMaxViews, 10);
    maxViews = Number.isInteger(maxViews) && maxViews > 0 ? maxViews : null;

    // If the timer starts on upload, compute expiry now; otherwise it starts on
    // the first view (expires_at stays NULL until then).
    const expiresAt = timerStart === 'upload' && ttlSeconds ? now + ttlSeconds * 1000 : null;

    // Moderation scan of the original (perceptual-hash blocklist + optional NSFW
    // classifier). Precise matches quarantine; classifier hits go to review.
    let mod = { status: 'ok', reason: null, score: null, phash: null };
    if (ranks.shouldScan(req.user)) {
      try {
        mod = await moderation.scan(filePath);
      } catch (error) {
        // A scan failure must not lose the upload. When classifier fail-closed
        // mode is enabled, hold it for review instead of making it look clean.
        console.warn('[NamelessUnSee] moderation scan failed:', error.message);
        if (config.moderation.enabled && config.moderation.nsfw.enabled && config.moderation.nsfw.failClosed) {
          mod = { status: 'review', reason: 'moderation-scan:failed', score: null, details: null, phash: null };
        }
      }
    }

    const token = uuidv7(now);
    const mediaDir = dims.mediaType === 'video' ? 'Videos' : 'Images';
    const date = new Date(now);
    const datePart = [date.getMonth() + 1, date.getDate(), date.getFullYear()].map((v) => String(v).padStart(2, '0')).join('.');
    const storageName = `upload/${req.user.id}/${mediaDir}/${datePart}_${now}_${token}${EXT[req.file.mimetype] || '.bin'}`;
    let stored;
    try {
      stored = await storage.put(filePath, storageName);
    } catch {
      fs.unlink(filePath, () => {});
      return res.status(500).render('error', { title: 'Upload error', message: 'The image could not be stored.' });
    }
    fs.unlink(filePath, () => {});
    try {
      insertImage.run({
      token,
      owner_id: req.user.id,
      storage_name: stored.storage_name,
      mime: req.file.mimetype,
      width: dims.width,
      height: dims.height,
      byte_size: req.file.size,
      title: (req.body.title || '').slice(0, 200) || null,
      created_at: now,
      ttl_seconds: ttlSeconds,
      timer_start: timerStart,
      max_views: maxViews,
      expires_at: expiresAt,
      phash: mod.phash,
      moderation_status: mod.status,
      moderation_reason: mod.reason,
      moderation_score: mod.score,
      moderation_details: mod.details ? JSON.stringify(mod.details) : null,
      storage_backend: stored.storage_backend,
      storage_encrypted: stored.storage_encrypted,
      });
    } catch (error) {
      await storage.remove(stored).catch(() => {});
      return res.status(500).render('error', { title: 'Upload error', message: 'The image could not be stored.' });
    }

    if (mod.status !== 'ok') {
      notify.notifyAdminFlag({
        username: req.user.username,
        email: req.user.email,
        token,
        title: (req.body.title || '').slice(0, 200) || null,
        reason: mod.reason,
        score: mod.score,
        reports: mod.details,
      }).catch(() => {});
    }

    const flagged = mod.status !== 'ok';
    res.redirect('/dashboard?uploaded=1' + (flagged ? '&flagged=1' : ''));
  });
});

router.get('/dashboard/i/:token/logs', requireAuth, (req, res) => {
  const img = getMineByToken.get(req.params.token, req.user.id);
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });

  const q = (req.query.q || '').toString().trim().slice(0, 100);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const offset = (page - 1) * LOGS_PAGE_SIZE;

  let total;
  let rows;
  if (q) {
    const like = '%' + q + '%';
    total = countLogsSearch.get({ image_id: img.id, like }).n;
    rows = pageLogsSearch.all({ image_id: img.id, like, limit: LOGS_PAGE_SIZE, offset });
  } else {
    total = countLogsAll.get(img.id).n;
    rows = pageLogsAll.all(img.id, LOGS_PAGE_SIZE, offset);
  }

  const logs = rows.map((r) => ({
    ...r,
    device: safeParse(r.device_json),
    geo: safeParse(r.geo_json),
    headers: safeParse(r.headers_json),
    client: safeParse(r.client_json),
  }));

  res.render('logs', {
    me: req.user,
    image: img,
    logs,
    baseUrl: config.baseUrl,
    q,
    page,
    pageSize: LOGS_PAGE_SIZE,
    total,
    totalPages: Math.max(1, Math.ceil(total / LOGS_PAGE_SIZE)),
    reported: req.query.reported === '1',
  });
});

// --- per-recipient view links ----------------------------------------------
const listLinks = db.prepare('SELECT * FROM view_links WHERE image_id = ? ORDER BY created_at DESC');
const insertLink = db.prepare(
  'INSERT INTO view_links (image_id, token, label, max_uses, created_at) VALUES (?, ?, ?, ?, ?)'
);
const revokeLink = db.prepare('UPDATE view_links SET revoked_at = ? WHERE id = ? AND image_id = ?');

router.get('/dashboard/i/:token/links', requireAuth, (req, res) => {
  const img = getMineByToken.get(req.params.token, req.user.id);
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });
  res.render('links', {
    me: req.user,
    image: img,
    links: listLinks.all(img.id),
    baseUrl: config.baseUrl,
    created: req.query.created === '1',
  });
});

router.post('/dashboard/i/:token/links', requireAuth, verifyCsrf, (req, res) => {
  const img = getMineByToken.get(req.params.token, req.user.id);
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });
  const label = String(req.body.label || '').trim().slice(0, 80) || null;
  const rawMax = String(req.body.max_uses || '').trim();
  let maxUses = rawMax ? parseInt(rawMax, 10) : null;
  maxUses = Number.isInteger(maxUses) && maxUses > 0 ? maxUses : null;
  if (req.body.one_time === 'on') maxUses = 1;
  insertLink.run(img.id, randomToken(20), label, maxUses, Date.now());
  res.redirect(`/dashboard/i/${encodeURIComponent(img.token)}/links?created=1`);
});

router.post('/dashboard/i/:token/links/:id/revoke', requireAuth, verifyCsrf, (req, res) => {
  const img = getMineByToken.get(req.params.token, req.user.id);
  if (img) revokeLink.run(Date.now(), parseInt(req.params.id, 10) || 0, img.id);
  res.redirect(`/dashboard/i/${encodeURIComponent(req.params.token)}/links`);
});

router.post('/dashboard/i/:token/delete', requireAuth, verifyCsrf, (req, res) => {
  const img = getMineByToken.get(req.params.token, req.user.id);
  if (img) {
    softDelete.run(Date.now(), img.id);
    storage.remove(img).catch(() => {});
  }
  res.redirect('/dashboard');
});

function safeParse(s) {
  try {
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

module.exports = router;
