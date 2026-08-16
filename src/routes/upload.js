'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const { getDatabase } = require('../db-runtime');
const config = require('../config');
const { requireAuth, verifyCsrf } = require('../auth');
const { randomToken, uuidv7 } = require('../util/crypto');
const { limiters } = require('../ratelimit');
const watermark = require('../watermark');
const moderation = require('../moderation');
const storage = require('../storage');
const accessLog = require('../access-log');
const ranks = require('../ranks');
const notify = require('../notify');
const { beneath } = require('../util/safe-path');
const { verifySolution } = require('../altcha');
const chunked = require('../chunked-upload');

const router = express.Router();

function stagedPath(file) {
  if (!file || typeof file.filename !== 'string') throw new Error('invalid staged file');
  return beneath(config.tempDir, file.filename);
}

const ALLOWED_MIME = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/avif', 'video/mp4', 'video/webm', 'video/quicktime', 'video/ogg']);
const EXT = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif', 'image/avif': '.avif', 'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov', 'video/ogg': '.ogv' };

const multerStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, config.tempDir),
  filename: (req, file, cb) => cb(null, randomToken(20) + (EXT[file.mimetype] || '.bin')),
});
function uploadFor(user) {
  const options = {
    storage: multerStorage,
    limits: { files: 50 },
    fileFilter: (req, file, cb) => cb(null, ALLOWED_MIME.has(file.mimetype)),
  };
  if (!ranks.isOwner(user)) options.limits.fileSize = config.maxUploadBytesHard;
  return multer(options);
}

const statement = (sql) => ({
  get: (...args) => getDatabase().then((db) => db.prepare(sql).get(...args)),
  all: (...args) => getDatabase().then((db) => db.prepare(sql).all(...args)),
  run: (...args) => getDatabase().then((db) => db.prepare(sql).run(...args)),
});
const insertImage = statement(
  `INSERT INTO images
     (token, owner_id, storage_name, mime, width, height, byte_size, title, created_at,
     ttl_seconds, timer_start, max_views, expires_at,
      phash, moderation_status, moderation_reason, moderation_score, moderation_details, storage_backend, storage_encrypted, video_normalized)
   VALUES
     (@token, @owner_id, @storage_name, @mime, @width, @height, @byte_size, @title, @created_at,
      @ttl_seconds, @timer_start, @max_views, @expires_at,
      @phash, @moderation_status, @moderation_reason, @moderation_score, @moderation_details, @storage_backend, @storage_encrypted, @video_normalized)`
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
const listMine = statement(
  `SELECT i.*, (SELECT COUNT(*) FROM access_logs a WHERE a.image_id = i.id AND a.blocked_reason IS NULL) AS views
   FROM images i WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC`
);
const getMineByToken = statement('SELECT * FROM images WHERE token = ? AND owner_id = ? AND deleted_at IS NULL');
const softDelete = statement('UPDATE images SET deleted_at = ? WHERE id = ?');
const getDefaults = statement('SELECT default_ttl, default_timer_start, default_max_views, upload_max_bytes, storage_limit_bytes, rank FROM users WHERE id = ?');
const storageUsed = statement('SELECT COALESCE(SUM(byte_size), 0) AS bytes FROM images WHERE owner_id = ? AND deleted_at IS NULL');
const insertGallery = statement('INSERT INTO galleries (token, owner_id, title, created_at) VALUES (?, ?, ?, ?)');
const addGalleryItem = statement('INSERT INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)');

// A deleted image keeps its access log for the retention window, so the owner
// can still read (and report from) it after the media itself is gone.
const getMineForLogs = statement(
  'SELECT * FROM images WHERE token = ? AND owner_id = ? AND (deleted_at IS NULL OR deleted_at > ?)'
);
const listMineDeleted = statement(
  `SELECT * FROM images WHERE owner_id = ? AND deleted_at IS NOT NULL AND deleted_at > ?
   ORDER BY deleted_at DESC`
);

// Retention settings come from the form, falling back to the user's defaults.
function resolveRetention(body, defaults) {
  const requestedTtl = body.ttl || defaults.default_ttl;
  const ttlKey = Object.prototype.hasOwnProperty.call(TTL_PRESETS, requestedTtl) ? requestedTtl : '24h';
  const requestedMaxViews = body.max_views === undefined || body.max_views === '' ? defaults.default_max_views : body.max_views;
  const parsedViews = parseInt(requestedMaxViews, 10);
  return {
    ttlSeconds: TTL_PRESETS[ttlKey],
    timerStart: (body.timer_start || defaults.default_timer_start) === 'upload' ? 'upload' : 'first_view',
    maxViews: Number.isInteger(parsedViews) && parsedViews > 0 ? parsedViews : null,
    title: String(body.title || '').slice(0, 200) || null,
  };
}

/**
 * Take one staged file through probe -> moderation -> storage -> database.
 * Shared by the multipart path and the chunked path, so both apply identical
 * validation and produce identical rows. Consumes `filePath`: it is unlinked
 * whether or not this succeeds.
 */
async function processStagedFile({ user, filePath, mimetype, size, retention }) {
  let dims;
  try {
    dims = await watermark.probe(filePath);
    if (!dims.format) throw new Error('unrecognised media');
  } catch {
    throw new Error('That file is not a valid image or video.');
  }

  // Canonicalise video once, here, rather than making every viewer's render
  // cope with whatever container and codec arrived. The per-viewer watermark
  // itself still has to be burned per view- that is what makes a leaked copy
  // traceable- but this removes the format work from that hot path and lets it
  // copy the audio track untouched.
  let normalized = 0;
  let mediaPath = filePath;
  let storedSize = size;
  if (dims.mediaType === 'video' && config.ffmpeg.normalizeOnUpload) {
    const normalizedPath = beneath(config.tempDir, randomToken(20) + '.mp4');
    try {
      await watermark.transcodeVideo(filePath, normalizedPath);
      fs.unlink(filePath, () => {});
      mediaPath = normalizedPath;
      normalized = 1;
      storedSize = (await fs.promises.stat(normalizedPath)).size;
      mimetype = 'video/mp4';
      // Normalisation caps resolution, so the stored dimensions are the ones
      // after the cap- the watermark overlay is built from these columns and
      // would be the wrong size otherwise.
      dims = await watermark.probe(normalizedPath);
    } catch (error) {
      // A normalisation failure must not lose the upload: keep the original
      // bytes and let each view re-encode from them as before.
      console.warn('[NamelessUnSee] video normalisation failed, storing the original:', error.message);
      fs.unlink(normalizedPath, () => {});
    }
  }

  const now = Date.now();
  const expiresAt = retention.timerStart === 'upload' && retention.ttlSeconds
    ? now + retention.ttlSeconds * 1000
    : null;

  let mod = { status: 'ok', reason: null, score: null, phash: null };
  if (ranks.shouldScan(user)) {
    try {
      mod = await moderation.scan(mediaPath);
    } catch (error) {
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
  const storageName = `upload/${user.id}/${mediaDir}/${datePart}_${now}_${token}${EXT[mimetype] || '.bin'}`;
  const stored = await storage.put(mediaPath, storageName);
  fs.unlink(mediaPath, () => {});

  let image;
  try {
    const info = await insertImage.run({
      token, owner_id: user.id, storage_name: stored.storage_name, mime: mimetype,
      width: dims.width, height: dims.height, byte_size: storedSize, title: retention.title, created_at: now,
      ttl_seconds: retention.ttlSeconds, timer_start: retention.timerStart, max_views: retention.maxViews,
      expires_at: expiresAt,
      phash: mod.phash, moderation_status: mod.status, moderation_reason: mod.reason,
      moderation_score: mod.score, moderation_details: mod.details ? JSON.stringify(mod.details) : null,
      storage_backend: stored.storage_backend, storage_encrypted: stored.storage_encrypted,
      video_normalized: normalized,
    });
    image = await statement('SELECT * FROM images WHERE id = ?').get(info.lastInsertRowid);
  } catch (error) {
    await storage.remove(stored).catch(() => {});
    throw error;
  }

  if (mod.status !== 'ok') {
    notify.notifyAdminFlag({
      username: user.username, email: user.email, token, title: retention.title,
      reason: mod.reason, score: mod.score, reports: mod.details,
    }).catch(() => {});
  }
  return { image, flagged: mod.status !== 'ok' };
}

// A batch of more than one file becomes a gallery, as on the multipart path.
async function galleryFor(created, user, title) {
  if (created.length <= 1) return null;
  const now = Date.now();
  const galleryToken = uuidv7(now);
  const galleryId = (await insertGallery.run(galleryToken, user.id, title || 'Uploaded gallery', now)).lastInsertRowid;
  const db = await getDatabase();
  await db.batch(created.map((image, index) => ({
    sql: 'INSERT INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)',
    args: [galleryId, image.id, index + 1, now],
  })));
  return galleryToken;
}

function dashboardRedirect({ flagged, galleryToken }) {
  return '/dashboard?uploaded=1'
    + (flagged ? '&flagged=1' : '')
    + (galleryToken ? `&gallery=${encodeURIComponent(galleryToken)}` : '');
}

router.get('/dashboard', requireAuth, async (req, res) => {
  const defaults = await getDefaults.get(req.user.id) || {};
  const effective = ranks.limits({ ...req.user, ...defaults });
  res.render('dashboard', {
    me: req.user,
    images: await listMine.all(req.user.id),
    recentlyDeleted: await listMineDeleted.all(req.user.id, accessLog.retentionCutoff()),
    logRetentionHours: config.logRetentionAfterDeleteHours,
    baseUrl: config.baseUrl,
    ttlHours: config.imageTtlHours,
    maxMb: Number.isFinite(effective.uploadBytes) ? Math.round(effective.uploadBytes / (1024 * 1024)) : null,
    storageUsed: (await storageUsed.get(req.user.id)).bytes,
    storageLimit: effective.storageBytes,
    rank: req.user.rank,
    defaults,
    chunkedUploads: config.chunkedUpload.enabled,
    chunkBytes: config.chunkedUpload.chunkBytes,
    chunkThreshold: config.chunkedUpload.thresholdBytes,
    chunkParallel: config.chunkedUpload.parallel,
    imageMaxEdge: config.clientImage.maxEdge,
    imageQuality: config.clientImage.quality,
    imageReencodeAbove: config.clientImage.reencodeAboveBytes,
    clientVideo: config.clientVideo.enabled,
    clientVideoMaxHeight: config.clientVideo.maxHeight,
    clientVideoMaxFps: config.clientVideo.maxFps,
    clientVideoBitrate: config.clientVideo.bitrate,
    notice: req.query.uploaded ? 'Image uploaded.' : null,
    flagged: !!req.query.flagged,
    gallery: req.query.gallery || null,
  });
});

// Batch upload endpoint. A batch with multiple files is automatically put into
// a gallery; the single-file path remains equivalent to the original upload.
router.post('/upload', requireAuth, limiters.upload, (req, res) => {
  uploadFor(req.user).array('image', 50)(req, res, async (err) => {
    const files = req.files || [];
    const removeStaged = () => files.forEach((file) => {
      try { fs.unlink(stagedPath(file), () => {}); } catch { /* invalid staged path */ }
    });
    if (err) {
      removeStaged();
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? `File too large (max ${Math.round(config.maxUploadBytes / (1024 * 1024))} MB).`
        : err.code === 'LIMIT_FILE_COUNT'
          ? 'You may upload up to 50 files at once.'
          : 'Upload failed.';
      return res.status(400).render('error', { title: 'Upload error', message: msg });
    }
    if (!req.session || !req.body._csrf || req.body._csrf !== req.session.csrf_token) {
      removeStaged();
      return res.status(403).render('error', { title: 'Forbidden', message: 'Invalid CSRF token. Please reload and try again.' });
    }
    if (!files.length) {
      return res.status(400).render('error', { title: 'Upload error', message: 'No media files provided (allowed: PNG, JPEG, WebP, GIF, AVIF, MP4, WebM, MOV, Ogg).' });
    }
    if (!verifySolution(req.body.altcha)) {
      removeStaged();
      return res.status(400).render('error', { title: 'Upload error', message: 'Complete the bot check before uploading.' });
    }

    const limits = await getDefaults.get(req.user.id) || {};
    const effective = ranks.limits({ ...req.user, ...limits });
    const totalBytes = files.reduce((sum, file) => sum + (file.size || 0), 0);
    if (files.some((file) => file.size > effective.uploadBytes)) {
      removeStaged();
      return res.status(400).render('error', { title: 'Upload error', message: `File too large (your limit is ${Math.round(effective.uploadBytes / (1024 * 1024))} MB per file).` });
    }
    const used = (await storageUsed.get(req.user.id)).bytes;
    if (used + totalBytes > effective.storageBytes) {
      removeStaged();
      return res.status(400).render('error', { title: 'Upload error', message: `Storage limit reached. You have ${Math.max(0, Math.floor((effective.storageBytes - used) / (1024 * 1024)))} MB remaining.` });
    }

    const defaults = await getDefaults.get(req.user.id) || { default_ttl: '24h', default_timer_start: 'first_view', default_max_views: null };
    const retention = resolveRetention(req.body, defaults);
    const created = [];
    let flagged = false;

    try {
      for (const file of files) {
        const filePath = stagedPath(file);
        if (file.buffer && !fs.existsSync(filePath)) await fs.promises.writeFile(filePath, file.buffer, { mode: 0o600 });
        const result = await processStagedFile({
          user: req.user, filePath, mimetype: file.mimetype, size: file.size, retention,
        });
        created.push(result.image);
        if (result.flagged) flagged = true;
      }
    } catch (error) {
      removeStaged();
      for (const image of created) {
        await softDelete.run(Date.now(), image.id);
        storage.remove(image).catch(() => {});
      }
      const message = error.message === 'That file is not a valid image or video.' ? error.message : 'The upload could not be stored.';
      return res.status(400).render('error', { title: 'Upload error', message });
    }

    const galleryToken = await galleryFor(created, req.user, retention.title);
    res.redirect(dashboardRedirect({ flagged, galleryToken }));
  });
});


// --- chunked upload ---------------------------------------------------------
// A reverse proxy caps request bodies (Cloudflare: 100 MB on most plans), so a
// large file is posted as slices instead: /upload/init once, then each slice to
// /upload/chunk/:id/:index, then /upload/complete. Only /init spends the altcha
// solution- solutions are single-use, so verifying one per chunk would fail on
// the second request.

const chunkBody = express.raw({
  type: 'application/octet-stream',
  limit: config.chunkedUpload.chunkBytes + 4096, // headroom so a full chunk is never a 413
});

// Chunk bodies are raw bytes, so the token travels in a header there. A custom
// header cannot be set cross-origin without a CORS preflight this server never
// grants, and the same-origin guard in server.js applies on top.
function csrfOk(req) {
  const token = (req.body && !Buffer.isBuffer(req.body) && req.body._csrf) || req.get('X-CSRF-Token');
  return !!(req.session && token && token === req.session.csrf_token);
}

function chunkingEnabled(res) {
  if (config.chunkedUpload.enabled) return true;
  res.status(404).json({ error: 'Chunked uploads are disabled.' });
  return false;
}

router.post('/upload/init', requireAuth, limiters.upload, async (req, res) => {
  if (!chunkingEnabled(res)) return;
  if (!csrfOk(req)) return res.status(403).json({ error: 'Invalid CSRF token. Please reload and try again.' });
  if (!verifySolution(req.body.altcha)) return res.status(400).json({ error: 'Complete the bot check before uploading.' });

  const requested = Array.isArray(req.body.files) ? req.body.files : [];
  if (!requested.length) return res.status(400).json({ error: 'No media files provided.' });
  if (requested.length > 50) return res.status(400).json({ error: 'You may upload up to 50 files at once.' });

  const limits = await getDefaults.get(req.user.id) || {};
  const effective = ranks.limits({ ...req.user, ...limits });
  const hardLimit = ranks.isOwner(req.user) ? Infinity : config.maxUploadBytesHard;

  let total = 0;
  for (const file of requested) {
    const size = Number(file && file.size);
    if (!Number.isInteger(size) || size <= 0) return res.status(400).json({ error: 'Invalid file size.' });
    if (!ALLOWED_MIME.has(file.mime)) {
      return res.status(400).json({ error: 'Unsupported file type (allowed: PNG, JPEG, WebP, GIF, AVIF, MP4, WebM, MOV, Ogg).' });
    }
    if (size > effective.uploadBytes || size > hardLimit) {
      return res.status(400).json({ error: `File too large (your limit is ${Math.round(effective.uploadBytes / (1024 * 1024))} MB per file).` });
    }
    total += size;
  }

  const used = (await storageUsed.get(req.user.id)).bytes;
  if (used + total > effective.storageBytes) {
    return res.status(400).json({ error: `Storage limit reached. You have ${Math.max(0, Math.floor((effective.storageBytes - used) / (1024 * 1024)))} MB remaining.` });
  }

  const uploads = requested.map((file) => {
    const session = chunked.create({
      userId: req.user.id, mime: file.mime, size: Number(file.size), ext: EXT[file.mime] || '.bin',
    });
    return { id: session.id, totalChunks: session.totalChunks };
  });
  res.json({ chunkBytes: config.chunkedUpload.chunkBytes, uploads });
});

router.post('/upload/chunk/:id/:index', requireAuth, limiters.uploadChunk, chunkBody, async (req, res) => {
  if (!chunkingEnabled(res)) return;
  if (!csrfOk(req)) return res.status(403).json({ error: 'Invalid CSRF token. Please reload and try again.' });

  const session = chunked.get(req.params.id, req.user.id);
  if (!session) return res.status(404).json({ error: 'Unknown or expired upload session.' });

  try {
    const progress = await chunked.writeChunk(session, Number(req.params.index), req.body);
    res.json(progress);
  } catch (error) {
    // A bad or over-budget chunk voids the whole session rather than letting the
    // client retry its way around the size check.
    chunked.discard(session);
    res.status(400).json({ error: error.message });
  }
});

router.post('/upload/complete', requireAuth, limiters.upload, async (req, res) => {
  if (!chunkingEnabled(res)) return;
  if (!csrfOk(req)) return res.status(403).json({ error: 'Invalid CSRF token. Please reload and try again.' });

  const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
  if (!ids.length) return res.status(400).json({ error: 'No uploads to finish.' });

  const sessions = ids.map((id) => chunked.get(String(id), req.user.id));
  if (sessions.some((session) => !session)) {
    sessions.forEach((session) => chunked.discard(session));
    return res.status(404).json({ error: 'An upload session expired. Please try again.' });
  }
  if (sessions.some((session) => !chunked.isComplete(session))) {
    sessions.forEach((session) => chunked.discard(session));
    return res.status(400).json({ error: 'Upload is incomplete. Please try again.' });
  }

  // Re-check against the bytes that actually arrived, not what was declared at
  // init: quota may also have been consumed by another upload in between.
  const limits = await getDefaults.get(req.user.id) || {};
  const effective = ranks.limits({ ...req.user, ...limits });
  const total = sessions.reduce((sum, session) => sum + session.bytes, 0);
  if (sessions.some((session) => session.bytes > effective.uploadBytes)) {
    sessions.forEach((session) => chunked.discard(session));
    return res.status(400).json({ error: `File too large (your limit is ${Math.round(effective.uploadBytes / (1024 * 1024))} MB per file).` });
  }
  const used = (await storageUsed.get(req.user.id)).bytes;
  if (used + total > effective.storageBytes) {
    sessions.forEach((session) => chunked.discard(session));
    return res.status(400).json({ error: `Storage limit reached. You have ${Math.max(0, Math.floor((effective.storageBytes - used) / (1024 * 1024)))} MB remaining.` });
  }

  const defaults = await getDefaults.get(req.user.id) || { default_ttl: '24h', default_timer_start: 'first_view', default_max_views: null };
  const retention = resolveRetention(req.body, defaults);
  const created = [];
  let flagged = false;

  try {
    for (const session of sessions) {
      const filePath = await chunked.assemble(session);
      const result = await processStagedFile({
        user: req.user, filePath, mimetype: session.mime, size: session.bytes, retention,
      });
      created.push(result.image);
      if (result.flagged) flagged = true;
    }
  } catch (error) {
    sessions.forEach((session) => chunked.discard(session));
    for (const image of created) {
      await softDelete.run(Date.now(), image.id);
      storage.remove(image).catch(() => {});
    }
    const message = error.message === 'That file is not a valid image or video.' ? error.message : 'The upload could not be stored.';
    return res.status(400).json({ error: message });
  }

  const galleryToken = await galleryFor(created, req.user, retention.title);
  res.json({ redirect: dashboardRedirect({ flagged, galleryToken }) });
});

router.get('/dashboard/i/:token/logs', requireAuth, async (req, res) => {
  const img = await getMineForLogs.get(req.params.token, req.user.id, accessLog.retentionCutoff());
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });

  const q = (req.query.q || '').toString().trim().slice(0, 100);
  res.render('logs', {
    me: req.user,
    image: img,
    admin: false,
    owner: null,
    basePath: `/dashboard/i/${encodeURIComponent(img.token)}/logs`,
    backHref: '/dashboard',
    backLabel: 'Dashboard',
    retainedUntil: accessLog.retainedUntil(img),
    baseUrl: config.baseUrl,
    q,
    reported: req.query.reported === '1',
    // Erasing a log early is an owner-rank action, taken from the admin view.
    canErase: false,
    erasePath: null,
    openReports: 0,
    notice: null,
    error: null,
    ...(await accessLog.readPage(img.id, { q, page: req.query.page })),
  });
});

// --- per-recipient view links ----------------------------------------------
const listLinks = statement('SELECT * FROM view_links WHERE image_id = ? ORDER BY created_at DESC');
const insertLink = statement(
  'INSERT INTO view_links (image_id, token, label, max_uses, created_at) VALUES (?, ?, ?, ?, ?)'
);
const revokeLink = statement('UPDATE view_links SET revoked_at = ? WHERE id = ? AND image_id = ?');

router.get('/dashboard/i/:token/links', requireAuth, async (req, res) => {
  const img = await getMineByToken.get(req.params.token, req.user.id);
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });
  res.render('links', {
    me: req.user,
    image: img,
    links: await listLinks.all(img.id),
    baseUrl: config.baseUrl,
    created: req.query.created === '1',
  });
});

router.post('/dashboard/i/:token/links', requireAuth, verifyCsrf, async (req, res) => {
  const img = await getMineByToken.get(req.params.token, req.user.id);
  if (!img) return res.status(404).render('error', { title: 'Not found', message: 'No such image.' });
  const label = String(req.body.label || '').trim().slice(0, 80) || null;
  const rawMax = String(req.body.max_uses || '').trim();
  let maxUses = rawMax ? parseInt(rawMax, 10) : null;
  maxUses = Number.isInteger(maxUses) && maxUses > 0 ? maxUses : null;
  if (req.body.one_time === 'on') maxUses = 1;
  await insertLink.run(img.id, randomToken(20), label, maxUses, Date.now());
  res.redirect(`/dashboard/i/${encodeURIComponent(img.token)}/links?created=1`);
});

router.post('/dashboard/i/:token/links/:id/revoke', requireAuth, verifyCsrf, async (req, res) => {
  const img = await getMineByToken.get(req.params.token, req.user.id);
  if (img) await revokeLink.run(Date.now(), parseInt(req.params.id, 10) || 0, img.id);
  res.redirect(`/dashboard/i/${encodeURIComponent(req.params.token)}/links`);
});

router.post('/dashboard/i/:token/delete', requireAuth, verifyCsrf, async (req, res) => {
  const img = await getMineByToken.get(req.params.token, req.user.id);
  if (img) {
    await softDelete.run(Date.now(), img.id);
    storage.remove(img).catch(() => {});
  }
  res.redirect('/dashboard');
});

module.exports = router;
