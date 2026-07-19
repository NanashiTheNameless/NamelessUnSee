'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const db = require('../db');
const config = require('../config');
const watermark = require('../watermark');
const logging = require('../logging');
const ipintel = require('../ipintel');
const { limiters } = require('../ratelimit');
const { requireConsent, withScriptNonce } = require('../middleware');
const { verifySolution } = require('../altcha');
const storage = require('../storage');

const router = express.Router();

const getLive = db.prepare('SELECT * FROM images WHERE token = ? AND deleted_at IS NULL');
// A row with a non-null ip means a render already happened for this view id
// (the telemetry beacon also upserts the row, but never sets ip).
const getExistingView = db.prepare('SELECT 1 AS seen FROM access_logs WHERE image_id = ? AND view_id = ? AND ip IS NOT NULL');
const startTimer = db.prepare(
  'UPDATE images SET first_viewed_at = ?, expires_at = ? WHERE id = ? AND first_viewed_at IS NULL'
);
const bumpViews = db.prepare('UPDATE images SET view_count = view_count + 1 WHERE id = ? RETURNING view_count, max_views');
const softDeleteImg = db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?');
const VIEW_GATE_COOKIE = 'view_gate';

// Start the retention timer on first view (if configured that way) and count
// the view, deleting the image once max_views is reached.
function accountView(img) {
  const now = Date.now();
  if (img.timer_start === 'first_view' && img.ttl_seconds && !img.first_viewed_at) {
    startTimer.run(now, now + img.ttl_seconds * 1000, img.id);
  }
  const row = bumpViews.get(img.id);
  if (row && row.max_views && row.view_count >= row.max_views) {
    softDeleteImg.run(now, img.id);
    storage.remove(img).catch(() => {});
  }
}

function servedFilename(ip, now, extension) {
  const date = new Date(now);
  const datePart = [date.getMonth() + 1, date.getDate(), date.getFullYear()]
    .map((value) => String(value).padStart(2, '0'))
    .join('.');
  // Keep the forensic IP readable while staying a legal filename everywhere:
  // IPv6 colons become dashes (2001:db8::1 -> 2001-db8--1), and characters
  // that break headers or filesystems are stripped to underscores.
  const safeIp = String(ip || 'unknown').replace(/:/g, '-').replace(/[\\/"\r\n*?<>|\s]/g, '_');
  return `CONFIDENTIAL-${safeIp}-${datePart}-${now}.${extension}`;
}

function isViewable(img) {
  const s = img.moderation_status;
  if (s === 'ok' || s === 'approved') return true;
  // A review-flagged image is viewable only if the operator chose not to hold.
  if (s === 'review' && !config.moderation.holdOnReview) return true;
  return false; // quarantined / rejected / held-for-review
}

function loadImage(req, res) {
  const img = getLive.get(req.params.token);
  if (!img) {
    res.status(404);
    return null;
  }
  if (img.expires_at && img.expires_at < Date.now()) {
    res.status(410);
    res.locals._expired = true;
    return null;
  }
  // Held/quarantined images are indistinguishable from "not found" to viewers.
  if (!isViewable(img)) {
    res.status(404);
    return null;
  }
  return img;
}

function sanitizeViewId(v) {
  if (typeof v !== 'string') return null;
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(v)) return null;
  return v;
}

// --- per-recipient links ----------------------------------------------------
const getLink = db.prepare('SELECT * FROM view_links WHERE token = ? AND image_id = ?');
const consumeLink = db.prepare(
  `UPDATE view_links SET use_count = use_count + 1
   WHERE id = ? AND revoked_at IS NULL AND (max_uses IS NULL OR use_count < max_uses)`
);

// Resolve ?r= to a link row. Returns:
//   { link: null }                  no ?r= given
//   { invalid: true }               unknown or revoked
//   { link, exhausted: true }       valid but its uses are spent- still fine
//                                   for replays of an already-counted view
//   { link }                        valid and usable
function resolveLink(req, img) {
  const raw = req.query.r !== undefined ? req.query.r : (req.body && req.body.r);
  if (raw === undefined || raw === '') return { link: null };
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{10,64}$/.test(raw)) return { invalid: true };
  const link = getLink.get(raw, img.id);
  if (!link || link.revoked_at) return { invalid: true };
  if (link.max_uses && link.use_count >= link.max_uses) return { link, exhausted: true };
  return { link };
}

function linkGone(res) {
  return res.status(410).render('error', {
    title: 'Link no longer valid',
    message: 'This share link has been used up or revoked. Ask the person who shared it for a new one.',
  });
}

function blockMessage(reason) {
  switch (reason) {
    case 'no-public-ip':
      return 'We could not determine your public network address, so this image cannot be shown.';
    case 'proxy':
      return 'Access through VPNs, proxies, Tor or other anonymising networks is not permitted for this image.';
    case 'intel-unavailable':
      return 'We could not verify your connection right now. Because this image is only shown to fully identifiable viewers, access is blocked. Please try again later.';
    default:
      return 'Access to this image is not permitted from your connection.';
  }
}

// --- Consent-gated view page ---------------------------------------------
router.get('/i/:token', limiters.view, requireConsent, withScriptNonce, async (req, res) => {
  const img = loadImage(req, res);
  if (!img) {
    return res.render('view-gone', { expired: !!res.locals._expired });
  }

  const { link, invalid, exhausted } = resolveLink(req, img);
  if (invalid || exhausted) return linkGone(res);

  const assessment = await ipintel.assess(req);
  if (!assessment.allowed) {
    res.status(403);
    return res.render('view-blocked', { reason: assessment.reason, message: blockMessage(assessment.reason) });
  }

  res.setHeader('Cache-Control', 'no-store');
  res.render('view', {
    token: img.token,
    linkToken: link ? link.token : null,
    title: img.title,
    width: img.width,
    height: img.height,
    mediaType: img.mime && img.mime.startsWith('video/') ? 'video' : 'image',
    nonce: res.locals.nonce,
    reported: req.query.reported === '1',
    gateReady: req.signedCookies && req.signedCookies[VIEW_GATE_COOKIE] === img.token,
  });
});

router.post('/i/:token/view-check', limiters.view, requireConsent, (req, res) => {
  const img = loadImage(req, res);
  if (!img) return res.status(res.statusCode === 410 ? 410 : 404).end();
  const { link, invalid, exhausted } = resolveLink(req, img);
  if (invalid || exhausted) return linkGone(res);
  if (!verifySolution(req.body && req.body.altcha)) return res.status(400).type('text').send('The bot check did not pass. Please go back and try again.');
  res.cookie(VIEW_GATE_COOKIE, img.token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    signed: true,
    maxAge: 10 * 60 * 1000,
    path: `/i/${img.token}`,
  });
  const linkParam = link ? '&r=' + encodeURIComponent(link.token) : '';
  res.redirect(`/i/${encodeURIComponent(img.token)}?gate=1${linkParam}`);
});

// --- Per-viewer watermarked render (the ONLY image bytes ever served) ------
router.get(['/i/:token/render.png', '/i/:token/render.mp4'], limiters.render, requireConsent, async (req, res) => {
  const img = loadImage(req, res);
  if (!img) return res.status(res.statusCode === 410 ? 410 : 404).end();
  if (!req.signedCookies || req.signedCookies[VIEW_GATE_COOKIE] !== img.token) {
    return res.status(403).type('text').send('Complete the bot check before viewing this image.');
  }
  const { link, invalid, exhausted } = resolveLink(req, img);
  if (invalid) return res.status(410).type('text').send('This share link has been used up or revoked.');

  // Assess the viewer. If we cannot fully identify them, or they are behind a
  // VPN/proxy/Tor, refuse to render the image.
  const assessment = await ipintel.assess(req);
  if (!assessment.allowed) return res.status(403).type('text').send(blockMessage(assessment.reason));

  const viewId = sanitizeViewId(req.query.v);
  // Replays and seeks re-request the media with the same per-page view id;
  // only the first render of a view id counts against limits. An exhausted
  // link may still replay a view it already paid for- never start a new one.
  const isReplay = !!(viewId && getExistingView.get(img.id, viewId));
  if (exhausted && !isReplay) return res.status(410).type('text').send('This share link has been used up or revoked.');
  const linkLabel = link ? (link.label || `link #${link.id}`) : null;
  let identity;
  try {
    identity = logging.logRender(req, img.id, viewId, assessment, linkLabel);
  } catch {
    identity = {
      ip: assessment.ip,
      geoSummary: assessment.geoSummary,
      deviceSummary: '',
      org: assessment.org,
      proxy: assessment.proxy,
    };
  }

  const when = new Date().toISOString().replace('T', ' ').replace(/\..+/, ' UTC');
  const geoLine = identity.geoSummary;
  const lines = [
    'NamelessUnSee',
    'CONFIDENTIAL',
    'Traceable Copy',
    'Do Not Redistribute',
    `IP ${identity.ip}  - ${geoLine}`,
    identity.deviceSummary,
    `Viewed ${when}`,
    `Ref ${img.token}${viewId ? '/' + viewId.slice(0, 8) : ''}${linkLabel ? ' via ' + linkLabel : ''}`,
  ].filter((l) => l && l.trim());
  const footerLines = [
    'NamelessUnSee - CONFIDENTIAL - Traceable Copy',
    'Do Not Redistribute',
    `IP ${identity.ip} - ${geoLine}`,
    identity.deviceSummary,
    `Viewed ${when}`,
    `Ref ${img.token}${viewId ? '/' + viewId.slice(0, 8) : ''}${linkLabel ? ' via ' + linkLabel : ''}`,
  ].filter((l) => l && l.trim());

  let out;
  let materialized;
  let renderedVideo;
  try {
    materialized = await storage.materialize(img);
    if (img.mime && img.mime.startsWith('video/')) {
      renderedVideo = path.join(config.tempDir, `render-${img.token}-${Date.now()}.mp4`);
      await watermark.renderWatermarkedVideo(materialized.path, renderedVideo, img.width, img.height, lines, footerLines);
    } else {
      out = await watermark.renderWatermarked(materialized.path, lines, footerLines);
    }
  } catch {
    if (materialized) await materialized.cleanup();
    if (renderedVideo) fs.unlink(renderedVideo, () => {});
    return res.status(500).end();
  }
  await materialized.cleanup();

  // Consume the recipient link only after a successful render, atomically- if
  // two requests race a one-time link, exactly one gets the bytes. Replays of
  // an already-counted view (same view id) don't consume another use.
  if (link && !isReplay && consumeLink.run(link.id).changes === 0) {
    if (renderedVideo) fs.unlink(renderedVideo, () => {});
    return res.status(410).type('text').send('This share link has been used up or revoked.');
  }

  // Count this view: start the first-view timer if needed and enforce
  // max_views. Replays within the same page load don't count again.
  try {
    if (!isReplay) accountView(img);
  } catch { /* non-fatal */ }

  // Never cache: every delivery is a fresh, per-viewer watermarked render.
  if (renderedVideo) {
    res.setHeader('Content-Type', 'video/mp4');
    res.setHeader('Content-Disposition', `inline; filename="${servedFilename(identity.ip, Date.now(), 'mp4')}"`);
    res.setHeader('Content-Length', String(fs.statSync(renderedVideo).size));
    res.setHeader('Cache-Control', 'no-store, private, max-age=0');
    const stream = fs.createReadStream(renderedVideo);
    const cleanup = () => fs.unlink(renderedVideo, () => {});
    stream.on('close', cleanup);
    stream.on('error', cleanup);
    return stream.pipe(res);
  }
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'no-store, private, max-age=0');
  res.setHeader('Content-Disposition', `inline; filename="${servedFilename(identity.ip, Date.now(), 'png')}"`);
  res.send(out);
});

// --- Client-side telemetry beacon -----------------------------------------
router.post('/i/:token/telemetry', limiters.telemetry, requireConsent, (req, res) => {
  const img = getLive.get(req.params.token);
  if (!img) return res.status(204).end();
  const viewId = sanitizeViewId(req.body && req.body.viewId);

  const c = (req.body && req.body.client) || {};
  const client = {};
  const keys = [
    'screenW', 'screenH', 'availW', 'availH', 'viewportW', 'viewportH',
    'colorDepth', 'pixelRatio', 'timezone', 'timezoneOffset', 'languages',
    'platform', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
    'cookieEnabled', 'doNotTrack', 'referrer', 'connection',
    'userAgentData', 'webgl', 'battery', 'mediaCapabilities', 'fontFeatures',
  ];
  const bounded = (value, depth = 0) => {
    if (typeof value === 'string') return value.slice(0, 300);
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (typeof value === 'boolean' || value === null) return value;
    if (Array.isArray(value)) return value.slice(0, 20).map((v) => bounded(v, depth + 1));
    if (value && typeof value === 'object' && depth < 2) {
      return Object.fromEntries(Object.entries(value).slice(0, 20).map(([k, v]) => [k.slice(0, 80), bounded(v, depth + 1)]));
    }
    return undefined;
  };
  for (const k of keys) {
    if (c[k] !== undefined) client[k] = bounded(c[k]);
  }

  try {
    logging.logClient(img.id, viewId, client);
  } catch { /* best-effort */ }
  res.status(204).end();
});

module.exports = router;
