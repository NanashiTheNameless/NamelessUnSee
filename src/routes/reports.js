'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const db = require('../db');
const config = require('../config');
const { requireAuth, verifyCsrf } = require('../auth');
const { requireConsent, widgetPage } = require('../middleware');
const { limiters } = require('../ratelimit');
const { randomToken } = require('../util/crypto');
const watermark = require('../watermark');
const { verifySolution } = require('../altcha');
const notify = require('../notify');

const router = express.Router();
const REPORT_REASONS = new Set(['unauthorized_redistribution', 'harassment', 'other']);
const proofUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, config.reportDir),
    filename: (req, file, cb) => cb(null, randomToken(20) + path.extname(file.originalname || '').toLowerCase()),
  }),
  limits: { fileSize: config.maxReportBytes, files: 15 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpeg|webp|gif|avif)$/.test(file.mimetype)),
});

const getImage = db.prepare('SELECT * FROM images WHERE token = ? AND deleted_at IS NULL');
const insertReport = db.prepare(
  `INSERT INTO leak_reports
     (image_id, reporter_id, view_ref, reason, details, proof_storage_name, proof_mime, proof_byte_size, created_at, access_log_id)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const getOwnerLog = db.prepare(
  `SELECT a.*, i.token, i.title
   FROM access_logs a JOIN images i ON i.id = a.image_id
   WHERE a.id = ? AND i.token = ? AND i.owner_id = ? AND i.deleted_at IS NULL`
);
const existingLogReport = db.prepare('SELECT id FROM leak_reports WHERE access_log_id = ?');
const insertProof = db.prepare(
  'INSERT INTO leak_report_proofs (report_id, storage_name, mime, byte_size, created_at) VALUES (?, ?, ?, ?, ?)'
);

function removeProofs(files) {
  for (const file of files || []) {
    if (file && file.filename) fs.unlink(path.join(config.reportDir, file.filename), () => {});
  }
}

async function validateProofs(files) {
  if (!files || files.length < 1 || files.length > 15) throw new Error('proof count');
  for (const file of files) {
    const proof = await watermark.probe(path.join(config.reportDir, file.filename));
    if (!proof.format) throw new Error('invalid proof image');
  }
}

router.post('/i/:token/report', requireAuth, requireConsent, widgetPage, limiters.report, (req, res) => {
  proofUpload.array('proofs', 15)(req, res, async (err) => {
    if (err) {
      removeProofs(req.files);
      const message = err.code === 'LIMIT_FILE_SIZE'
        ? `Screenshot too large (max ${Math.round(config.maxReportBytes / (1024 * 1024))} MB).`
        : err.code === 'LIMIT_UNEXPECTED_FILE'
          ? 'You may upload up to 15 screenshots.'
        : 'Screenshot upload failed. Use PNG, JPEG, WebP, GIF, or AVIF.';
      return res.status(400).render('error', { title: 'Report error', message });
    }
    if (!req.session || !req.body._csrf || req.body._csrf !== req.session.csrf_token) {
      removeProofs(req.files);
      return res.status(403).render('error', { title: 'Forbidden', message: 'Invalid CSRF token.' });
    }
    if (!verifySolution(req.body.altcha)) {
      removeProofs(req.files);
      return res.status(400).render('error', { title: 'Report error', message: 'Complete the bot check before submitting.' });
    }

    const image = getImage.get(req.params.token);
    const reason = REPORT_REASONS.has(req.body.reason) ? req.body.reason : null;
    const details = String(req.body.details || '').trim().slice(0, 2000) || null;
    const viewRef = String(req.body.view_ref || '').trim().slice(0, 120) || null;
    if (!image || !reason || !details || !req.files || !req.files.length) {
      removeProofs(req.files);
      return res.status(400).render('error', { title: 'Report error', message: 'Image, reason, details, and at least one screenshot are required.' });
    }

    try {
      await validateProofs(req.files);
    } catch {
      removeProofs(req.files);
      return res.status(400).render('error', { title: 'Report error', message: 'Every screenshot must be a valid image.' });
    }

    const first = req.files[0];
    const result = insertReport.run(
      image.id,
      req.user.id,
      viewRef,
      reason,
      details,
      first.filename,
      first.mimetype,
      first.size,
      Date.now(),
      null
    );
    for (const file of req.files) insertProof.run(result.lastInsertRowid, file.filename, file.mimetype, file.size, Date.now());
    notify.notifyAdminReport({
      id: result.lastInsertRowid,
      reporterUsername: req.user.username,
      reporterEmail: req.user.email,
      title: image.title,
      token: image.token,
      reason,
      details,
    }).catch(() => {});
    res.redirect(`/i/${encodeURIComponent(image.token)}?reported=1`);
  });
});

router.get('/dashboard/i/:token/logs/:logId/report', requireAuth, widgetPage, (req, res) => {
  const log = getOwnerLog.get(req.params.logId, req.params.token, req.user.id);
  if (!log) return res.status(404).render('error', { title: 'Not found', message: 'No such access log entry.' });
  if (existingLogReport.get(log.id)) return res.redirect(`/dashboard/i/${encodeURIComponent(log.token)}/logs`);
  res.render('report-log', { image: log, log, error: null });
});

router.post('/dashboard/i/:token/logs/:logId/report', requireAuth, widgetPage, limiters.report, (req, res) => {
  proofUpload.array('proofs', 15)(req, res, async (err) => {
    const log = getOwnerLog.get(req.params.logId, req.params.token, req.user.id);
    const fail = (message, status = 400) => {
      removeProofs(req.files);
      return res.status(status).render('report-log', { image: log || { token: req.params.token }, log, error: message });
    };
    if (err) return fail(err.code === 'LIMIT_FILE_SIZE'
      ? `Screenshot too large (max ${Math.round(config.maxReportBytes / (1024 * 1024))} MB).`
      : err.code === 'LIMIT_UNEXPECTED_FILE' ? 'You may upload up to 15 screenshots.' : 'Screenshot upload failed.');
    if (!log) return fail('No such access log entry.', 404);
    if (existingLogReport.get(log.id)) return fail('This access log entry was already reported.', 409);
    if (!req.session || req.body._csrf !== req.session.csrf_token) return fail('Invalid CSRF token.', 403);
    if (!verifySolution(req.body.altcha)) return fail('Complete the bot check before submitting.', 400);
    const details = String(req.body.details || '').trim().slice(0, 2000);
    if (!details) return fail('Details are required.', 400);
    if (!req.files || !req.files.length) return fail('At least one screenshot proof is required.', 400);
    try {
      await validateProofs(req.files);
    } catch {
      return fail('Screenshot is not a valid image.', 400);
    }
    const first = req.files[0];
    const result = insertReport.run(log.image_id, req.user.id, log.view_id || null, 'unauthorized_redistribution',
      details, first.filename,
      first.mimetype, first.size, Date.now(), log.id);
    for (const file of req.files) insertProof.run(result.lastInsertRowid, file.filename, file.mimetype, file.size, Date.now());
    notify.notifyAdminReport({
      id: result.lastInsertRowid,
      reporterUsername: req.user.username,
      reporterEmail: req.user.email,
      title: log.title,
      token: log.token,
      reason: 'unauthorized_redistribution',
      details,
    }).catch(() => {});
    res.redirect(`/dashboard/i/${encodeURIComponent(log.token)}/logs?reported=1`);
  });
});

module.exports = router;
