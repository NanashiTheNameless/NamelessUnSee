'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const db = require('../db');
const config = require('../config');
const { requireAdmin, requireOwner, verifyCsrf } = require('../auth');
const bans = require('../bans');
const audit = require('../audit');
const storage = require('../storage');
const notify = require('../notify');

const router = express.Router();

const pendingUsers = db.prepare("SELECT * FROM users WHERE status = 'pending' ORDER BY created_at ASC");
const allUsers = db.prepare('SELECT * FROM users ORDER BY created_at DESC');
const getUser = db.prepare('SELECT * FROM users WHERE id = ?');
const setStatus = db.prepare('UPDATE users SET status = ?, approved_at = ?, approved_by = ? WHERE id = ?');
const setRole = db.prepare('UPDATE users SET role = ? WHERE id = ?');
const setRank = db.prepare("UPDATE users SET rank = ? WHERE id = ? AND rank != 'owner'");
const setUserLimits = db.prepare('UPDATE users SET upload_max_bytes = ?, storage_limit_bytes = ? WHERE id = ?');
const listUserImages = db.prepare('SELECT * FROM images WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC');
const getUserImage = db.prepare('SELECT * FROM images WHERE owner_id = ? AND token = ? AND deleted_at IS NULL');
const softDeleteUserImage = db.prepare('UPDATE images SET deleted_at = ? WHERE id = ? AND owner_id = ? AND deleted_at IS NULL');
const listReports = db.prepare(
  `SELECT r.*, i.token, i.title AS image_title, i.owner_id, owner.username AS owner_name,
          reporter.username AS reporter_name
   FROM leak_reports r
   JOIN images i ON i.id = r.image_id
   JOIN users owner ON owner.id = i.owner_id
   JOIN users reporter ON reporter.id = r.reporter_id
   ORDER BY CASE r.status WHEN 'open' THEN 0 ELSE 1 END, r.created_at DESC`
);
const getReport = db.prepare('SELECT * FROM leak_reports WHERE id = ?');
const listReportProofs = db.prepare('SELECT id, storage_name, mime, byte_size FROM leak_report_proofs WHERE report_id = ? ORDER BY id');
const updateReport = db.prepare(
  'UPDATE leak_reports SET status = ?, reviewed_at = ?, reviewed_by = ?, admin_note = ? WHERE id = ?'
);
const countAccounts = db.prepare('SELECT COUNT(*) AS n FROM users');
const countPendingAccounts = db.prepare("SELECT COUNT(*) AS n FROM users WHERE status = 'pending'");
const countOpenReports = db.prepare("SELECT COUNT(*) AS n FROM leak_reports WHERE status = 'open'");

// Optional expiry presets for bans.
const BAN_TTL = { never: null, '1h': 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400 };
function banExpiry(key) {
  const s = Object.prototype.hasOwnProperty.call(BAN_TTL, key) ? BAN_TTL[key] : null;
  return s ? Date.now() + s * 1000 : null;
}

const AUDIT_PAGE = 50;

function reportRows() {
  return listReports.all().map((report) => ({
    ...report,
    proofs: listReportProofs.all(report.id).length
      ? listReportProofs.all(report.id)
      : [{ id: null, storage_name: report.proof_storage_name, mime: report.proof_mime, byte_size: report.proof_byte_size }],
  }));
}

function sectionData(req, section) {
  const users = allUsers.all().map((u) => ({ ...u, ban: bans.userBan(u.id) }));
  const apage = Math.max(1, parseInt(req.query.apage, 10) || 1);
  const auditTotal = audit.count();
  return {
    section,
    pending: pendingUsers.all(),
    users,
    bans: bans.list(),
    me: req.user,
    audit: audit.list(AUDIT_PAGE, (apage - 1) * AUDIT_PAGE),
    apage,
    auditTotalPages: Math.max(1, Math.ceil(auditTotal / AUDIT_PAGE)),
    reports: reportRows(),
    config,
  };
}

router.get('/admin', requireAdmin, (req, res) => {
  res.render('admin-home', {
    accountCount: countAccounts.get().n,
    pendingCount: countPendingAccounts.get().n,
    openReportCount: countOpenReports.get().n,
    banCount: bans.list().length,
    auditCount: audit.count(),
    reviewCount: res.locals.reviewPending || 0,
    recentBans: bans.list().slice(0, 5),
    recentAudit: audit.list(5, 0),
  });
});

for (const [pathName, section] of [['users', 'users'], ['reports', 'reports'], ['bans', 'bans'], ['audit', 'audit']]) {
  router.get(`/admin/${pathName}`, requireAdmin, (req, res) => res.render('admin', sectionData(req, section)));
}

router.post('/admin/audit/clear', requireOwner, verifyCsrf, (req, res) => {
  audit.clear();
  res.redirect('/admin/audit');
});

router.post('/admin/audit/:id/delete', requireOwner, verifyCsrf, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (Number.isInteger(id) && id > 0) audit.remove(id);
  res.redirect('/admin/audit');
});

router.get('/admin/users/:id/files', requireAdmin, (req, res) => {
  const user = getUser.get(req.params.id);
  if (!user) return res.status(404).render('error', { title: 'Not found', message: 'No such user.' });
  res.render('admin-user-files', { target: user, images: listUserImages.all(user.id) });
});

router.get('/admin/users/:id/files/:token', requireAdmin, async (req, res) => {
  const image = db.prepare(
    'SELECT i.* FROM images i WHERE i.owner_id = ? AND i.token = ? AND i.deleted_at IS NULL'
  ).get(req.params.id, req.params.token);
  if (!image) return res.status(404).end();
  try { await storage.send(res, image); } catch { res.status(404).end(); }
});

router.post('/admin/users/:id/files/:token/delete', requireAdmin, verifyCsrf, async (req, res) => {
  const user = getUser.get(req.params.id);
  const image = getUserImage.get(req.params.id, req.params.token);
  if (user && image) {
    try {
      await storage.remove(image);
      softDeleteUserImage.run(Date.now(), image.id, user.id);
      audit.record(req.user, 'admin_delete_file', `${image.token} owned by ${user.username} (#${user.id})`);
    } catch {
      return res.status(500).render('error', { title: 'Delete error', message: 'The file could not be deleted.' });
    }
  }
  res.redirect(`/admin/users/${encodeURIComponent(req.params.id)}/files`);
});

router.post('/admin/users/:id/files/delete-all', requireAdmin, verifyCsrf, async (req, res) => {
  const user = getUser.get(req.params.id);
  if (!user) return res.status(404).render('error', { title: 'Not found', message: 'No such user.' });
  const images = listUserImages.all(user.id);
  try {
    for (const image of images) {
      await storage.remove(image);
      softDeleteUserImage.run(Date.now(), image.id, user.id);
    }
    if (images.length) audit.record(req.user, 'admin_delete_all_files', `${images.length} files owned by ${user.username} (#${user.id})`);
  } catch {
    return res.status(500).render('error', { title: 'Delete error', message: 'One or more files could not be deleted.' });
  }
  res.redirect(`/admin/users/${encodeURIComponent(req.params.id)}/files`);
});

router.get('/admin/reports/:id/proof', requireAdmin, (req, res) => {
  const report = getReport.get(req.params.id);
  if (!report) return res.status(404).end();
  const proofPath = path.join(config.reportDir, report.proof_storage_name);
  if (!fs.existsSync(proofPath)) return res.status(404).end();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', report.proof_mime);
  res.setHeader('Content-Disposition', 'inline');
  fs.createReadStream(proofPath).pipe(res);
});

router.get('/admin/reports/:id/proof/:proofId', requireAdmin, (req, res) => {
  const proof = db.prepare(
    'SELECT storage_name, mime FROM leak_report_proofs WHERE id = ? AND report_id = ?'
  ).get(req.params.proofId, req.params.id);
  if (!proof) return res.status(404).end();
  const proofPath = path.join(config.reportDir, proof.storage_name);
  if (!fs.existsSync(proofPath)) return res.status(404).end();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', proof.mime);
  res.setHeader('Content-Disposition', 'inline');
  fs.createReadStream(proofPath).pipe(res);
});

router.post('/admin/reports/:id/status', requireAdmin, verifyCsrf, (req, res) => {
  const report = getReport.get(req.params.id);
  const status = ['open', 'reviewed', 'dismissed'].includes(req.body.status) ? req.body.status : null;
  if (report && status) {
    updateReport.run(status, Date.now(), req.user.id, (req.body.admin_note || '').slice(0, 1000) || null, report.id);
    audit.record(req.user, 'report_' + status, `report #${report.id} image ${report.image_id}`);
  }
  res.redirect('/admin/reports');
});

router.post('/admin/users/:id/approve', requireAdmin, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  if (u && u.status === 'pending') {
    setStatus.run('approved', Date.now(), req.user.id, u.id);
    audit.record(req.user, 'approve_user', `${u.username} <${u.email}> (#${u.id})`);
    notify.sendSignupStatus(u, 'approved').catch(() => {});
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/reject', requireAdmin, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  if (u && u.id !== req.user.id && u.rank !== 'owner') {
    setStatus.run('rejected', null, req.user.id, u.id);
    audit.record(req.user, 'reject_user', `${u.username} <${u.email}> (#${u.id})`);
    notify.sendSignupStatus(u, 'rejected').catch(() => {});
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/rank', requireAdmin, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  const rank = ['user', 'trusted'].includes(req.body.rank) ? req.body.rank : null;
  if (u && rank) {
    setRank.run(rank, u.id);
    audit.record(req.user, 'set_user_rank', `${u.username} (#${u.id}) -> ${rank}`);
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/promote', requireOwner, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  if (u && u.status === 'approved') {
    setRole.run('admin', u.id);
    audit.record(req.user, 'promote_admin', `${u.username} (#${u.id})`);
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/demote', requireOwner, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  // Never let an admin demote themselves (avoid locking out the last admin).
  if (u && u.id !== req.user.id) {
    setRole.run('user', u.id);
    audit.record(req.user, 'demote_admin', `${u.username} (#${u.id})`);
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/limits', requireAdmin, verifyCsrf, (req, res) => {
  const user = getUser.get(req.params.id);
  if (user) {
    const parseMb = (value, max) => {
      if (value === undefined || value === '') return null;
      const mb = Number(value);
      return Number.isInteger(mb) && mb > 0 && mb <= max ? mb * 1024 * 1024 : null;
    };
    const uploadMb = parseMb(req.body.upload_max_mb, Math.floor(config.maxUploadBytesHard / 1024 / 1024));
    const storageMb = parseMb(req.body.storage_limit_mb, 1024 * 1024);
    const uploadInvalid = req.body.upload_max_mb !== '' && uploadMb === null;
    const storageInvalid = req.body.storage_limit_mb !== '' && storageMb === null;
    if (!uploadInvalid && !storageInvalid) {
      setUserLimits.run(uploadMb, storageMb, user.id);
      audit.record(req.user, 'set_user_limits', `${user.username} (#${user.id}) upload=${uploadMb ? uploadMb / 1048576 + 'MB' : 'default'} storage=${storageMb ? storageMb / 1048576 + 'MB' : 'default'}`);
    }
  }
  res.redirect('/admin/users');
});

// Quick account ban/unban for a user (optionally also ban their last IP / email).
router.post('/admin/users/:id/ban', requireAdmin, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  if (u && u.id !== req.user.id) {
    const expires_at = banExpiry(req.body.expires);
    bans.add({ kind: 'user', value: u.id, block_account: 1, block_view: 1, reason: req.body.reason || 'admin ban', created_by: req.user.id, expires_at });
    const extras = [];
    if (req.body.ban_ip && u.last_ip) {
      bans.add({ kind: 'ip', value: u.last_ip, block_account: 1, block_view: 1, reason: `user ${u.username} last IP`, created_by: req.user.id, expires_at });
      extras.push('ip ' + u.last_ip);
    }
    if (req.body.ban_email) {
      bans.add({ kind: 'email', value: u.email, block_account: 1, block_view: 0, reason: `user ${u.username} email`, created_by: req.user.id, expires_at });
      extras.push('email');
    }
    audit.record(req.user, 'ban_user', `${u.username} (#${u.id})${extras.length ? ' + ' + extras.join(', ') : ''}${expires_at ? ' until ' + new Date(expires_at).toISOString() : ''}`);
  }
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/unban', requireAdmin, verifyCsrf, (req, res) => {
  const u = getUser.get(req.params.id);
  if (u) {
    bans.removeMatching('user', u.id);
    audit.record(req.user, 'unban_user', `${u.username} (#${u.id})`);
  }
  res.redirect('/admin/users');
});

// General ban management.
router.post('/admin/bans', requireAdmin, verifyCsrf, (req, res) => {
  const kind = req.body.kind;
  const value = (req.body.value || '').trim();
  const blockAccount = req.body.block_account ? 1 : 0;
  const blockView = req.body.block_view ? 1 : 0;
  if (['ip', 'email', 'user'].includes(kind) && value && (blockAccount || blockView)) {
    const expires_at = banExpiry(req.body.expires);
    bans.add({
      kind,
      value: kind === 'email' ? value.toLowerCase() : value,
      block_account: blockAccount,
      block_view: blockView,
      reason: (req.body.reason || '').slice(0, 300) || null,
      created_by: req.user.id,
      expires_at,
    });
    audit.record(req.user, 'add_ban', `${kind} ${value}${blockView ? ' [view]' : ''}${blockAccount ? ' [account]' : ''}${expires_at ? ' until ' + new Date(expires_at).toISOString() : ''}`);
  }
  res.redirect('/admin/bans');
});

router.post('/admin/bans/:id/delete', requireAdmin, verifyCsrf, (req, res) => {
  bans.remove(req.params.id);
  audit.record(req.user, 'remove_ban', `#${req.params.id}`);
  res.redirect('/admin/bans');
});

module.exports = router;
