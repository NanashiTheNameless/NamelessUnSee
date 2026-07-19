'use strict';

const db = require('./db');
const { parseIp, normalizeIp, RangeSet } = require('./util/ip');

const insert = db.prepare(
  `INSERT INTO bans (kind, value, block_account, block_view, reason, created_at, created_by, expires_at)
   VALUES (@kind, @value, @block_account, @block_view, @reason, @created_at, @created_by, @expires_at)`
);
const del = db.prepare('DELETE FROM bans WHERE id = ?');
const delWhere = db.prepare('DELETE FROM bans WHERE kind = ? AND value = ?');
const delExpired = db.prepare('DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?');
const all = db.prepare('SELECT * FROM bans ORDER BY created_at DESC');

// In-memory indexes, rebuilt whenever bans change.
const idx = {
  viewExact: new Set(),
  viewRanges: new RangeSet().finalize(),
  acctExact: new Set(),
  acctRanges: new RangeSet().finalize(),
  emails: new Map(), // email -> { account, view }
  users: new Map(), // userId(string) -> { account, view }
};

function load() {
  const viewExact = new Set();
  const acctExact = new Set();
  const viewRanges = new RangeSet();
  const acctRanges = new RangeSet();
  const emails = new Map();
  const users = new Map();

  const now = Date.now();
  for (const b of all.all()) {
    if (b.expires_at && b.expires_at <= now) continue; // expired: don't index
    const acct = !!b.block_account;
    const view = !!b.block_view;
    if (b.kind === 'ip') {
      const val = b.value.trim();
      if (val.includes('/')) {
        if (view) viewRanges.addCidr(val);
        if (acct) acctRanges.addCidr(val);
      } else {
        const norm = normalizeIp(val) || val;
        if (view) viewExact.add(norm);
        if (acct) acctExact.add(norm);
      }
    } else if (b.kind === 'email') {
      const e = b.value.trim().toLowerCase();
      const prev = emails.get(e) || { account: false, view: false };
      emails.set(e, { account: prev.account || acct, view: prev.view || view });
    } else if (b.kind === 'user') {
      const u = String(b.value);
      const prev = users.get(u) || { account: false, view: false };
      users.set(u, { account: prev.account || acct, view: prev.view || view });
    }
  }

  idx.viewExact = viewExact;
  idx.acctExact = acctExact;
  idx.viewRanges = viewRanges.finalize();
  idx.acctRanges = acctRanges.finalize();
  idx.emails = emails;
  idx.users = users;
}

function ipMatches(ip, exact, ranges) {
  if (!ip) return false;
  const norm = normalizeIp(ip);
  if (norm && exact.has(norm)) return true;
  const p = parseIp(ip);
  if (p && p.version === 4 && ranges.size && ranges.contains(p.value)) return true;
  return false;
}

function isViewBannedIp(ip) {
  return ipMatches(ip, idx.viewExact, idx.viewRanges);
}
function isAccountBannedIp(ip) {
  return ipMatches(ip, idx.acctExact, idx.acctRanges);
}
function emailBan(email) {
  return idx.emails.get(String(email || '').trim().toLowerCase()) || { account: false, view: false };
}
function userBan(userId) {
  return idx.users.get(String(userId)) || { account: false, view: false };
}

function add(ban) {
  insert.run({
    kind: ban.kind,
    value: String(ban.value).trim(),
    block_account: ban.block_account ? 1 : 0,
    block_view: ban.block_view ? 1 : 0,
    reason: ban.reason || null,
    created_at: Date.now(),
    created_by: ban.created_by || null,
    expires_at: ban.expires_at || null,
  });
  load();
}

// Delete expired bans from the table and rebuild the index. Returns count removed.
function sweepExpired() {
  const info = delExpired.run(Date.now());
  if (info.changes) load();
  return info.changes;
}
function remove(id) {
  del.run(id);
  load();
}
function removeMatching(kind, value) {
  delWhere.run(kind, String(value).trim());
  load();
}
function list() {
  return all.all();
}

load();

module.exports = {
  isViewBannedIp,
  isAccountBannedIp,
  emailBan,
  userBan,
  add,
  remove,
  removeMatching,
  sweepExpired,
  list,
  reload: load,
};
