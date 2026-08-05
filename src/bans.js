'use strict';

const { getDatabase } = require('./db-runtime');
const { parseIp, normalizeIp, RangeSet } = require('./util/ip');

const idx = {
  viewExact: new Set(), viewRanges: new RangeSet().finalize(),
  acctExact: new Set(), acctRanges: new RangeSet().finalize(),
  emails: new Map(), users: new Map(),
};
let loaded;

function applyRows(rows) {
  const viewExact = new Set(), acctExact = new Set();
  const viewRanges = new RangeSet(), acctRanges = new RangeSet();
  const emails = new Map(), users = new Map();
  const now = Date.now();
  for (const b of rows) {
    if (b.expires_at && b.expires_at <= now) continue;
    const acct = !!b.block_account, view = !!b.block_view;
    if (b.kind === 'ip') {
      const value = b.value.trim();
      if (value.includes('/')) {
        if (view) viewRanges.addCidr(value);
        if (acct) acctRanges.addCidr(value);
      } else {
        const norm = normalizeIp(value) || value;
        if (view) viewExact.add(norm);
        if (acct) acctExact.add(norm);
      }
    } else if (b.kind === 'email') {
      const key = b.value.trim().toLowerCase();
      const prev = emails.get(key) || { account: false, view: false };
      emails.set(key, { account: prev.account || acct, view: prev.view || view });
    } else if (b.kind === 'user') {
      const key = String(b.value);
      const prev = users.get(key) || { account: false, view: false };
      users.set(key, { account: prev.account || acct, view: prev.view || view });
    }
  }
  idx.viewExact = viewExact; idx.acctExact = acctExact;
  idx.viewRanges = viewRanges.finalize(); idx.acctRanges = acctRanges.finalize();
  idx.emails = emails; idx.users = users;
}

async function load() {
  if (!loaded) {
    loaded = (async () => {
      const db = await getDatabase();
      const rows = await db.all('SELECT * FROM bans ORDER BY created_at DESC');
      applyRows(rows);
    })().catch((error) => { loaded = undefined; throw error; });
  }
  return loaded;
}

function ipMatches(ip, exact, ranges) {
  if (!ip) return false;
  const norm = normalizeIp(ip);
  if (norm && exact.has(norm)) return true;
  const parsed = parseIp(ip);
  return !!(parsed && parsed.version === 4 && ranges.size && ranges.contains(parsed.value));
}

function isViewBannedIp(ip) { return load().then(() => ipMatches(ip, idx.viewExact, idx.viewRanges)); }
function isAccountBannedIp(ip) { return load().then(() => ipMatches(ip, idx.acctExact, idx.acctRanges)); }
function emailBan(email) { const read = () => idx.emails.get(String(email || '').trim().toLowerCase()) || { account: false, view: false }; return load().then(read); }
function userBan(userId) { const read = () => idx.users.get(String(userId)) || { account: false, view: false }; return load().then(read); }

function reload() { loaded = undefined; return load(); }

function add(ban) {
  return (async () => {
  const db = await getDatabase();
  await db.run(
    `INSERT INTO bans (kind, value, block_account, block_view, reason, created_at, created_by, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [ban.kind, String(ban.value).trim(), ban.block_account ? 1 : 0, ban.block_view ? 1 : 0,
      ban.reason || null, Date.now(), ban.created_by || null, ban.expires_at || null]
  );
  await reload();
  })();
}

function sweepExpired() {
  return (async () => {
    const db = await getDatabase();
    const result = await db.run('DELETE FROM bans WHERE expires_at IS NOT NULL AND expires_at <= ?', [Date.now()]);
    if (result.changes) await reload();
    return result.changes;
  })();
}

function remove(id) {
  return (async () => {
    await (await getDatabase()).run('DELETE FROM bans WHERE id = ?', [id]);
    await reload();
  })();
}

function removeMatching(kind, value) {
  return (async () => {
    await (await getDatabase()).run('DELETE FROM bans WHERE kind = ? AND value = ?', [kind, String(value).trim()]);
    await reload();
  })();
}

async function list() {
  return (await getDatabase()).all('SELECT * FROM bans ORDER BY created_at DESC');
}

module.exports = { isViewBannedIp, isAccountBannedIp, emailBan, userBan, add, remove, removeMatching, sweepExpired, list, reload };
