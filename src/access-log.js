'use strict';

const { getDatabase } = require('./db-runtime');
const config = require('./config');

const PAGE_SIZE = 50;
const SEARCH_WHERE = '(ip LIKE @like OR ip_country LIKE @like OR user_agent LIKE @like OR geo_json LIKE @like OR client_json LIKE @like OR blocked_reason LIKE @like)';

function safeParse(value) {
  try { return value ? JSON.parse(value) : null; } catch { return null; }
}
function retentionMs() { return Math.max(0, config.logRetentionAfterDeleteHours) * 3600 * 1000; }
function retentionCutoff(now = Date.now()) { return now - retentionMs(); }
function retainedUntil(image) { return image && image.deleted_at ? image.deleted_at + retentionMs() : null; }

async function readPage(imageId, { q = '', page = 1 } = {}) {
  const db = await getDatabase();
  const current = Math.max(1, parseInt(page, 10) || 1);
  const offset = (current - 1) * PAGE_SIZE;
  let totalRow, rows;
  if (q) {
    const like = `%${q}%`;
    totalRow = await db.get(`SELECT COUNT(*) AS n FROM access_logs WHERE image_id = @image_id AND ${SEARCH_WHERE}`, { image_id: imageId, like });
    rows = await db.all(`SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
      FROM access_logs a WHERE a.image_id = @image_id AND ${SEARCH_WHERE}
      ORDER BY a.viewed_at DESC LIMIT @limit OFFSET @offset`, { image_id: imageId, like, limit: PAGE_SIZE, offset });
  } else {
    totalRow = await db.get('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?', [imageId]);
    rows = await db.all(`SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
      FROM access_logs a WHERE a.image_id = ? ORDER BY a.viewed_at DESC LIMIT ? OFFSET ?`, [imageId, PAGE_SIZE, offset]);
  }
  const total = Number(totalRow.n || 0);
  return { logs: rows.map((row) => ({ ...row, device: safeParse(row.device_json), geo: safeParse(row.geo_json), headers: safeParse(row.headers_json), client: safeParse(row.client_json) })), total, page: current, pageSize: PAGE_SIZE, totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)) };
}

async function openReportCount(imageId) {
  const row = await (await getDatabase()).get(`SELECT COUNT(*) AS n FROM leak_reports WHERE status = 'open' AND access_log_id IN (SELECT id FROM access_logs WHERE image_id = ?)`, [imageId]);
  return Number(row.n || 0);
}

async function eraseForImage(imageId) {
  const open = await openReportCount(imageId);
  if (open) return { blocked: open };
  const result = await (await getDatabase()).batch([
    { sql: 'UPDATE leak_reports SET access_log_id = NULL WHERE access_log_id IN (SELECT id FROM access_logs WHERE image_id = ?)', args: [imageId] },
    { sql: 'DELETE FROM access_logs WHERE image_id = ?', args: [imageId] },
  ]);
  return { erased: Number(result[1] && result[1].changes || 0) };
}

async function purgeExpired(now = Date.now()) {
  const db = await getDatabase();
  const cutoff = retentionCutoff(now);
  const expired = await db.all('SELECT id FROM images WHERE deleted_at IS NOT NULL AND deleted_at <= ?', [cutoff]);
  let removed = 0;
  for (const image of expired) {
    const result = await db.batch([
      { sql: 'UPDATE leak_reports SET access_log_id = NULL WHERE access_log_id IN (SELECT id FROM access_logs WHERE image_id = ?)', args: [image.id] },
      { sql: 'DELETE FROM access_logs WHERE image_id = ?', args: [image.id] },
    ]);
    removed += Number(result[1] && result[1].changes || 0);
  }
  await db.run(`DELETE FROM images WHERE owner_id IS NULL AND deleted_at IS NOT NULL AND deleted_at <= ?
    AND NOT EXISTS (SELECT 1 FROM access_logs a WHERE a.image_id = images.id)`, [cutoff]);
  return removed;
}

module.exports = { readPage, purgeExpired, eraseForImage, openReportCount, retainedUntil, retentionCutoff, retentionMs, safeParse, PAGE_SIZE };
