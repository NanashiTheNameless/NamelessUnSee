'use strict';

// Shared access-log reader used by both the owner's log page and the admin's.
// Both views show the same rows; only the surrounding page differs.

const db = require('./db');
const config = require('./config');

const PAGE_SIZE = 50;

const SEARCH_WHERE =
  '(ip LIKE @like OR ip_country LIKE @like OR user_agent LIKE @like OR geo_json LIKE @like OR client_json LIKE @like OR blocked_reason LIKE @like)';

const countAll = db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?');
const pageAll = db.prepare(
  `SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
   FROM access_logs a WHERE a.image_id = ? ORDER BY a.viewed_at DESC LIMIT ? OFFSET ?`
);
const countSearch = db.prepare(
  `SELECT COUNT(*) AS n FROM access_logs WHERE image_id = @image_id AND ${SEARCH_WHERE}`
);
const pageSearch = db.prepare(
  `SELECT a.*, EXISTS(SELECT 1 FROM leak_reports r WHERE r.access_log_id = a.id) AS reported
   FROM access_logs a WHERE a.image_id = @image_id AND ${SEARCH_WHERE}
   ORDER BY a.viewed_at DESC LIMIT @limit OFFSET @offset`
);

function safeParse(s) {
  try {
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

function retentionMs() {
  return Math.max(0, config.logRetentionAfterDeleteHours) * 3600 * 1000;
}

/** Oldest deletion time whose logs are still retained. */
function retentionCutoff(now = Date.now()) {
  return now - retentionMs();
}

/** When this image's logs disappear, or null while the image is still live. */
function retainedUntil(image) {
  return image && image.deleted_at ? image.deleted_at + retentionMs() : null;
}

/** One page of an image's access log, ready to hand to the logs template. */
function readPage(imageId, { q = '', page = 1 } = {}) {
  const current = Math.max(1, parseInt(page, 10) || 1);
  const offset = (current - 1) * PAGE_SIZE;

  let total;
  let rows;
  if (q) {
    const like = '%' + q + '%';
    total = countSearch.get({ image_id: imageId, like }).n;
    rows = pageSearch.all({ image_id: imageId, like, limit: PAGE_SIZE, offset });
  } else {
    total = countAll.get(imageId).n;
    rows = pageAll.all(imageId, PAGE_SIZE, offset);
  }

  return {
    logs: rows.map((r) => ({
      ...r,
      device: safeParse(r.device_json),
      geo: safeParse(r.geo_json),
      headers: safeParse(r.headers_json),
      client: safeParse(r.client_json),
    })),
    total,
    page: current,
    pageSize: PAGE_SIZE,
    totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
  };
}

// Logs outlive their image by the retention window, then go. A leak report may
// still point at one of these rows, so the reference is cleared first- the
// report itself (with its proof files and text) is kept.
const expiredLogImages = db.prepare(
  'SELECT id FROM images WHERE deleted_at IS NOT NULL AND deleted_at <= ?'
);
const detachReports = db.prepare(
  `UPDATE leak_reports SET access_log_id = NULL
   WHERE access_log_id IN (SELECT id FROM access_logs WHERE image_id = ?)`
);
const deleteLogsForImage = db.prepare('DELETE FROM access_logs WHERE image_id = ?');

const openReportsCiting = db.prepare(
  `SELECT COUNT(*) AS n FROM leak_reports
   WHERE status = 'open' AND access_log_id IN (SELECT id FROM access_logs WHERE image_id = ?)`
);

/** How many open leak reports still cite an entry of this image's log. */
function openReportCount(imageId) {
  return openReportsCiting.get(imageId).n;
}

/**
 * Erase an image's whole access log ahead of the retention window. Refuses
 * while an open leak report cites one of the entries- that evidence trail has
 * to be resolved first. Resolved reports survive with their reference cleared.
 * Returns { erased } or { blocked: <open report count> }.
 */
function eraseForImage(imageId) {
  const open = openReportCount(imageId);
  if (open) return { blocked: open };
  let erased = 0;
  db.transaction(() => {
    detachReports.run(imageId);
    erased = deleteLogsForImage.run(imageId).changes;
  })();
  return { erased };
}

// An image whose owner deleted their account is left behind on purpose, so its
// log can age out normally. Once that log is gone the record has no reader and
// no owner, so it goes too.
const dropOrphanedImages = db.prepare(
  `DELETE FROM images
   WHERE owner_id IS NULL AND deleted_at IS NOT NULL AND deleted_at <= ?
     AND NOT EXISTS (SELECT 1 FROM access_logs a WHERE a.image_id = images.id)`
);

/** Delete the logs of images deleted longer ago than the retention window. */
function purgeExpired(now = Date.now()) {
  const cutoff = retentionCutoff(now);
  let removed = 0;
  const tx = db.transaction((imageId) => {
    detachReports.run(imageId);
    removed += deleteLogsForImage.run(imageId).changes;
  });
  for (const row of expiredLogImages.all(cutoff)) tx(row.id);
  dropOrphanedImages.run(cutoff);
  return removed;
}

module.exports = {
  readPage,
  purgeExpired,
  eraseForImage,
  openReportCount,
  retainedUntil,
  retentionCutoff,
  retentionMs,
  safeParse,
  PAGE_SIZE,
};
