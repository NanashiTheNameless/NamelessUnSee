'use strict';

const fs = require('fs');
const { getDatabase } = require('./db-runtime');
const config = require('./config');
const storage = require('./storage');
const { beneath } = require('./util/safe-path');

/**
 * Permanently delete an account. Stored files- uploads and report proofs- are
 * erased immediately, and the user row goes with everything that cascades from
 * it (sessions, challenges, reports). The image records themselves are marked
 * deleted and left behind, orphaned, so their access logs age out on the normal
 * retention schedule instead of vanishing with the account; the retention sweep
 * collects both once the window closes.
 * Throws if a stored image cannot be removed; proof cleanup is best-effort.
 */
async function deleteUserAccount(user) {
  const db = await getDatabase();
  const images = await db.all('SELECT * FROM images WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC', [user.id]);
  for (const image of images) await storage.remove(image);
  const proofFiles = await db.all(
    `SELECT p.storage_name FROM leak_report_proofs p
     JOIN leak_reports r ON r.id = p.report_id
     LEFT JOIN images i ON i.id = r.image_id
     WHERE r.reporter_id = ? OR i.owner_id = ?
     UNION
     SELECT r.proof_storage_name FROM leak_reports r
     LEFT JOIN images i ON i.id = r.image_id
     WHERE r.reporter_id = ? OR i.owner_id = ?`,
    [user.id, user.id, user.id, user.id]
  );
  for (const { storage_name } of proofFiles) {
    if (!storage_name) continue;
    try { fs.rmSync(beneath(config.reportDir, storage_name), { force: true }); } catch {}
  }
  const now = Date.now();
  await db.batch([
    { sql: 'UPDATE images SET deleted_at = ? WHERE owner_id = ? AND deleted_at IS NULL', args: [now, user.id] },
    { sql: 'UPDATE users SET approved_by = NULL WHERE approved_by = ?', args: [user.id] },
    { sql: 'UPDATE bans SET created_by = NULL WHERE created_by = ?', args: [user.id] },
    { sql: 'UPDATE phash_blocklist SET added_by = NULL WHERE added_by = ?', args: [user.id] },
    { sql: 'UPDATE audit_log SET actor_id = NULL WHERE actor_id = ?', args: [user.id] },
    { sql: 'UPDATE leak_reports SET reviewed_by = NULL WHERE reviewed_by = ?', args: [user.id] },
    { sql: 'DELETE FROM users WHERE id = ?', args: [user.id] },
  ]);
}

module.exports = { deleteUserAccount };
