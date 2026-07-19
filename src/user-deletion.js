'use strict';

const fs = require('fs');
const db = require('./db');
const config = require('./config');
const storage = require('./storage');
const { beneath } = require('./util/safe-path');

const listUserImages = db.prepare('SELECT * FROM images WHERE owner_id = ? AND deleted_at IS NULL ORDER BY created_at DESC');
const listUserProofFiles = db.prepare(
  `SELECT p.storage_name FROM leak_report_proofs p
   JOIN leak_reports r ON r.id = p.report_id
   LEFT JOIN images i ON i.id = r.image_id
   WHERE r.reporter_id = ? OR i.owner_id = ?
   UNION
   SELECT r.proof_storage_name FROM leak_reports r
   LEFT JOIN images i ON i.id = r.image_id
   WHERE r.reporter_id = ? OR i.owner_id = ?`
);

// Rows that reference users without ON DELETE CASCADE must be nulled before the
// user row can be removed (foreign_keys is ON).
const deleteUserTx = db.transaction((id) => {
  db.prepare('UPDATE users SET approved_by = NULL WHERE approved_by = ?').run(id);
  db.prepare('UPDATE bans SET created_by = NULL WHERE created_by = ?').run(id);
  db.prepare('UPDATE phash_blocklist SET added_by = NULL WHERE added_by = ?').run(id);
  db.prepare('UPDATE audit_log SET actor_id = NULL WHERE actor_id = ?').run(id);
  db.prepare('UPDATE leak_reports SET reviewed_by = NULL WHERE reviewed_by = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
});

// Permanently delete an account: stored files, report proofs, then the user row
// (sessions, images, challenges and their reports cascade). Throws if a stored
// image cannot be removed; proof-file cleanup is best-effort.
async function deleteUserAccount(user) {
  for (const image of listUserImages.all(user.id)) await storage.remove(image);
  for (const { storage_name } of listUserProofFiles.all(user.id, user.id, user.id, user.id)) {
    if (!storage_name) continue;
    try { fs.rmSync(beneath(config.reportDir, storage_name), { force: true }); } catch {}
  }
  deleteUserTx(user.id);
}

module.exports = { deleteUserAccount };
