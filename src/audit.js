'use strict';

const { getDatabase } = require('./db-runtime');

async function record(actor, action, detail, targetId = null, notes = {}) {
  try {
    await (await getDatabase()).run(
      `INSERT INTO audit_log (actor_id, actor_name, action, detail, target_id, note, internal_note, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [actor ? actor.id : null, actor ? actor.username : null, String(action).slice(0, 60),
        detail ? String(detail).slice(0, 500) : null, targetId ? String(targetId) : null,
        notes.note ? String(notes.note).slice(0, 1000) : null,
        notes.internalNote ? String(notes.internalNote).slice(0, 1000) : null, Date.now()]
    );
  } catch { /* auditing must never break the action */ }
}

async function list(limit = 50, offset = 0) {
  return (await getDatabase()).all('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, offset]);
}
async function count() { return (await getDatabase()).get('SELECT COUNT(*) AS n FROM audit_log').then((row) => row.n); }
async function clear() { return (await getDatabase()).run('DELETE FROM audit_log').then((result) => result.changes); }
async function remove(id) { return (await getDatabase()).run('DELETE FROM audit_log WHERE id = ?', [id]).then((result) => result.changes); }

module.exports = { record, list, count, clear, remove };
