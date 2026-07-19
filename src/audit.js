'use strict';

const db = require('./db');

const insert = db.prepare(
  `INSERT INTO audit_log (actor_id, actor_name, action, detail, created_at)
   VALUES (@actor_id, @actor_name, @action, @detail, @created_at)`
);
const recent = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?');
const countAll = db.prepare('SELECT COUNT(*) AS n FROM audit_log');
const deleteAll = db.prepare('DELETE FROM audit_log');
const deleteOne = db.prepare('DELETE FROM audit_log WHERE id = ?');

// Record an administrative action. `actor` is req.user; never throws.
function record(actor, action, detail) {
  try {
    insert.run({
      actor_id: actor ? actor.id : null,
      actor_name: actor ? actor.username : null,
      action: String(action).slice(0, 60),
      detail: detail ? String(detail).slice(0, 500) : null,
      created_at: Date.now(),
    });
  } catch { /* auditing must never break the action */ }
}

function list(limit = 50, offset = 0) {
  return recent.all(limit, offset);
}
function count() {
  return countAll.get().n;
}

function clear() {
  return deleteAll.run().changes;
}

function remove(id) {
  return deleteOne.run(id).changes;
}

module.exports = { record, list, count, clear, remove };
