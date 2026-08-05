'use strict';

const { SCHEMA } = require('./db-schema');

async function bootstrapAsyncDatabase(db) {
  await db.exec(SCHEMA);
  // Existing local files (and D1 databases created from an older schema) may
  // already have the table but not the newer additive fields. SQLite/D1 have
  // no portable ADD COLUMN IF NOT EXISTS, so probe each alteration and ignore
  // only the duplicate-column response.
  const additions = [
    ['users', 'last_ip TEXT'], ['users', 'trust_until INTEGER'],
    ['images', 'phash TEXT'], ['images', "moderation_status TEXT NOT NULL DEFAULT 'ok'"],
    ['images', 'moderation_reason TEXT'], ['images', 'moderation_score REAL'],
    ['images', 'moderation_details TEXT'], ['access_logs', 'link_label TEXT'],
    ['access_logs', 'blocked_reason TEXT'], ['access_logs', 'attempts INTEGER NOT NULL DEFAULT 1'],
    ['leak_reports', 'access_log_id INTEGER REFERENCES access_logs(id)'],
  ];
  for (const [table, definition] of additions) {
    try {
      await db.execute(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
    } catch (error) {
      if (!/duplicate column|already exists/i.test(String(error && error.message))) throw error;
    }
  }
  return db;
}

module.exports = { bootstrapAsyncDatabase };
