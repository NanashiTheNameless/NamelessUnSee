'use strict';

const Database = require('better-sqlite3');
const config = require('../config');
const { createAsyncDatabase } = require('../db-async');

// Parent tables must be copied before tables containing foreign keys. Explicit
// IDs are retained so existing links, logs, and sessions remain valid.
const TABLES = [
  'users', 'sessions', 'login_challenges', 'recovery_challenges', 'images',
  'bans', 'phash_blocklist', 'audit_log', 'access_logs', 'leak_reports',
  'view_links', 'galleries', 'gallery_items', 'leak_report_proofs',
];
const BATCH_SIZE = 50;

function valueForD1(value) {
  if (Buffer.isBuffer(value)) return value.toString('base64');
  return value;
}

function statementsFor(table, columns, rows) {
  const names = columns.map((column) => `"${column}"`).join(', ');
  const placeholders = columns.map(() => '?').join(', ');
  return rows.map((row) => ({
    sql: `INSERT OR REPLACE INTO "${table}" (${names}) VALUES (${placeholders})`,
    params: columns.map((column) => valueForD1(row[column])),
  }));
}

async function migrate() {
  const local = new Database(config.dbPath, { readonly: true });
  const target = await createAsyncDatabase({
    backend: 'd1',
    d1Config: config.database.d1,
  });

  let copied = 0;
  try {
    for (const table of TABLES) {
      const columns = local.prepare(`PRAGMA table_info("${table}")`).all().map((column) => column.name);
      if (!columns.length) continue;
      const rows = local.prepare(`SELECT ${columns.map((column) => `"${column}"`).join(', ')} FROM "${table}"`).all();
      for (let offset = 0; offset < rows.length; offset += BATCH_SIZE) {
        await target.batch(statementsFor(table, columns, rows.slice(offset, offset + BATCH_SIZE)));
      }
      copied += rows.length;
      console.log(`[NamelessUnSee] migrated ${rows.length} row(s) from ${table}`);
    }
  } finally {
    local.close();
    await target.close();
  }
  console.log(`[NamelessUnSee] D1 migration complete: ${copied} row(s) copied from ${config.dbPath}`);
}

migrate().catch((error) => {
  console.error(`[NamelessUnSee] D1 migration failed: ${error.message}`);
  process.exitCode = 1;
});
