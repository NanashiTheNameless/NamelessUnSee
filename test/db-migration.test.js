'use strict';

// Boots src/db.js against a database written in the old shape, in a child
// process, because the module binds to one database path per process.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { test } = require('node:test');
const assert = require('node:assert');
const Database = require('better-sqlite3');

const ROOT = path.join(__dirname, '..');

function seedLegacyDb(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const db = new Database(path.join(dir, 'namelessunsee.sqlite'));
  db.pragma('foreign_keys = ON');
  db.exec(`
CREATE TABLE users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, approved_at INTEGER,
  approved_by TEXT REFERENCES users(id)
);
CREATE TABLE images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  storage_name TEXT NOT NULL, mime TEXT NOT NULL,
  width INTEGER, height INTEGER, byte_size INTEGER, title TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER, deleted_at INTEGER
);
CREATE TABLE access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  view_id TEXT, viewed_at INTEGER NOT NULL, ip TEXT
);
CREATE INDEX idx_images_owner ON images(owner_id);
`);
  const now = Date.now();
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at)
     VALUES ('u-legacy', 'legacy@test.invalid', 'legacyuser', 'x', 'user', 'approved', ?)`
  ).run(now);
  db.prepare(
    `INSERT INTO images (token, owner_id, storage_name, mime, created_at)
     VALUES ('legacytoken', 'u-legacy', 'legacy.png', 'image/png', ?)`
  ).run(now);
  db.prepare("INSERT INTO access_logs (image_id, view_id, viewed_at, ip) VALUES (1, 'v1', ?, '203.0.113.5')").run(now);
  db.close();
}

// Boot the real db module against that database, then report on the result.
const PROBE = `
  const db = require(${JSON.stringify(path.join(ROOT, 'src', 'db.js'))});
  const imagesSql = db.prepare("SELECT sql FROM sqlite_master WHERE name = 'images'").get().sql;
  const logsSql = db.prepare("SELECT sql FROM sqlite_master WHERE name = 'access_logs'").get().sql;
  db.prepare("INSERT INTO access_logs (image_id, view_id, viewed_at, ip) VALUES (1, 'v2', ?, '198.51.100.6')").run(Date.now());
  db.prepare("DELETE FROM users WHERE id = 'u-legacy'").run();
  process.stdout.write(JSON.stringify({
    imagesSql,
    logsSql,
    brokenKeys: db.pragma('foreign_key_check').length,
    images: db.prepare('SELECT COUNT(*) AS n FROM images').get().n,
    orphanOwner: db.prepare("SELECT owner_id FROM images WHERE token = 'legacytoken'").get().owner_id,
    logs: db.prepare('SELECT COUNT(*) AS n FROM access_logs').get().n,
    ownerIndex: !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_images_owner'").get(),
  }));
`;

// Exactly what a database looks like after the earlier, broken rebuild shipped:
// the rename rewrote access_logs' foreign key to the temp table, which was then
// dropped. Reads still work; every write dies with "no such table".
function corruptLegacyDb(dir) {
  const db = new Database(path.join(dir, 'namelessunsee.sqlite'));
  // The rebuild as it originally shipped: no legacy_alter_table, so the rename
  // silently rewrites access_logs' foreign key to the table we then drop.
  const schema = db.prepare("SELECT sql FROM sqlite_master WHERE name = 'images'").get().sql;
  const cols = db.prepare('PRAGMA table_info(images)').all().map((c) => `"${c.name}"`).join(', ');
  const createSql = schema.replace(
    /owner_id(\s+TEXT)?\s+NOT NULL\s+REFERENCES users\(id\)\s+ON DELETE CASCADE/i,
    'owner_id TEXT REFERENCES users(id) ON DELETE SET NULL'
  );
  db.pragma('foreign_keys = OFF');
  db.exec('ALTER TABLE images RENAME TO __images_cascade_old');
  db.exec(createSql);
  db.exec(`INSERT INTO images (${cols}) SELECT ${cols} FROM __images_cascade_old`);
  db.exec('DROP TABLE __images_cascade_old');
  db.close();
}

test('a database left with a dangling reference by the earlier rebuild is repaired on boot', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-repair-'));
  seedLegacyDb(dir);
  corruptLegacyDb(dir);

  // Confirm the fixture really is broken the way production was.
  const before = new Database(path.join(dir, 'namelessunsee.sqlite'));
  assert.match(
    before.prepare("SELECT sql FROM sqlite_master WHERE name = 'access_logs'").get().sql,
    /__images_cascade_old/,
    'fixture reproduces the corruption'
  );
  assert.throws(
    () => before.prepare("INSERT INTO access_logs (image_id, view_id, viewed_at, ip) VALUES (1,'x',1,'1.1.1.1')").run(),
    /no such table: main\.__images_cascade_old/,
    'fixture fails exactly as production did'
  );
  before.close();

  const out = execFileSync(process.execPath, ['-e', PROBE], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, DATA_DIR: dir, COOKIE_SECRET: 'test-' + 'x'.repeat(40), RESEND_API_KEY: '' },
  });
  const result = JSON.parse(out);

  assert.match(result.logsSql, /REFERENCES\s+"?images"?\(id\)/i, 'the reference was pointed back at images');
  assert.doesNotMatch(result.logsSql, /__images_cascade_old/, 'no trace of the temp table is left');
  assert.equal(result.brokenKeys, 0, 'the database is consistent again');
  assert.equal(result.logs, 2, 'existing log rows survived and writes work again');
  assert.equal(result.images, 1, 'image rows survived');
});

test('a legacy database is rebuilt without breaking the keys that point at images', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-migrate-'));
  seedLegacyDb(dir);

  const out = execFileSync(process.execPath, ['-e', PROBE], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      DATA_DIR: dir,
      COOKIE_SECRET: 'test-' + 'x'.repeat(40),
      RESEND_API_KEY: '',
    },
  });
  const result = JSON.parse(out);

  // The point of the rebuild: images may now be orphaned instead of cascaded.
  assert.match(result.imagesSql, /owner_id[^,]*ON DELETE SET NULL/i, 'images was rebuilt');
  assert.doesNotMatch(result.imagesSql, /owner_id[^,]*NOT NULL/i, 'owner_id became nullable');

  // The trap: renaming a table rewrites references to it elsewhere.
  assert.match(result.logsSql, /REFERENCES\s+"?images"?\(id\)/i, 'access_logs still points at images');
  assert.equal(result.brokenKeys, 0, 'no dangling foreign keys survived the rebuild');

  assert.equal(result.images, 1, 'existing rows were carried over');
  assert.equal(result.logs, 2, 'writes to access_logs still work, and old rows are intact');
  assert.equal(result.orphanOwner, null, 'deleting the account detaches the image instead of erasing it');
  assert.ok(result.ownerIndex, 'indexes were recreated');
});
