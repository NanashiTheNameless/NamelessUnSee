'use strict';

const Database = require('better-sqlite3');
const config = require('./config');
const { uuidv7 } = require('./util/crypto');

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',     -- 'user' | 'admin'
  rank          TEXT NOT NULL DEFAULT 'user',     -- 'user' | 'trusted' | 'owner'
  status        TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'rejected'
  email_verified INTEGER NOT NULL DEFAULT 1,
  signup_reason TEXT,
  decision_note TEXT,          -- last decision message sent to this user
  decision_internal_note TEXT, -- last decision note for administrators only
  created_at    INTEGER NOT NULL,
  approved_at   INTEGER,
  approved_by   TEXT REFERENCES users(id)
  ,twofa_mode   TEXT NOT NULL DEFAULT 'email'
  ,totp_secret  TEXT
  ,totp_pending_secret TEXT
  ,totp_enabled INTEGER NOT NULL DEFAULT 0
  ,totp_last_counter INTEGER
  ,default_ttl TEXT NOT NULL DEFAULT '24h'
  ,default_timer_start TEXT NOT NULL DEFAULT 'first_view'
  ,default_max_views INTEGER
  ,upload_max_bytes INTEGER
  ,storage_limit_bytes INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,           -- random token (also the cookie value)
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_challenges (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method      TEXT NOT NULL, -- 'email' | 'totp'
  code_hash   TEXT,
  csrf_token  TEXT NOT NULL,
  next_url    TEXT NOT NULL DEFAULT '/dashboard',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  resend_count INTEGER NOT NULL DEFAULT 0,
  last_sent_at INTEGER,
  resend_blocked_until INTEGER
  ,purpose    TEXT NOT NULL DEFAULT 'login' -- 'login' | 'account_delete'
);

CREATE TABLE IF NOT EXISTS recovery_challenges (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL, -- 'password' | 'email' | 'account_password'
  target      TEXT,
  code_hash   TEXT NOT NULL,
  csrf_token  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS images (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  token           TEXT NOT NULL UNIQUE,  -- public slug in the share URL
  -- Nullable, and detached rather than cascaded, so that deleting an account
  -- does not take the access logs of its uploads with it: the rows are orphaned
  -- and swept once the log-retention window closes.
  owner_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  storage_name    TEXT NOT NULL,         -- filename on disk (originals, never served)
  mime            TEXT NOT NULL,
  width           INTEGER,
  height          INTEGER,
  byte_size       INTEGER,
  title           TEXT,
  created_at      INTEGER NOT NULL,
  ttl_seconds     INTEGER,               -- retention duration; NULL = no time limit
  timer_start     TEXT NOT NULL DEFAULT 'first_view', -- 'first_view' | 'upload'
  max_views       INTEGER,               -- delete after this many views; NULL = unlimited
  first_viewed_at INTEGER,               -- when the retention timer actually started
  view_count      INTEGER NOT NULL DEFAULT 0,
  expires_at      INTEGER,               -- computed deletion time; NULL = not started / never
  deleted_at      INTEGER                -- soft delete / purged marker
  ,storage_backend TEXT NOT NULL DEFAULT 'local'
  ,storage_encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  kind          TEXT NOT NULL,           -- 'ip' | 'email' | 'user'
  value         TEXT NOT NULL,           -- IP/CIDR, email, or user id
  block_account INTEGER NOT NULL DEFAULT 0, -- deny signup/login
  block_view    INTEGER NOT NULL DEFAULT 0, -- deny access to the service at all
  reason        TEXT,
  created_at    INTEGER NOT NULL,
  created_by    TEXT REFERENCES users(id),
  expires_at    INTEGER                  -- NULL = permanent
);

CREATE TABLE IF NOT EXISTS phash_blocklist (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  phash      TEXT NOT NULL,
  label      TEXT,
  added_by   TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id   TEXT REFERENCES users(id),
  actor_name TEXT,
  action     TEXT NOT NULL,
  detail     TEXT,
  -- The user acted upon, when there is one. Deliberately not a foreign key: the
  -- log must survive the deletion of the account it describes.
  target_id  TEXT,
  note          TEXT,  -- message sent to the user
  internal_note TEXT,  -- administrators only; never sent
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  image_id     INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  view_id      TEXT,       -- correlates the render log with the client beacon
  viewed_at    INTEGER NOT NULL,
  ip           TEXT,
  ip_country   TEXT,
  geo_json     TEXT,       -- richer geo (city/region) if a provider is enabled
  user_agent   TEXT,
  device_json  TEXT,       -- parsed browser/os/device
  headers_json TEXT,       -- captured request headers (view route only)
  client_json  TEXT,       -- client-side telemetry beacon (screen, tz, etc.)
  blocked_reason TEXT,     -- set when access was refused (VPN/proxy/Tor, no public IP…)
  attempts     INTEGER NOT NULL DEFAULT 1  -- refused attempts collapsed into this row
);

CREATE TABLE IF NOT EXISTS leak_reports (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  image_id           INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  reporter_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  view_ref           TEXT,
  reason             TEXT NOT NULL,
  details            TEXT,
  proof_storage_name TEXT NOT NULL,
  proof_mime         TEXT NOT NULL,
  proof_byte_size    INTEGER NOT NULL,
  status             TEXT NOT NULL DEFAULT 'open', -- 'open' | 'reviewed' | 'dismissed'
  created_at         INTEGER NOT NULL,
  reviewed_at        INTEGER,
  reviewed_by        TEXT REFERENCES users(id),
  admin_note         TEXT
  ,access_log_id     INTEGER REFERENCES access_logs(id)
);

CREATE TABLE IF NOT EXISTS view_links (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  image_id   INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  token      TEXT NOT NULL UNIQUE,   -- unguessable slug appended as ?r=
  label      TEXT,                   -- who this link was handed to
  max_uses   INTEGER,                -- NULL = unlimited; 1 = one-time
  use_count  INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

-- Galleries: a single share link that groups multiple uploads.
CREATE TABLE IF NOT EXISTS galleries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token      TEXT NOT NULL UNIQUE, -- public slug in /g/:token
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER
);

CREATE TABLE IF NOT EXISTS gallery_items (
  gallery_id INTEGER NOT NULL REFERENCES galleries(id) ON DELETE CASCADE,
  image_id   INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  position   INTEGER,
  added_at   INTEGER NOT NULL,
  PRIMARY KEY (gallery_id, image_id)
);

CREATE TABLE IF NOT EXISTS leak_report_proofs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id    INTEGER NOT NULL REFERENCES leak_reports(id) ON DELETE CASCADE,
  storage_name TEXT NOT NULL,
  mime         TEXT NOT NULL,
  byte_size    INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_images_owner ON images(owner_id);
CREATE INDEX IF NOT EXISTS idx_view_links_image ON view_links(image_id);
CREATE INDEX IF NOT EXISTS idx_galleries_owner ON galleries(owner_id);
CREATE INDEX IF NOT EXISTS idx_gallery_items_gallery ON gallery_items(gallery_id);
CREATE INDEX IF NOT EXISTS idx_images_expires ON images(expires_at);
CREATE INDEX IF NOT EXISTS idx_logs_image ON access_logs(image_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON leak_reports(status, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_image ON leak_reports(image_id);
CREATE INDEX IF NOT EXISTS idx_reports_access_log ON leak_reports(access_log_id);
CREATE INDEX IF NOT EXISTS idx_report_proofs_report ON leak_report_proofs(report_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_view ON access_logs(image_id, view_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_login_challenges_expires ON login_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_recovery_challenges_expires ON recovery_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_bans_kind ON bans(kind);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`);

// Convert pre-UUID databases in place. SQLite cannot alter a primary-key type,
// so rebuild the user table and every table that stores a user foreign key.
function migrateIntegerUserIds() {
  const idColumn = db.prepare('PRAGMA table_info(users)').all().find((c) => c.name === 'id');
  if (!idColumn || !/^INT/i.test(String(idColumn.type))) return;

  const affected = ['users', 'sessions', 'login_challenges', 'images', 'bans', 'phash_blocklist', 'audit_log', 'leak_reports'];
  const userColumns = new Set(['approved_by']);
  const foreignColumns = new Set(['user_id', 'owner_id', 'created_by', 'added_by', 'actor_id', 'reporter_id', 'reviewed_by']);
  const schemas = new Map();
  const indexes = db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL").all()
    .filter((i) => affected.some((table) => new RegExp(`\\bON\\s+${table}\\b`, 'i').test(i.sql)));
  for (const table of affected) {
    const schema = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
    if (schema && schema.sql) schemas.set(table, {
      sql: schema.sql,
      columns: db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name),
    });
  }

  db.pragma('foreign_keys = OFF');
  // Renaming a table would otherwise rewrite references to it in the foreign
  // keys of tables not in `affected` (access_logs, gallery_items, view_links),
  // leaving them pointing at temp tables this function drops.
  const legacyAlter = db.pragma('legacy_alter_table', { simple: true });
  db.pragma('legacy_alter_table = ON');
  db.exec('CREATE TEMP TABLE __user_uuid_map (old_id INTEGER PRIMARY KEY, new_id TEXT NOT NULL UNIQUE)');
  const oldUsers = db.prepare('SELECT id FROM users').all();
  const mapUser = db.prepare('INSERT INTO __user_uuid_map (old_id, new_id) VALUES (?, ?)');
  for (const user of oldUsers) mapUser.run(user.id, uuidv7());

  for (const table of affected) {
    const schema = schemas.get(table);
    if (!schema) continue;
    const oldTable = `__uuid_old_${table}`;
    db.exec(`ALTER TABLE ${table} RENAME TO ${oldTable}`);
    let createSql = schema.sql.replace(/^CREATE TABLE(?: IF NOT EXISTS)?\s+\S+/i, `CREATE TABLE ${table}`);
    const textColumns = table === 'users'
      ? ['id', 'approved_by']
      : ['user_id', 'owner_id', 'created_by', 'added_by', 'actor_id', 'reporter_id', 'reviewed_by'];
    createSql = createSql.replace(
      new RegExp(`\\b(${textColumns.join('|')})\\s+INTEGER\\b`, 'gi'),
      '$1 TEXT'
    );
    if (table === 'users') createSql = createSql.replace(/AUTOINCREMENT/gi, '');
    db.exec(createSql);
    const selectColumns = schema.columns.map((column) => {
      if (column === 'id' && table === 'users') return '(SELECT new_id FROM __user_uuid_map WHERE old_id = old.id) AS id';
      if ((table === 'users' && userColumns.has(column)) || (table !== 'users' && foreignColumns.has(column))) {
        return `(SELECT new_id FROM __user_uuid_map WHERE old_id = old.${column}) AS ${column}`;
      }
      return `old.${column}`;
    });
    const columns = schema.columns.map((column) => `"${column}"`).join(', ');
    db.exec(`INSERT INTO ${table} (${columns}) SELECT ${selectColumns.join(', ')} FROM ${oldTable} old`);
    db.exec(`DROP TABLE ${oldTable}`);
  }

  // User bans store the target ID as a value rather than a foreign key.
  db.exec(`UPDATE bans SET value = (SELECT new_id FROM __user_uuid_map WHERE old_id = CAST(bans.value AS INTEGER))
           WHERE kind = 'user' AND value GLOB '[0-9]*'
             AND EXISTS (SELECT 1 FROM __user_uuid_map WHERE old_id = CAST(bans.value AS INTEGER))`);

  for (const index of indexes) db.exec(index.sql);
  db.exec('DROP TABLE __user_uuid_map');
  db.pragma(`legacy_alter_table = ${legacyAlter ? 'ON' : 'OFF'}`);
  db.pragma('foreign_keys = ON');
}

migrateIntegerUserIds();

// --- schema updates ----------------------------------------------------------
function columns(table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
}
function addColumn(table, name, ddl) {
  if (!columns(table).has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}
addColumn('images', 'ttl_seconds', 'ttl_seconds INTEGER');
addColumn('images', 'timer_start', "timer_start TEXT NOT NULL DEFAULT 'first_view'");
addColumn('images', 'max_views', 'max_views INTEGER');
addColumn('images', 'first_viewed_at', 'first_viewed_at INTEGER');
addColumn('images', 'view_count', 'view_count INTEGER NOT NULL DEFAULT 0');
addColumn('users', 'last_ip', 'last_ip TEXT');
addColumn('audit_log', 'target_id', 'target_id TEXT');
addColumn('audit_log', 'note', 'note TEXT');
addColumn('audit_log', 'internal_note', 'internal_note TEXT');
addColumn('users', 'decision_note', 'decision_note TEXT');
addColumn('users', 'decision_internal_note', 'decision_internal_note TEXT');
addColumn('users', 'signup_reason', 'signup_reason TEXT');
addColumn('users', 'trust_until', 'trust_until INTEGER');
addColumn('users', 'email_verified', 'email_verified INTEGER NOT NULL DEFAULT 1');
addColumn('users', 'twofa_mode', "twofa_mode TEXT NOT NULL DEFAULT 'email'");
addColumn('users', 'totp_secret', 'totp_secret TEXT');
addColumn('users', 'totp_pending_secret', 'totp_pending_secret TEXT');
addColumn('users', 'totp_enabled', 'totp_enabled INTEGER NOT NULL DEFAULT 0');
addColumn('users', 'totp_last_counter', 'totp_last_counter INTEGER');
addColumn('users', 'default_ttl', "default_ttl TEXT NOT NULL DEFAULT '24h'");
addColumn('users', 'default_timer_start', "default_timer_start TEXT NOT NULL DEFAULT 'first_view'");
addColumn('users', 'default_max_views', 'default_max_views INTEGER');
addColumn('users', 'upload_max_bytes', 'upload_max_bytes INTEGER');
addColumn('users', 'storage_limit_bytes', 'storage_limit_bytes INTEGER');
addColumn('users', 'rank', "rank TEXT NOT NULL DEFAULT 'user'");
addColumn('images', 'storage_backend', "storage_backend TEXT NOT NULL DEFAULT 'local'");
addColumn('images', 'storage_encrypted', 'storage_encrypted INTEGER NOT NULL DEFAULT 0');
addColumn('leak_reports', 'access_log_id', 'access_log_id INTEGER REFERENCES access_logs(id)');
addColumn('login_challenges', 'next_url', "next_url TEXT NOT NULL DEFAULT '/dashboard'");
addColumn('login_challenges', 'resend_count', 'resend_count INTEGER NOT NULL DEFAULT 0');
addColumn('login_challenges', 'last_sent_at', 'last_sent_at INTEGER');
addColumn('login_challenges', 'resend_blocked_until', 'resend_blocked_until INTEGER');
addColumn('login_challenges', 'purpose', "purpose TEXT NOT NULL DEFAULT 'login'");
addColumn('bans', 'expires_at', 'expires_at INTEGER');
addColumn('images', 'phash', 'phash TEXT');
addColumn('images', 'moderation_status', "moderation_status TEXT NOT NULL DEFAULT 'ok'");
addColumn('images', 'moderation_reason', 'moderation_reason TEXT');
addColumn('images', 'moderation_score', 'moderation_score REAL');
addColumn('images', 'moderation_details', 'moderation_details TEXT');
addColumn('access_logs', 'link_label', 'link_label TEXT');
addColumn('access_logs', 'blocked_reason', 'blocked_reason TEXT');
addColumn('access_logs', 'attempts', 'attempts INTEGER NOT NULL DEFAULT 1');

// Repair databases that went through an earlier table rebuild which renamed a
// table without PRAGMA legacy_alter_table. SQLite rewrote the references to it
// inside other tables' foreign keys, and those temp tables no longer exist, so
// every write to the affected tables fails with "no such table". The data is
// untouched- only the stored schema text is wrong- so each affected table is
// rebuilt with the reference pointed back at the real parent.
const TEMP_PARENTS = [
  [/__images_cascade_old/i, 'images'],
  [/__uuid_old_([a-z_]+)/i, null], // parent name is the captured suffix
];

function realParentFor(tempName) {
  for (const [pattern, target] of TEMP_PARENTS) {
    const match = pattern.exec(tempName);
    if (match) return target || match[1];
  }
  return null;
}

function repairDetachedForeignKeys() {
  const suspects = db
    .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND sql IS NOT NULL")
    .all()
    .filter((t) => !t.name.startsWith('__') && /REFERENCES\s+"?__\w+"?/i.test(t.sql));
  if (!suspects.length) return 0;

  db.pragma('foreign_keys = OFF');
  const legacyAlter = db.pragma('legacy_alter_table', { simple: true });
  db.pragma('legacy_alter_table = ON');
  let repaired = 0;
  try {
    for (const table of suspects) {
      const fixedSql = table.sql.replace(/REFERENCES\s+"?(__\w+)"?/gi, (whole, tempName) => {
        const parent = realParentFor(tempName);
        return parent ? `REFERENCES "${parent}"` : whole;
      });
      if (fixedSql === table.sql) continue;

      const cols = db.prepare(`PRAGMA table_info("${table.name}")`).all().map((c) => `"${c.name}"`).join(', ');
      const indexes = db
        .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL AND tbl_name = ?")
        .all(table.name);
      const staging = `__repair_${table.name}`;
      db.transaction(() => {
        db.exec(`ALTER TABLE "${table.name}" RENAME TO "${staging}"`);
        db.exec(fixedSql);
        db.exec(`INSERT INTO "${table.name}" (${cols}) SELECT ${cols} FROM "${staging}"`);
        db.exec(`DROP TABLE "${staging}"`);
        for (const index of indexes) db.exec(index.sql);
      })();
      repaired += 1;
      console.warn(`[NamelessUnSee] repaired dangling foreign key in ${table.name}`);
    }
  } finally {
    db.pragma(`legacy_alter_table = ${legacyAlter ? 'ON' : 'OFF'}`);
    db.pragma('foreign_keys = ON');
  }
  return repaired;
}
repairDetachedForeignKeys();

// Older databases cascade images away with their owner, which would also take
// the access logs of those images. Rebuild the table so an image survives its
// owner as an orphan until the log-retention sweep collects it. SQLite cannot
// alter a foreign key in place, so the table has to be rewritten.
function detachImagesFromOwner() {
  const schema = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'images'").get();
  if (!schema || !/owner_id[^,]*ON DELETE CASCADE/i.test(schema.sql)) return;

  const cols = db.prepare('PRAGMA table_info(images)').all().map((c) => `"${c.name}"`).join(', ');
  const indexes = db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL AND tbl_name = 'images'")
    .all();
  const createSql = schema.sql
    .replace(/^CREATE TABLE(?: IF NOT EXISTS)?\s+\S+/i, 'CREATE TABLE images')
    .replace(/owner_id(\s+TEXT)?\s+NOT NULL\s+REFERENCES users\(id\)\s+ON DELETE CASCADE/i,
      'owner_id TEXT REFERENCES users(id) ON DELETE SET NULL');

  db.pragma('foreign_keys = OFF');
  // Modern SQLite rewrites references to a renamed table inside every OTHER
  // table's foreign keys. Without this, access_logs, leak_reports and
  // gallery_items would be left pointing at the temp table we are about to
  // drop, and every later write to them would fail with "no such table".
  const legacyAlter = db.pragma('legacy_alter_table', { simple: true });
  db.pragma('legacy_alter_table = ON');
  try {
    db.transaction(() => {
      db.exec('ALTER TABLE images RENAME TO __images_cascade_old');
      db.exec(createSql);
      db.exec(`INSERT INTO images (${cols}) SELECT ${cols} FROM __images_cascade_old`);
      db.exec('DROP TABLE __images_cascade_old');
      for (const index of indexes) db.exec(index.sql);
    })();
  } finally {
    db.pragma(`legacy_alter_table = ${legacyAlter ? 'ON' : 'OFF'}`);
    db.pragma('foreign_keys = ON');
  }

  // A rebuild that silently broke a reference is worse than no rebuild, so
  // refuse to start rather than serve a database whose keys no longer resolve.
  const broken = db.pragma('foreign_key_check');
  if (broken.length) {
    throw new Error(`images rebuild left ${broken.length} broken foreign key reference(s)`);
  }
}
detachImagesFromOwner();

// Gallery tables were added after initial release. Older DB files won't have
// them, but SQLite can't IF NOT EXISTS on ALTER TABLE for missing tables.
// Create them lazily here.
db.exec(`
CREATE TABLE IF NOT EXISTS galleries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token      TEXT NOT NULL UNIQUE,
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE TABLE IF NOT EXISTS gallery_items (
  gallery_id INTEGER NOT NULL REFERENCES galleries(id) ON DELETE CASCADE,
  image_id   INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  position   INTEGER,
  added_at   INTEGER NOT NULL,
  PRIMARY KEY (gallery_id, image_id)
);
CREATE INDEX IF NOT EXISTS idx_galleries_owner ON galleries(owner_id);
CREATE INDEX IF NOT EXISTS idx_gallery_items_gallery ON gallery_items(gallery_id);
`);

module.exports = db;
