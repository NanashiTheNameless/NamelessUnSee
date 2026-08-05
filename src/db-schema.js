'use strict';

// Portable modern schema for the async local SQLite and Cloudflare D1 paths.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', rank TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'pending', email_verified INTEGER NOT NULL DEFAULT 1, signup_reason TEXT, decision_note TEXT, decision_internal_note TEXT, created_at INTEGER NOT NULL, approved_at INTEGER, approved_by TEXT REFERENCES users(id), twofa_mode TEXT NOT NULL DEFAULT 'email', totp_secret TEXT, totp_pending_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_counter INTEGER, default_ttl TEXT NOT NULL DEFAULT '24h', default_timer_start TEXT NOT NULL DEFAULT 'first_view', default_max_views INTEGER, upload_max_bytes INTEGER, storage_limit_bytes INTEGER, last_ip TEXT, trust_until INTEGER);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS login_challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, method TEXT NOT NULL, code_hash TEXT, csrf_token TEXT NOT NULL, next_url TEXT NOT NULL DEFAULT '/dashboard', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, resend_count INTEGER NOT NULL DEFAULT 0, last_sent_at INTEGER, resend_blocked_until INTEGER, purpose TEXT NOT NULL DEFAULT 'login');
CREATE TABLE IF NOT EXISTS recovery_challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, target TEXT, code_hash TEXT NOT NULL, csrf_token TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS images (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, owner_id TEXT REFERENCES users(id) ON DELETE SET NULL, storage_name TEXT NOT NULL, mime TEXT NOT NULL, width INTEGER, height INTEGER, byte_size INTEGER, title TEXT, created_at INTEGER NOT NULL, ttl_seconds INTEGER, timer_start TEXT NOT NULL DEFAULT 'first_view', max_views INTEGER, first_viewed_at INTEGER, view_count INTEGER NOT NULL DEFAULT 0, expires_at INTEGER, deleted_at INTEGER, storage_backend TEXT NOT NULL DEFAULT 'local', storage_encrypted INTEGER NOT NULL DEFAULT 0, phash TEXT, moderation_status TEXT NOT NULL DEFAULT 'ok', moderation_reason TEXT, moderation_score REAL, moderation_details TEXT);
CREATE TABLE IF NOT EXISTS bans (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL, block_account INTEGER NOT NULL DEFAULT 0, block_view INTEGER NOT NULL DEFAULT 0, reason TEXT, created_at INTEGER NOT NULL, created_by TEXT REFERENCES users(id), expires_at INTEGER);
CREATE TABLE IF NOT EXISTS phash_blocklist (id INTEGER PRIMARY KEY AUTOINCREMENT, phash TEXT NOT NULL, label TEXT, added_by TEXT REFERENCES users(id), created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT REFERENCES users(id), actor_name TEXT, action TEXT NOT NULL, detail TEXT, target_id TEXT, note TEXT, internal_note TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE, view_id TEXT, viewed_at INTEGER NOT NULL, ip TEXT, ip_country TEXT, geo_json TEXT, user_agent TEXT, device_json TEXT, headers_json TEXT, client_json TEXT, blocked_reason TEXT, attempts INTEGER NOT NULL DEFAULT 1, link_label TEXT);
CREATE TABLE IF NOT EXISTS leak_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE, reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, view_ref TEXT, reason TEXT NOT NULL, details TEXT, proof_storage_name TEXT NOT NULL, proof_mime TEXT NOT NULL, proof_byte_size INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL, reviewed_at INTEGER, reviewed_by TEXT REFERENCES users(id), admin_note TEXT, access_log_id INTEGER REFERENCES access_logs(id));
CREATE TABLE IF NOT EXISTS view_links (id INTEGER PRIMARY KEY AUTOINCREMENT, image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE, token TEXT NOT NULL UNIQUE, label TEXT, max_uses INTEGER, use_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS galleries (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT, created_at INTEGER NOT NULL, deleted_at INTEGER);
CREATE TABLE IF NOT EXISTS gallery_items (gallery_id INTEGER NOT NULL REFERENCES galleries(id) ON DELETE CASCADE, image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE, position INTEGER, added_at INTEGER NOT NULL, PRIMARY KEY (gallery_id, image_id));
CREATE TABLE IF NOT EXISTS leak_report_proofs (id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES leak_reports(id) ON DELETE CASCADE, storage_name TEXT NOT NULL, mime TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at INTEGER NOT NULL);
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
`;

module.exports = { SCHEMA };
