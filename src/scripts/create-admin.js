'use strict';

// Usage:
//   node src/scripts/create-admin.js <email> <username> <password>
// Docker:
//   docker compose exec app yarn create-admin <email> <username> <password>
// Creates an approved owner/admin account, or promotes an existing user to owner/admin.

const { getDatabase } = require('../db-runtime');
const { hashPassword, uuidv7 } = require('../util/crypto');

const [, , email, username, password] = process.argv;

if (!email || !username || !password) {
  console.error('Usage: node src/scripts/create-admin.js <email> <username> <password>');
  process.exit(1);
}
if (password.length < 10) {
  console.error('Password must be at least 10 characters.');
  process.exit(1);
}

async function main() {
const db = await getDatabase();
const existing = await db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email.toLowerCase(), username]);
const now = Date.now();

if (existing) {
  await db.run("UPDATE users SET role = 'admin', rank = 'owner', status = 'approved', approved_at = ? WHERE id = ?", [now, existing.id]);
  console.log(`Promoted existing user "${existing.username}" to approved owner/admin.`);
} else {
  await db.run(
    `INSERT INTO users (id, email, username, password_hash, role, rank, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'admin', 'owner', 'approved', ?, ?)`
  , [uuidv7(now), email.toLowerCase(), username, hashPassword(password), now, now]);
  console.log(`Created approved owner/admin "${username}" <${email}>.`);
}
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
