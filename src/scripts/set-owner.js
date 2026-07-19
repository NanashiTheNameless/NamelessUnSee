'use strict';

// Usage:
//   node src/scripts/set-owner.js <email|username|uuid>
// Docker:
//   docker compose exec app yarn set-owner <email|username|uuid>
const db = require('../db');

const identifier = process.argv[2];
if (!identifier) {
  console.error('Usage: node src/scripts/set-owner.js <email|username|uuid>');
  process.exit(1);
}

const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ? OR id = ?').get(identifier.toLowerCase(), identifier, identifier);
if (!user) {
  console.error('No matching user.');
  process.exit(1);
}
db.prepare("UPDATE users SET role = 'admin', rank = 'owner', status = 'approved', approved_at = COALESCE(approved_at, ?) WHERE id = ?").run(Date.now(), user.id);
console.log(`Set ${user.username} (${user.id}) as owner and admin.`);
