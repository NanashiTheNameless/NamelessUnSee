'use strict';

// Usage:
//   node src/scripts/set-owner.js <email|username|uuid>
// Docker:
//   docker compose exec app yarn set-owner <email|username|uuid>
const { getDatabase } = require('../db-runtime');

const identifier = process.argv[2];
if (!identifier) {
  console.error('Usage: node src/scripts/set-owner.js <email|username|uuid>');
  process.exit(1);
}

async function main() {
const db = await getDatabase();
const user = await db.get('SELECT * FROM users WHERE email = ? OR username = ? OR id = ?', [identifier.toLowerCase(), identifier, identifier]);
if (!user) {
  console.error('No matching user.');
  process.exit(1);
}
await db.run("UPDATE users SET role = 'admin', rank = 'owner', status = 'approved', approved_at = COALESCE(approved_at, ?) WHERE id = ?", [Date.now(), user.id]);
console.log(`Set ${user.username} (${user.id}) as owner and admin.`);
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
