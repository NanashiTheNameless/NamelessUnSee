'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-retain-'));
process.env.STORAGE_BACKEND = 'local';
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.RATELIMIT_ENABLED = 'false';
process.env.ALTCHA_MAX_NUMBER = '4000';
process.env.NSFW_CLASSIFIER_ENABLED = 'false';
process.env.TWOFA_ENABLED = 'false';
process.env.SECURE_COOKIES = 'false';
process.env.RESEND_API_KEY = '';
process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED = 'false';
process.env.ADMIN_NOTIFY_FROM = '';
process.env.ADMIN_NOTIFY_TO = '';

const { test, before } = require('node:test');
const assert = require('node:assert');

const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
const accessLog = require('../src/access-log');
const { hashPassword, uuidv7 } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, solveAltcha, csrfFrom } = require('./helpers');

let ownerId;

before(() => {
  const now = Date.now();
  ownerId = uuidv7(now);
  const seed = db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, ?, 'approved', ?, ?)`
  );
  seed.run(ownerId, 'keeper@test.invalid', 'keeper', hashPassword('keeperpass1234'), 'user', now, now);
  seed.run(uuidv7(now + 1), 'boss@test.invalid', 'bossr', hashPassword('bosspass1234'), 'admin', now, now);
});

async function login(identifier, password) {
  const req = makeReq(app, newJar());
  await consent(req, '/');
  await req('/login', form({ identifier, password, altcha: await solveAltcha(req), next: '/dashboard' }));
  return req;
}

function seedImageWithLog(token) {
  const now = Date.now();
  const image = db
    .prepare(
      `INSERT INTO images (token, owner_id, storage_name, mime, width, height, byte_size, title, created_at, timer_start)
       VALUES (?, ?, ?, 'image/png', 20, 20, 400, ?, ?, 'first_view') RETURNING id`
    )
    .get(token, ownerId, token + '.png', 'kept ' + token, now);
  db.prepare(
    `INSERT INTO access_logs (image_id, view_id, viewed_at, ip, ip_country, user_agent, blocked_reason)
     VALUES (?, 'viewidkept01', ?, '198.51.100.9', 'NL', 'Mozilla/5.0 KeeperBrowser', NULL)`
  ).run(image.id, now);
  return image.id;
}

test('access logs survive image deletion for both the uploader and admins, then expire', async () => {
  const imageId = seedImageWithLog('keptimage1');
  const owner = await login('keeper', 'keeperpass1234');
  const admin = await login('bossr', 'bosspass1234');

  const ownerPath = '/dashboard/i/keptimage1/logs';
  const adminPath = '/admin/images/keptimage1/logs';
  assert.equal((await owner(ownerPath)).status, 200, 'owner reads the log while the image is live');
  assert.equal((await admin(adminPath)).status, 200, 'admin reads the log while the image is live');

  // The owner deletes the image outright.
  const csrf = csrfFrom(await (await owner('/dashboard')).text());
  assert.equal((await owner('/dashboard/i/keptimage1/delete', form({ _csrf: csrf }))).status, 302);
  assert.ok(db.prepare('SELECT deleted_at FROM images WHERE id = ?').get(imageId).deleted_at, 'image is deleted');

  // Both can still retrieve the log, and both are told when it expires.
  const ownerAfter = await owner(ownerPath);
  assert.equal(ownerAfter.status, 200, 'owner still reads the log after deletion');
  const ownerHtml = await ownerAfter.text();
  assert.ok(/198\.51\.100\.9/.test(ownerHtml), 'the entries are still there');
  assert.ok(/has been deleted/.test(ownerHtml), 'the page says the image is gone');

  const adminAfter = await admin(adminPath);
  assert.equal(adminAfter.status, 200, 'admin still reads the log after deletion');
  assert.ok(/198\.51\.100\.9/.test(await adminAfter.text()));

  // Both find their way there through the UI, not just by typing the URL.
  assert.ok((await (await owner('/dashboard')).text()).includes(ownerPath), 'dashboard links to the deleted image log');
  assert.ok(
    (await (await admin('/admin/users/' + ownerId + '/files')).text()).includes(adminPath),
    'admin file list links to the deleted image log'
  );

  // The owner can still act on what they find, for the life of the log.
  const logId = db.prepare('SELECT id FROM access_logs WHERE image_id = ?').get(imageId).id;
  assert.equal(
    (await owner(`/dashboard/i/keptimage1/logs/${logId}/report`)).status,
    200,
    'a leak report can still be filed against a retained entry'
  );

  // Past the window, the sweep erases the rows and both views 404.
  const expired = Date.now() - config.logRetentionAfterDeleteHours * 3600 * 1000 - 1000;
  db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?').run(expired, imageId);
  assert.equal(accessLog.purgeExpired(), 1, 'the sweep erases the expired log');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 0);
  assert.equal((await owner(ownerPath)).status, 404, 'owner can no longer reach it');
  assert.equal((await admin(adminPath)).status, 404, 'admin can no longer reach it');
});

test('the retention sweep spares live images and keeps leak reports', () => {
  const liveId = seedImageWithLog('liveimage1');
  const goneId = seedImageWithLog('goneimage1');
  const goneLog = db.prepare('SELECT id FROM access_logs WHERE image_id = ?').get(goneId).id;
  db.prepare(
    `INSERT INTO leak_reports
       (image_id, reporter_id, reason, details, proof_storage_name, proof_mime, proof_byte_size, created_at, access_log_id)
     VALUES (?, ?, 'unauthorized_redistribution', 'proof', 'p.png', 'image/png', 10, ?, ?)`
  ).run(goneId, ownerId, Date.now(), goneLog);

  const expired = Date.now() - config.logRetentionAfterDeleteHours * 3600 * 1000 - 1000;
  db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?').run(expired, goneId);
  accessLog.purgeExpired();

  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(liveId).n, 1, 'live image untouched');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(goneId).n, 0);
  const report = db.prepare('SELECT * FROM leak_reports WHERE image_id = ?').get(goneId);
  assert.ok(report, 'the report itself outlives the log it pointed at');
  assert.equal(report.access_log_id, null, 'its dangling reference was cleared');
});
