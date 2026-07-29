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
const { deleteUserAccount } = require('../src/user-deletion');
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
  const siteOwnerId = uuidv7(now + 2);
  seed.run(siteOwnerId, 'root@test.invalid', 'rootr', hashPassword('rootpass1234'), 'admin', now, now);
  db.prepare("UPDATE users SET rank = 'owner' WHERE id = ?").run(siteOwnerId);
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

test('the site owner can force-erase a log early; admins and uploaders cannot', async () => {
  const imageId = seedImageWithLog('eraseme001');
  const erasePath = '/admin/images/eraseme001/logs/erase';
  const adminPath = '/admin/images/eraseme001/logs';

  const uploader = await login('keeper', 'keeperpass1234');
  const admin = await login('bossr', 'bosspass1234');
  const siteOwner = await login('rootr', 'rootpass1234');

  // The uploader's own log page never offers the action.
  assert.ok(
    !(await (await uploader('/dashboard/i/eraseme001/logs')).text()).includes('Erase Access Log'),
    'uploaders are not offered the erase action'
  );

  // A plain admin sees the log but cannot erase it.
  const adminHtml = await (await admin(adminPath)).text();
  assert.ok(!adminHtml.includes('Erase Access Log'), 'plain admins are not offered the erase action');
  const adminCsrf = csrfFrom(await (await admin('/admin')).text());
  assert.equal((await admin(erasePath, form({ _csrf: adminCsrf }))).status, 403, 'admin rank is refused');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 1);

  // An open leak report citing an entry blocks erasure, for everyone.
  const logId = db.prepare('SELECT id FROM access_logs WHERE image_id = ?').get(imageId).id;
  const reportId = db
    .prepare(
      `INSERT INTO leak_reports
         (image_id, reporter_id, reason, details, proof_storage_name, proof_mime, proof_byte_size, created_at, access_log_id)
       VALUES (?, ?, 'unauthorized_redistribution', 'evidence', 'p.png', 'image/png', 10, ?, ?) RETURNING id`
    )
    .get(imageId, ownerId, Date.now(), logId).id;

  const ownerCsrf = csrfFrom(await (await siteOwner('/admin')).text());
  const refused = await siteOwner(erasePath, form({ _csrf: ownerCsrf }));
  assert.equal(refused.status, 302);
  assert.match(refused.headers.get('location'), /blocked=1/, 'erasure is refused while a report is open');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 1, 'nothing was erased');
  assert.ok(
    (await (await siteOwner(adminPath + '?blocked=1')).text()).includes('open leak report'),
    'the page explains why'
  );

  // Resolve the report, and the owner may erase.
  db.prepare("UPDATE leak_reports SET status = 'reviewed' WHERE id = ?").run(reportId);
  const erased = await siteOwner(erasePath, form({ _csrf: ownerCsrf }));
  assert.equal(erased.status, 302);
  assert.match(erased.headers.get('location'), /erased=1/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 0, 'log erased');

  // The resolved report survives, with its dangling reference cleared, and the
  // erasure is on the record.
  const report = db.prepare('SELECT * FROM leak_reports WHERE id = ?').get(reportId);
  assert.ok(report, 'the report outlives the log it cited');
  assert.equal(report.access_log_id, null);
  assert.ok(
    db.prepare("SELECT id FROM audit_log WHERE action = 'owner_erase_access_log'").get(),
    'the erasure is audited'
  );
});

test('deleting an account erases files at once but keeps the access logs for the window', async () => {
  const now = Date.now();
  const doomedId = uuidv7(now + 3);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
  ).run(doomedId, 'doomed@test.invalid', 'doomed', hashPassword('doomedpass1234'), now, now);

  const storedName = 'doomedfile.png';
  fs.writeFileSync(path.join(config.uploadDir, storedName), Buffer.from([1, 2, 3, 4]));
  const imageId = db
    .prepare(
      `INSERT INTO images (token, owner_id, storage_name, mime, width, height, byte_size, title, created_at, timer_start)
       VALUES ('doomedimg1', ?, ?, 'image/png', 10, 10, 4, 'doomed shot', ?, 'first_view') RETURNING id`
    )
    .get(doomedId, storedName, now).id;
  db.prepare(
    `INSERT INTO access_logs (image_id, view_id, viewed_at, ip, user_agent)
     VALUES (?, 'viewiddoomed', ?, '203.0.113.77', 'Mozilla/5.0 DoomedBrowser')`
  ).run(imageId, now);

  await deleteUserAccount({ id: doomedId, username: 'doomed' });

  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE id = ?').get(doomedId).n, 0, 'account gone');
  assert.equal(fs.existsSync(path.join(config.uploadDir, storedName)), false, 'stored file erased immediately');

  // The image record survives as an orphan purely so its log can age out.
  const orphan = db.prepare('SELECT * FROM images WHERE id = ?').get(imageId);
  assert.ok(orphan, 'image record retained');
  assert.equal(orphan.owner_id, null, 'detached from the deleted account');
  assert.ok(orphan.deleted_at, 'and marked deleted, so it is unviewable');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 1, 'log kept');

  // An admin can still read it during the window; nobody can view the media.
  const admin = await login('bossr', 'bosspass1234');
  const page = await admin('/admin/images/doomedimg1/logs');
  assert.equal(page.status, 200, 'admin reads the orphaned log');
  assert.ok(/203\.0\.113\.77/.test(await page.text()));

  const viewer = makeReq(app, newJar());
  await consent(viewer, '/');
  const gone = await viewer('/i/doomedimg1');
  assert.equal(gone.status, 404, 'viewers get nothing back');
  assert.ok(/no longer|gone|not found/i.test(await gone.text()), 'the view page shows the gone notice');
  assert.equal((await viewer('/i/doomedimg1/render.png')).status, 404, 'no media is served');

  // Past the window the log goes, and the orphaned record goes with it.
  const expired = Date.now() - config.logRetentionAfterDeleteHours * 3600 * 1000 - 1000;
  db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?').run(expired, imageId);
  accessLog.purgeExpired();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ?').get(imageId).n, 0, 'log erased');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM images WHERE id = ?').get(imageId).n, 0, 'orphan collected');
  assert.equal((await admin('/admin/images/doomedimg1/logs')).status, 404);
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
