'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-intel-'));
process.env.STORAGE_BACKEND = 'local';
// The whole point of this suite: every request looks like an unidentifiable
// connection, so the viewer routes refuse it the way they refuse a VPN.
process.env.ALLOW_PRIVATE_IPS = 'false';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.MAXMIND_LICENSE_KEY = '';
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
const sharp = require('sharp');

const app = require('../src/server');
const db = require('../src/db');
const logging = require('../src/logging');
const { hashPassword, uuidv7 } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, solveAltcha, uploadForm } = require('./helpers');

let ownerId;

before(() => {
  const now = Date.now();
  ownerId = uuidv7(now);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
  ).run(ownerId, 'owner@test.invalid', 'owneri', hashPassword('ownerpass1234'), now, now);
});

// Metadata-only rows: the routes under test refuse before any image is read,
// so no bytes need to exist on disk.
function seedImage(token) {
  const now = Date.now();
  return db
    .prepare(
      `INSERT INTO images (token, owner_id, storage_name, mime, width, height, byte_size, title, created_at, timer_start)
       VALUES (?, ?, ?, 'image/png', 10, 10, 100, ?, ?, 'first_view') RETURNING id`
    )
    .get(token, ownerId, token + '.png', token, now).id;
}

async function loginConsent(username, password) {
  const req = makeReq(app, newJar());
  await consent(req, '/');
  await req('/login', form({ identifier: username, password, altcha: await solveAltcha(req), next: '/dashboard' }));
  return req;
}

function logsFor(imageId) {
  return db.prepare('SELECT * FROM access_logs WHERE image_id = ? ORDER BY id').all(imageId);
}

test('a refused gallery hit fans out to its images, but stays bounded', async () => {
  const now = Date.now();
  const galleryId = db
    .prepare('INSERT INTO galleries (token, owner_id, title, created_at) VALUES (?, ?, ?, ?) RETURNING id')
    .get('galtoken1234', ownerId, 'blocked gallery', now).id;
  const imageIds = [];
  for (let i = 0; i < 14; i++) {
    const id = seedImage(`galimg${i}`);
    imageIds.push(id);
    db.prepare('INSERT INTO gallery_items (gallery_id, image_id, position, added_at) VALUES (?, ?, ?, ?)')
      .run(galleryId, id, i + 1, now);
  }

  const viewer = makeReq(app, newJar());
  await consent(viewer, '/');
  assert.equal((await viewer('/g/galtoken1234')).status, 403);

  const rows = db
    .prepare(`SELECT * FROM access_logs WHERE image_id IN (${imageIds.join(',')}) ORDER BY id`)
    .all();
  assert.equal(rows.length, 10, 'the fan-out is capped well below the gallery size');
  assert.ok(rows.every((r) => r.blocked_reason === 'no-public-ip'));
  assert.ok(rows.every((r) => r.link_label === 'gallery galtoken1234'), 'the log names the gallery used');
  assert.equal(rows.filter((r) => r.headers_json).length, 1, 'only the first row carries the header blob');

  // A second refused hit still collapses onto the same rows.
  assert.equal((await viewer('/g/galtoken1234')).status, 403);
  const after = db.prepare(`SELECT * FROM access_logs WHERE image_id IN (${imageIds.join(',')})`).all();
  assert.equal(after.length, 10, 'repeat gallery attempts do not add rows');
  assert.ok(after.every((r) => r.attempts === 2));

  // The blocked gallery page profiles the refused viewer the same way.
  const beacon = await viewer('/g/galtoken1234/telemetry', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client: { screenW: 800, timezone: 'UTC' } }),
  });
  assert.equal(beacon.status, 204);
  const profiled = db.prepare(`SELECT * FROM access_logs WHERE image_id IN (${imageIds.join(',')})`).all();
  assert.equal(profiled.length, 10, 'the gallery beacon adds no rows');
  assert.ok(profiled.every((r) => JSON.parse(r.client_json).screenW === 800), 'every refused row carries the browser data');
  assert.ok(profiled.every((r) => r.attempts === 2), 'the beacon is not counted as another attempt');
});

test('blocked attempts are capped per image so a scan cannot grow the log forever', async () => {
  const imageId = seedImage('prunetarget');
  const insert = db.prepare(
    `INSERT INTO access_logs (image_id, view_id, viewed_at, ip, blocked_reason, attempts)
     VALUES (?, NULL, ?, ?, 'proxy', 1)`
  );
  const base = Date.now();
  for (let i = 0; i < 260; i++) insert.run(imageId, base + i, `203.0.113.${i % 256}`);
  // A served view sits in the same log and must survive the sweep untouched.
  db.prepare(
    `INSERT INTO access_logs (image_id, view_id, viewed_at, ip, blocked_reason) VALUES (?, 'servedviewid', ?, ?, NULL)`
  ).run(imageId, base, '198.51.100.7');

  const removed = await logging.pruneBlockedLogs();
  assert.equal(removed, 60, 'only the overflow is dropped');

  const rows = db.prepare('SELECT * FROM access_logs WHERE image_id = ? ORDER BY viewed_at').all(imageId);
  const blocked = rows.filter((r) => r.blocked_reason);
  assert.equal(blocked.length, logging.BLOCKED_LOG_KEEP);
  assert.equal(blocked[0].viewed_at, base + 60, 'the newest attempts are the ones kept');
  assert.equal(rows.filter((r) => !r.blocked_reason).length, 1, 'served views are never pruned');
});

test('a refused viewer is logged as a blocked attempt, never as a served view', async () => {
  const owner = await loginConsent('owneri', 'ownerpass1234');
  const png = await sharp({ create: { width: 60, height: 40, channels: 3, background: { r: 5, g: 90, b: 120 } } })
    .png()
    .toBuffer();
  assert.equal((await uploadForm(owner, { title: 'blockedshot', ttl: 'never' }, png, 't.png')).status, 302);
  const img = db.prepare('SELECT * FROM images WHERE title = ? ORDER BY id DESC').get('blockedshot');

  const viewer = makeReq(app, newJar());
  await consent(viewer, '/');
  const blocked = await viewer(`/i/${img.token}`);
  assert.equal(blocked.status, 403, 'unidentifiable viewer is refused');
  const blockedHtml = await blocked.text();
  assert.ok(blockedHtml.includes(`/i/${img.token}/telemetry`), 'the blocked page still collects browser details');

  let rows = logsFor(img.id);
  assert.equal(rows.length, 1, 'the refused attempt is recorded');
  assert.equal(rows[0].blocked_reason, 'no-public-ip');
  assert.equal(rows[0].view_id, null, 'a blocked attempt never claims a view id');
  assert.ok(rows[0].headers_json && rows[0].user_agent !== undefined, 'forensic request data is kept');

  // Refreshing the blocked page inside the dedupe window updates the existing
  // row instead of flooding the owner's log.
  const firstSeenAt = rows[0].viewed_at;
  assert.equal(rows[0].attempts, 1);
  await viewer(`/i/${img.token}`);
  rows = logsFor(img.id);
  assert.equal(rows.length, 1, 'repeat attempts from the same IP collapse into one row');
  assert.ok(rows[0].viewed_at >= firstSeenAt, 'the existing row is refreshed, not duplicated');
  assert.equal(rows[0].attempts, 2, 'the collapsed row counts how many times they tried');

  // The render route refuses too, even once the bot gate is passed, and still
  // logs nothing that counts as a view.
  const gate = await viewer(`/i/${img.token}/view-check`, form({ altcha: await solveAltcha(viewer) }));
  assert.equal(gate.status, 302, 'bot check passes independently of the network assessment');
  const render = await viewer(`/i/${img.token}/render.png?v=${'a'.repeat(12)}`);
  assert.equal(render.status, 403, 'render is refused as well');
  assert.match(await render.text(), /VPN|anonymising|public network address/i, 'refusal explains why');
  rows = logsFor(img.id);
  assert.ok(rows.every((r) => r.blocked_reason), 'no served-view row was created');

  // Blocked attempts do not inflate the owner's view count.
  const views = db
    .prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = ? AND blocked_reason IS NULL')
    .get(img.id).n;
  assert.equal(views, 0, 'blocked attempts are not counted as views');
  assert.equal(db.prepare('SELECT view_count FROM images WHERE id = ?').get(img.id).view_count, 0);

  // The blocked page runs the same collector the view page does: browser data
  // from a refused viewer is kept, but it lands on the refused-attempt row and
  // can never become an ordinary-looking view row.
  const attemptsBeforeBeacon = rows[0].attempts;
  const beacon = await viewer(`/i/${img.token}/telemetry`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ viewId: 'a'.repeat(12), client: { screenW: 1920, platform: 'Linux x86_64' } }),
  });
  assert.equal(beacon.status, 204);
  rows = logsFor(img.id);
  assert.equal(rows.length, 1, 'the beacon did not create a row of its own');
  assert.ok(rows.every((r) => r.blocked_reason), 'the beacon did not create a view row');
  const blockedClient = JSON.parse(rows[0].client_json);
  assert.equal(blockedClient.screenW, 1920, 'the refused viewer is still profiled');
  assert.equal(blockedClient.platform, 'Linux x86_64');
  assert.equal(rows[0].attempts, attemptsBeforeBeacon, 'a beacon is not a new access attempt');

  // The owner sees the attempt in the access log, but cannot report a viewer
  // who never received image bytes as a leaker.
  const logsHtml = await (await owner(`/dashboard/i/${img.token}/logs`)).text();
  assert.ok(logsHtml.includes('blocked:'), 'the log page marks the entry as blocked');
  assert.ok(!logsHtml.includes('Report As Leaker'), 'a blocked attempt is not reportable');
  assert.equal((await owner(`/dashboard/i/${img.token}/logs/${rows[0].id}/report`)).status, 404);
});
