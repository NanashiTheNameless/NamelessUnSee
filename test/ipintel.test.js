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
const { hashPassword, uuidv7 } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, solveAltcha, uploadForm } = require('./helpers');

before(() => {
  const now = Date.now();
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
  ).run(uuidv7(now), 'owner@test.invalid', 'owneri', hashPassword('ownerpass1234'), now, now);
});

async function loginConsent(username, password) {
  const req = makeReq(app, newJar());
  await consent(req, '/');
  await req('/login', form({ identifier: username, password, altcha: await solveAltcha(req), next: '/dashboard' }));
  return req;
}

function logsFor(imageId) {
  return db.prepare('SELECT * FROM access_logs WHERE image_id = ? ORDER BY id').all(imageId);
}

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

  let rows = logsFor(img.id);
  assert.equal(rows.length, 1, 'the refused attempt is recorded');
  assert.equal(rows[0].blocked_reason, 'no-public-ip');
  assert.equal(rows[0].view_id, null, 'a blocked attempt never claims a view id');
  assert.ok(rows[0].headers_json && rows[0].user_agent !== undefined, 'forensic request data is kept');

  // Refreshing the blocked page inside the dedupe window updates the existing
  // row instead of flooding the owner's log.
  const firstSeenAt = rows[0].viewed_at;
  await viewer(`/i/${img.token}`);
  rows = logsFor(img.id);
  assert.equal(rows.length, 1, 'repeat attempts from the same IP collapse into one row');
  assert.ok(rows[0].viewed_at >= firstSeenAt, 'the existing row is refreshed, not duplicated');

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

  // The owner sees the attempt in the access log, but cannot report a viewer
  // who never received image bytes as a leaker.
  const logsHtml = await (await owner(`/dashboard/i/${img.token}/logs`)).text();
  assert.ok(logsHtml.includes('blocked:'), 'the log page marks the entry as blocked');
  assert.ok(!logsHtml.includes('Report As Leaker'), 'a blocked attempt is not reportable');
  assert.equal((await owner(`/dashboard/i/${img.token}/logs/${rows[0].id}/report`)).status, 404);
});
