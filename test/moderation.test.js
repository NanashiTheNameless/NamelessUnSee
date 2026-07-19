'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-mod-'));
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.RATELIMIT_ENABLED = 'false';
process.env.ALTCHA_MAX_NUMBER = '4000';
process.env.MODERATION_ENABLED = 'true';
process.env.NSFW_CLASSIFIER_ENABLED = 'true';
process.env.MODERATION_HOLD_ON_REVIEW = 'true';
process.env.TWOFA_ENABLED = 'false';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const sharp = require('sharp');

const app = require('../src/server');
const db = require('../src/db');
const bans = require('../src/bans');
const nsfw = require('../src/nsfw');
const { hashPassword, uuidv7 } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, csrfFrom, solveAltcha } = require('./helpers');
let scorer = async () => 0; // controllable stub

before(() => {
  nsfw.setScorer((p) => scorer(p));
  const now = Date.now();
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'admin', 'approved', ?, ?)`
  ).run(uuidv7(now), 'admin@x.co', 'adminm', hashPassword('adminpass1234'), now, now);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
  ).run(uuidv7(now), 'user@x.co', 'userm', hashPassword('userpass1234'), now, now);

});

async function png(w, h, color) {
  return sharp({ create: { width: w, height: h, channels: 3, background: color } }).png().toBuffer();
}
async function loginConsent(username, password) {
  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');
  const altcha = await solveAltcha(req);
  await req('/login', form({ identifier: username, password, altcha, next: '/dashboard' }));
  return { jar, req };
}
async function uploadImage(req, buf, title) {
  const csrf = csrfFrom(await (await req('/dashboard')).text());
  const fd = new FormData();
  fd.set('_csrf', csrf);
  fd.set('title', title);
  fd.set('ttl', 'never');
  fd.set('image', new Blob([buf], { type: 'image/png' }), 't.png');
  return req('/upload', { method: 'POST', body: fd });
}
function newestToken(title) {
  return db.prepare('SELECT token FROM images WHERE title = ? ORDER BY id DESC').get(title).token;
}

test('NSFW classifier flag -> held for review, admin can allow', async () => {
  const { req } = await loginConsent('userm', 'userpass1234');

  scorer = async () => 0.99; // classifier flags it
  const r = await uploadImage(req, await png(200, 140, { r: 220, g: 180, b: 170 }), 'nsfwshot');
  assert.equal(r.status, 302);
  assert.ok((r.headers.get('location') || '').includes('flagged=1'), 'redirect flags the upload');

  const token = newestToken('nsfwshot');
  const row = db.prepare('SELECT moderation_status FROM images WHERE token = ?').get(token);
  assert.equal(row.moderation_status, 'review');

  // Held: not viewable
  assert.equal((await req('/i/' + token)).status, 404);

  // Admin sees it in the review queue, then allows it
  const admin = await loginConsent('adminm', 'adminpass1234');
  const rq = await (await admin.req('/admin/review')).text();
  assert.ok(rq.includes(token), 'item in review queue');
  const csrf = csrfFrom(rq);
  assert.equal((await admin.req('/admin/review/' + token + '/allow', form({ _csrf: csrf }))).status, 302);

  // Now viewable
  assert.equal((await req('/i/' + token)).status, 200);
  scorer = async () => 0;
});

test('blocklist: admin adds a hash, matching upload is auto-quarantined; blocklist+ban bans owner', async () => {
  const admin = await loginConsent('adminm', 'adminpass1234');
  const adminCsrf = csrfFrom(await (await admin.req('/admin/review')).text());

  // A distinctive image; add its hash to the blocklist (image not stored).
  const bad = await png(180, 180, { r: 12, g: 200, b: 60 });
  const fd = new FormData();
  fd.set('_csrf', adminCsrf);
  fd.set('label', 'test-bad');
  fd.set('image', new Blob([bad], { type: 'image/png' }), 'bad.png');
  assert.equal((await admin.req('/admin/blocklist/add', { method: 'POST', body: fd })).status, 302);

  // A user uploads the same image -> auto-quarantined
  const { req } = await loginConsent('userm', 'userpass1234');
  await uploadImage(req, bad, 'reupload');
  const token = newestToken('reupload');
  const row = db.prepare('SELECT moderation_status, owner_id FROM images WHERE token = ?').get(token);
  assert.equal(row.moderation_status, 'quarantined');
  assert.equal((await req('/i/' + token)).status, 404, 'quarantined not viewable');

  // Admin: blocklist + ban the owner
  const rq = await (await admin.req('/admin/review')).text();
  const csrf = csrfFrom(rq);
  assert.equal((await admin.req('/admin/review/' + token + '/blocklist-ban', form({ _csrf: csrf }))).status, 302);
  assert.ok(bans.userBan(row.owner_id).account, 'owner is account-banned');
});
