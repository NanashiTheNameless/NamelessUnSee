'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-2fa-'));
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.RATELIMIT_ENABLED = 'false';
process.env.NSFW_CLASSIFIER_ENABLED = 'false';
process.env.TWOFA_ENABLED = 'true';
process.env.STORAGE_BACKEND = 'local';
process.env.TWOFA_CHALLENGE_MIN = '5';
process.env.RESEND_API_KEY = 'test-resend-key';
process.env.ADMIN_NOTIFY_FROM = 'security@example.test';

const { test } = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');
const db = require('../src/db');
const { hashPassword } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, csrfFrom, solveAltcha } = require('./helpers');
const { totpCode } = require('../src/twofa');
const { uuidv7 } = require('../src/util/crypto');

let lastEmail;
global.fetch = async (url, options) => {
  if (url === 'https://api.resend.com/emails') {
    lastEmail = JSON.parse(options.body);
    return new Response('', { status: 200 });
  }
  throw new Error('unexpected fetch: ' + url);
};

const now = Date.now();
db.prepare(
  `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
   VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
).run(uuidv7(now), 'twofa@example.test', 'twofauser', hashPassword('password1234'), now, now);

async function loginStep(req) {
  const altcha = await solveAltcha(req);
  return req('/login', form({
    identifier: 'twofauser',
    password: 'password1234',
    altcha,
    next: '/dashboard',
  }));
}

test('email 2FA is required, TOTP enrollment works, and TOTP is an alternative', async () => {
  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');

  let r = await loginStep(req);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /Verify login/);
  assert.ok(lastEmail && /verification code/.test(lastEmail.subject));
  assert.match(lastEmail.html, /<a href="http/);
  assert.match(lastEmail.text, /5 minutes/);
  assert.equal(lastEmail.from, 'security@example.test');
  const emailCode = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  assert.ok(emailCode);
  const challengeId = db.prepare('SELECT id FROM login_challenges ORDER BY created_at DESC LIMIT 1').get().id;
  const challengeCsrf = csrfFrom(await r.text());
  r = await req('/login/2fa/resend', form({ _csrf: challengeCsrf, next: '/dashboard' }));
  assert.equal(r.status, 429);
  db.prepare('UPDATE login_challenges SET last_sent_at = ? WHERE id = ?').run(Date.now() - 61000, challengeId);
  r = await req('/login/2fa/resend', form({ _csrf: challengeCsrf, next: '/dashboard' }));
  assert.equal(r.status, 200);
  assert.match(lastEmail.text, /5 minutes/);
  const emailLink = (lastEmail.text.match(/(http[^\s]+\/login\/2fa\/email\?token=[^\s]+)/) || [])[1];
  assert.ok(emailLink);
  assert.ok(!jar.has('sid')); // password alone did not create a session

  const linkUrl = new URL(emailLink);
  const otherBrowser = makeReq(app, newJar());
  assert.equal((await otherBrowser(linkUrl.pathname + linkUrl.search)).status, 403);
  r = await req(linkUrl.pathname + linkUrl.search);
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/dashboard');
  assert.ok(jar.has('sid'));

  let security = await req('/account/security');
  let securityHtml = await security.text();
  const securityCsrf = csrfFrom(securityHtml);
  r = await req('/account/security/totp/start', form({ _csrf: securityCsrf }));
  assert.equal(r.status, 200);
  const pending = db.prepare('SELECT totp_pending_secret FROM users WHERE username = ?').get('twofauser');
  assert.ok(pending.totp_pending_secret);
  const confirmCsrf = csrfFrom(await r.text());
  r = await req('/account/security/totp/confirm', form({
    _csrf: confirmCsrf,
    code: totpCode(pending.totp_pending_secret),
  }));
  assert.equal(r.status, 200);
  const enabled = db.prepare('SELECT totp_enabled, totp_secret FROM users WHERE username = ?').get('twofauser');
  assert.equal(enabled.totp_enabled, 1);
  assert.ok(enabled.totp_secret);

  const methodCsrf = csrfFrom(await (await req('/account?tab=security')).text());
  r = await req('/account/security/totp/method', form({ _csrf: methodCsrf, twofa_mode: 'totp' }));
  assert.equal(r.status, 200);

  const logoutCsrf = csrfFrom(await (await req('/dashboard')).text());
  await req('/logout', form({ _csrf: logoutCsrf }));
  const totpJar = newJar();
  const totpReq = makeReq(app, totpJar);
  await consent(totpReq, '/');
  r = await loginStep(totpReq);
  assert.equal(r.status, 200);
  const challenge = db.prepare('SELECT csrf_token FROM login_challenges ORDER BY created_at DESC LIMIT 1').get();
  r = await totpReq('/login/2fa', form({
    _csrf: challenge.csrf_token,
    code: totpCode(enabled.totp_secret),
    next: '/dashboard',
  }));
  assert.equal(r.status, 302);
  assert.ok(totpJar.has('sid'));
});

test('account deletion requires password + ALTCHA + 2FA (email fallback), then removes user + session', async () => {
  const now = Date.now();
  const id = uuidv7(now);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?)`
  ).run(id, 'del@example.test', 'deluser', hashPassword('password1234'), now, now);

  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');

  // Log in (email 2FA)
  const altchaLogin = await solveAltcha(req);
  let r = await req('/login', form({ identifier: 'deluser', password: 'password1234', altcha: altchaLogin, next: '/dashboard' }));
  const html2fa = await r.text();
  const emailCode = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  const challengeCsrf = csrfFrom(html2fa);
  r = await req('/login/2fa', form({ _csrf: challengeCsrf, code: emailCode, next: '/dashboard' }));
  assert.equal(r.status, 302);
  assert.ok(jar.has('sid'));

  // Start deletion: requires password + altcha
  const accountHtml = await (await req('/account?tab=security')).text();
  const csrf = csrfFrom(accountHtml);
  const altcha = await solveAltcha(req);
  r = await req('/account/security/delete/start', form({ _csrf: csrf, password: 'password1234', altcha }));
  assert.equal(r.status, 200);
  assert.ok(lastEmail && /account deletion verification code/i.test(lastEmail.subject));
  const delCode = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  assert.ok(delCode);

  // Confirm deletion
  const confirmHtml = await r.text();
  const confirmCsrf = csrfFrom(confirmHtml);
  const twofaCsrf = (confirmHtml.match(/name="_twofa_csrf" value="([^"]+)"/) || [])[1];
  assert.ok(twofaCsrf);
  r = await req('/account/security/delete/confirm', form({ _csrf: confirmCsrf, _twofa_csrf: twofaCsrf, code: delCode }));
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/?deleted=1');

  // User row should be gone and session cleared.
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get('deluser');
  assert.equal(u, undefined);
  assert.ok(!jar.has('sid'));
});

test('account deletion uses TOTP when enabled', async () => {
  const now = Date.now();
  const id = uuidv7(now);
  const secret = 'JBSWY3DPEHPK3PXP';
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at, totp_enabled, totp_secret)
     VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?, 1, ?)`
  ).run(id, 'totpdel@example.test', 'totpdel', hashPassword('password1234'), now, now, secret);

  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');

  // Login step: should offer TOTP (twofa_mode defaults to email, so login 2FA is email).
  // We'll just finish login via email so we have a session.
  const altchaLogin = await solveAltcha(req);
  let r = await req('/login', form({ identifier: 'totpdel', password: 'password1234', altcha: altchaLogin, next: '/dashboard' }));
  const html2fa = await r.text();
  const emailCode = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  const challengeCsrf = csrfFrom(html2fa);
  r = await req('/login/2fa', form({ _csrf: challengeCsrf, code: emailCode, next: '/dashboard' }));
  assert.equal(r.status, 302);
  assert.ok(jar.has('sid'));

  // Start deletion
  const accountHtml = await (await req('/account?tab=security')).text();
  const csrf = csrfFrom(accountHtml);
  const altcha = await solveAltcha(req);
  r = await req('/account/security/delete/start', form({ _csrf: csrf, password: 'password1234', altcha }));
  assert.equal(r.status, 200);
  const startHtml = await r.text();
  assert.match(startHtml, /authenticator/i);
  assert.ok(!/account deletion verification code/i.test((lastEmail && lastEmail.subject) || ''), 'no deletion email sent when TOTP enabled');

  const confirmCsrf = csrfFrom(startHtml);
  const twofaCsrf = (startHtml.match(/name="_twofa_csrf" value="([^"]+)"/) || [])[1];
  assert.ok(twofaCsrf);
  const code = totpCode(secret);
  r = await req('/account/security/delete/confirm', form({ _csrf: confirmCsrf, _twofa_csrf: twofaCsrf, code }));
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/?deleted=1');
  assert.equal(db.prepare('SELECT * FROM users WHERE username = ?').get('totpdel'), undefined);
});
