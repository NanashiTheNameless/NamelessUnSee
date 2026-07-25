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
process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED = 'false'; // tests register example.test addresses
process.env.ADMIN_NOTIFY_FROM = 'security@example.test';
process.env.OPERATOR_CONTACT = 'operator@example.test'; // rejection emails point here

const { test } = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');
const db = require('../src/db');
const { hashPassword } = require('../src/util/crypto');
const { newJar, makeReq, form, consent, csrfFrom, solveAltcha } = require('./helpers');
const { totpCode } = require('../src/twofa');
const { uuidv7 } = require('../src/util/crypto');

let lastEmail;
const sentEmails = [];
global.fetch = async (url, options) => {
  if (url === 'https://api.resend.com/emails') {
    lastEmail = JSON.parse(options.body);
    sentEmails.push(lastEmail);
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

test('account deletion rejects a bad password, a bad code, and the owner account', async () => {
  const seedNow = Date.now();
  const seed = db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, rank, status, created_at, approved_at, email_verified)
     VALUES (?, ?, ?, ?, 'user', ?, 'approved', ?, ?, 1)`
  );
  seed.run(uuidv7(seedNow), 'guard@example.test', 'delguard', hashPassword('password1234'), 'user', seedNow, seedNow);
  seed.run(uuidv7(seedNow), 'ownerdel@example.test', 'ownerdel', hashPassword('password1234'), 'owner', seedNow, seedNow);

  const login = async (username) => {
    const jar = newJar();
    const req = makeReq(app, jar);
    await consent(req, '/');
    const altcha = await solveAltcha(req);
    const r = await req('/login', form({ identifier: username, password: 'password1234', altcha, next: '/dashboard' }));
    const code = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
    await req('/login/2fa', form({ _csrf: csrfFrom(await r.text()), code, next: '/dashboard' }));
    assert.ok(jar.has('sid'), `${username} logged in`);
    return req;
  };

  const req = await login('delguard');
  const csrf = csrfFrom(await (await req('/account?tab=security')).text());

  // Wrong password: no challenge is issued.
  let r = await req('/account/security/delete/start', form({ _csrf: csrf, password: 'wrongpassword', altcha: await solveAltcha(req) }));
  assert.equal(r.status, 200);
  let html = await r.text();
  assert.match(html, /Current password is incorrect/);
  assert.ok(!/_twofa_csrf/.test(html), 'no deletion challenge issued');

  // A missing/invalid ALTCHA solution is refused too.
  r = await req('/account/security/delete/start', form({ _csrf: csrf, password: 'password1234', altcha: 'bogus' }));
  assert.match(await r.text(), /Bot check failed/);
  assert.ok(db.prepare('SELECT 1 FROM users WHERE username = ?').get('delguard'), 'account still present');

  // Correct password + ALTCHA issues a challenge; a wrong code does not delete.
  r = await req('/account/security/delete/start', form({ _csrf: csrf, password: 'password1234', altcha: await solveAltcha(req) }));
  html = await r.text();
  const twofaCsrf = (html.match(/name="_twofa_csrf" value="([^"]+)"/) || [])[1];
  assert.ok(twofaCsrf, 'challenge issued');
  const goodCode = (lastEmail.text.match(/code is (\d{6})/) || [])[1];

  r = await req('/account/security/delete/confirm', form({ _csrf: csrfFrom(html), _twofa_csrf: twofaCsrf, code: '000000' }));
  assert.equal(r.status, 200);
  assert.match(await r.text(), /Invalid verification code/);
  assert.ok(db.prepare('SELECT 1 FROM users WHERE username = ?').get('delguard'), 'wrong code does not delete');

  // The right code still works after the failed attempt.
  r = await req('/account/security/delete/confirm', form({ _csrf: csrf, _twofa_csrf: twofaCsrf, code: goodCode }));
  assert.equal(r.status, 302);
  assert.equal(db.prepare('SELECT 1 FROM users WHERE username = ?').get('delguard'), undefined);

  // The owner account cannot be deleted through the web interface.
  const ownerReq = await login('ownerdel');
  const ownerCsrf = csrfFrom(await (await ownerReq('/account?tab=security')).text());
  r = await ownerReq('/account/security/delete/start', form({ _csrf: ownerCsrf, password: 'password1234', altcha: await solveAltcha(ownerReq) }));
  assert.match(await r.text(), /owner account cannot be deleted/i);
  assert.ok(db.prepare('SELECT 1 FROM users WHERE username = ?').get('ownerdel'), 'owner survives');
});

test('signup decisions carry an admin message; deny+ban blocks and notifies', async () => {
  const bans = require('../src/bans');
  const now = Date.now();
  const seedPending = (username, email) => {
    const id = uuidv7(now);
    db.prepare(
      `INSERT INTO users (id, email, username, password_hash, role, status, created_at, email_verified)
       VALUES (?, ?, ?, ?, 'user', 'pending', ?, 1)`
    ).run(id, email, username, hashPassword('password1234'), now);
    return id;
  };
  const approveMe = seedPending('pendok', 'pendok@example.test');
  const denyMe = seedPending('penddeny', 'penddeny@example.test');
  const banMe = seedPending('pendspam', 'pendspam@example.test');

  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at, email_verified)
     VALUES (?, ?, ?, ?, 'admin', 'approved', ?, ?, 1)`
  ).run(uuidv7(now), 'decider@example.test', 'decider', hashPassword('password1234'), now, now);

  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');
  const altcha = await solveAltcha(req);
  let r = await req('/login', form({ identifier: 'decider', password: 'password1234', altcha, next: '/dashboard' }));
  const code = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  await req('/login/2fa', form({ _csrf: csrfFrom(await r.text()), code, next: '/dashboard' }));

  const usersHtml = await (await req('/admin/users')).text();
  const csrf = csrfFrom(usersHtml);
  assert.match(usersHtml, /name="note"/, 'pending rows expose a message field');

  // Approve with a message: it reaches the applicant's email.
  lastEmail = null;
  assert.equal((await req(`/admin/users/${approveMe}/approve`, form({ _csrf: csrf, note: 'Welcome aboard, verified via Discord.' }))).status, 302);
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(approveMe).status, 'approved');
  assert.equal(lastEmail.to[0], 'pendok@example.test');
  assert.match(lastEmail.subject, /approved/i);
  assert.match(lastEmail.text, /Welcome aboard, verified via Discord\./);
  assert.match(lastEmail.html, /Welcome aboard, verified via Discord\./);

  // Deny with a message.
  lastEmail = null;
  assert.equal((await req(`/admin/users/${denyMe}/reject`, form({ _csrf: csrf, note: 'Could not verify your identity.' }))).status, 302);
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(denyMe).status, 'rejected');
  assert.match(lastEmail.text, /Could not verify your identity\./);

  // HTML in a note is escaped rather than injected into the email body.
  lastEmail = null;
  const escapeMe = seedPending('pendhtml', 'pendhtml@example.test');
  await req(`/admin/users/${escapeMe}/reject`, form({ _csrf: csrf, note: '<script>alert(1)</script>' }));
  assert.ok(!lastEmail.html.includes('<script>'), 'note is escaped in the HTML part');
  assert.match(lastEmail.html, /&lt;script&gt;/);

  // Deny + ban: address is blocked, and the applicant is told they are banned.
  // The internal note is kept away from the email and used as the ban reason.
  lastEmail = null;
  assert.equal((await req(`/admin/users/${banMe}/reject-ban`, form({
    _csrf: csrf,
    note: 'Automated signup flood.',
    internal_note: 'Matches the botnet pattern from last week; do not reinstate.',
  }))).status, 302);
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(banMe).status, 'rejected');
  assert.equal(lastEmail.to[0], 'pendspam@example.test');
  assert.match(lastEmail.text, /blocked from registering again/);
  assert.match(lastEmail.text, /Automated signup flood\./);
  assert.ok(!lastEmail.text.includes('botnet pattern'), 'internal note never reaches the applicant');
  assert.ok(!lastEmail.html.includes('botnet pattern'), 'internal note never reaches the applicant');
  assert.ok(bans.emailBan('pendspam@example.test').account, 'email is account-banned');
  assert.ok(bans.userBan(banMe).account, 'user id is account-banned');
  // The ban reason an admin sees is the internal note, not the emailed message.
  const banRow = bans.list().find((b) => b.kind === 'email' && b.value === 'pendspam@example.test');
  assert.equal(banRow.reason, 'Matches the botnet pattern from last week; do not reinstate.');
  // Both texts are stored as their own columns, on the audit row and the account.
  const logged = db.prepare("SELECT note, internal_note, target_id FROM audit_log WHERE action = 'reject_ban_user' ORDER BY id DESC LIMIT 1").get();
  assert.equal(logged.note, 'Automated signup flood.');
  assert.equal(logged.internal_note, 'Matches the botnet pattern from last week; do not reinstate.');
  assert.equal(logged.target_id, banMe);
  const stored = db.prepare('SELECT decision_note, decision_internal_note FROM users WHERE id = ?').get(banMe);
  assert.equal(stored.decision_note, 'Automated signup flood.');
  assert.equal(stored.decision_internal_note, 'Matches the botnet pattern from last week; do not reinstate.');
  // Both are visible to admins in the account list.
  const listHtml = await (await req('/admin/users')).text();
  assert.match(listHtml, /Automated signup flood\./);
  assert.match(listHtml, /botnet pattern/);
});

test('signup requires a stated reason, which reaches the admin notification and queue', async () => {
  const config = require('../src/config');
  const previousTo = config.resend.to;
  config.resend.to = 'admins@example.test';
  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');

  // Too short a case is refused, and no account is created.
  let r = await req('/signup', form({
    email: 'why@example.test', username: 'whyuser', password: 'password1234',
    reason: 'gimme', altcha: await solveAltcha(req),
  }));
  assert.equal(r.status, 400);
  assert.match(await r.text(), /why you want an account/i);
  assert.equal(db.prepare('SELECT 1 FROM users WHERE username = ?').get('whyuser'), undefined);

  // A real one is stored, mailed to the admins and shown in the queue.
  const reason = 'I run a small photography collective and need traceable previews for clients.';
  sentEmails.length = 0;
  r = await req('/signup', form({
    email: 'why@example.test', username: 'whyuser', password: 'password1234',
    reason, altcha: await solveAltcha(req),
  }));
  assert.equal(r.status, 200);
  const created = db.prepare('SELECT id, signup_reason, status FROM users WHERE username = ?').get('whyuser');
  assert.equal(created.status, 'pending');
  assert.equal(created.signup_reason, reason);
  const adminMail = sentEmails.find((m) => m.to[0] === 'admins@example.test');
  assert.ok(adminMail, 'admins are notified of the request');
  assert.match(adminMail.text, /Why they want an account/);
  assert.match(adminMail.text, /photography collective/);
  assert.match(adminMail.html, /photography collective/);

  const admin = makeReq(app, newJar());
  await consent(admin, '/');
  const altcha = await solveAltcha(admin);
  const lr = await admin('/login', form({ identifier: 'decider', password: 'password1234', altcha, next: '/dashboard' }));
  const code = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
  await admin('/login/2fa', form({ _csrf: csrfFrom(await lr.text()), code, next: '/dashboard' }));
  assert.match(await (await admin('/admin/users')).text(), /photography collective/, 'reason shown in the approval queue');
  config.resend.to = previousTo;
});

test('rejection points the applicant at the operator contact; owner can override either way', async () => {
  const now = Date.now();
  const targetId = uuidv7(now);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, email_verified)
     VALUES (?, ?, ?, ?, 'user', 'pending', ?, 1)`
  ).run(targetId, 'appeal@example.test', 'appealuser', hashPassword('password1234'), now);
  const ownerId = uuidv7(now);
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, rank, status, created_at, approved_at, email_verified)
     VALUES (?, ?, ?, ?, 'admin', 'owner', 'approved', ?, ?, 1)`
  ).run(ownerId, 'boss2@example.test', 'boss2', hashPassword('password1234'), now, now);

  const login = async (username) => {
    const req = makeReq(app, newJar());
    await consent(req, '/');
    const altcha = await solveAltcha(req);
    const r = await req('/login', form({ identifier: username, password: 'password1234', altcha, next: '/dashboard' }));
    const code = (lastEmail.text.match(/code is (\d{6})/) || [])[1];
    await req('/login/2fa', form({ _csrf: csrfFrom(await r.text()), code, next: '/dashboard' }));
    return req;
  };

  // An ordinary admin denies; the email tells them where to appeal.
  const adminReq = await login('decider');
  const csrf = csrfFrom(await (await adminReq('/admin/users')).text());
  lastEmail = null;
  await adminReq(`/admin/users/${targetId}/reject`, form({ _csrf: csrf }));
  assert.equal(require('../src/config').operator.contact, 'operator@example.test');
  assert.match(lastEmail.text, /operator@example\.test/);
  assert.match(lastEmail.html, /mailto:/);

  // An admin cannot override; only the owner can.
  assert.equal((await adminReq(`/admin/users/${targetId}/override`, form({ _csrf: csrf, decision: 'approved' }))).status, 403);
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(targetId).status, 'rejected');

  // The owner reinstates from the user list, and the ban from a deny+ban is lifted.
  const bans = require('../src/bans');
  bans.add({ kind: 'email', value: 'appeal@example.test', block_account: 1, block_view: 0, created_by: ownerId, expires_at: null });
  const ownerReq = await login('boss2');
  const ocsrf = csrfFrom(await (await ownerReq('/admin/users')).text());
  lastEmail = null;
  assert.equal((await ownerReq(`/admin/users/${targetId}/override`, form({ _csrf: ocsrf, decision: 'approved', note: 'Vouched for by a moderator.' }))).status, 302);
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(targetId).status, 'approved');
  assert.ok(!bans.emailBan('appeal@example.test').account, 'override clears the email ban');
  assert.match(lastEmail.text, /Vouched for by a moderator\./);

  // ...and can reverse an approval too, returning to the audit log it came from.
  const r = await ownerReq(`/admin/users/${targetId}/override`, form({ _csrf: ocsrf, decision: 'rejected', back: 'audit' }));
  assert.equal(r.headers.get('location'), '/admin/audit');
  assert.equal(db.prepare('SELECT status FROM users WHERE id = ?').get(targetId).status, 'rejected');
  // The audit log carries the target, which is what the log's override button uses.
  const entry = db.prepare("SELECT target_id FROM audit_log WHERE action = 'override_reject_user' ORDER BY id DESC LIMIT 1").get();
  assert.equal(entry.target_id, targetId);
});

test('signup verification email carries a one-click link bound to the signup browser', async () => {
  const config = require('../src/config');
  const previous = config.emailVerificationRequired;
  config.emailVerificationRequired = true;
  try {
    const jar = newJar();
    const req = makeReq(app, jar);
    await consent(req, '/');
    lastEmail = null;
    const r = await req('/signup', form({
      email: 'linkverify@example.test', username: 'linkverify', password: 'password1234',
      reason: 'I need traceable previews for a client review workflow.', altcha: await solveAltcha(req),
    }));
    assert.equal(r.status, 200);
    assert.match(await r.text(), /verification/i);
    assert.equal(db.prepare('SELECT email_verified FROM users WHERE username = ?').get('linkverify').email_verified, 0);

    // The email offers both a code and a link, as the login email does.
    assert.match(lastEmail.text, /code is \d{6}/);
    const link = (lastEmail.text.match(/(http[^\s]+\/signup\/verify\/email\?token=[^\s]+)/) || [])[1];
    assert.ok(link, 'verification email includes a link');
    assert.match(lastEmail.html, /signup\/verify\/email\?token=/);
    const url = new URL(link);

    // The link is useless in a browser that did not start the signup.
    assert.equal((await makeReq(app, newJar())(url.pathname + url.search)).status, 403);
    assert.equal(db.prepare('SELECT email_verified FROM users WHERE username = ?').get('linkverify').email_verified, 0);

    // In the original browser it completes verification and queues the account.
    const done = await req(url.pathname + url.search);
    assert.equal(done.status, 200);
    assert.equal(db.prepare('SELECT email_verified FROM users WHERE username = ?').get('linkverify').email_verified, 1);
    assert.equal(db.prepare('SELECT status FROM users WHERE username = ?').get('linkverify').status, 'pending');
  } finally {
    config.emailVerificationRequired = previous;
  }
});
