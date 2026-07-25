'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-rl-'));
process.env.STORAGE_BACKEND = 'local';
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.RATELIMIT_ENABLED = 'true';
process.env.TWOFA_ENABLED = 'false';
process.env.RL_LOGIN_MAX = '3';
process.env.RESEND_API_KEY = ''; // never send real email from tests (a real key may sit in local .env)
process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED = 'false'; // tests register example.com addresses
process.env.ADMIN_NOTIFY_FROM = '';
process.env.ADMIN_NOTIFY_TO = '';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');
const { newJar, makeReq, form, solveAltcha } = require('./helpers');

test('login is rate limited after the configured max', async () => {
  const req = makeReq(app, newJar());

  // First 3 attempts: processed (401 invalid credentials)
  for (let i = 0; i < 3; i++) {
    const altcha = await solveAltcha(req);
    const body = form({ identifier: 'nobody', password: 'wrongpass123', altcha, next: '/' });
    const r = await req('/login', { method: body.method, headers: body.headers, body: body.body });
    assert.equal(r.status, 401, `attempt ${i + 1} processed`);
  }
  // 4th attempt: rate limited
  const altcha = await solveAltcha(req);
  const body = form({ identifier: 'nobody', password: 'wrongpass123', altcha, next: '/' });
  const limited = await req('/login', { method: body.method, headers: body.headers, body: body.body });
  assert.equal(limited.status, 429, 'rate limited');
  assert.ok(limited.headers.get('retry-after'), 'has Retry-After header');
});

test('admins and owners bypass the limiters; ordinary users do not', async () => {
  const db = require('../src/db');
  const { hashPassword, uuidv7 } = require('../src/util/crypto');
  const { consent } = require('./helpers');
  const now = Date.now();
  const seed = db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, rank, status, created_at, approved_at, email_verified)
     VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?, 1)`
  );
  seed.run(uuidv7(now), 'plain@rl.test', 'rlplain', hashPassword('password1234'), 'user', 'user', now, now);
  seed.run(uuidv7(now), 'admin@rl.test', 'rladmin', hashPassword('password1234'), 'admin', 'user', now, now);
  seed.run(uuidv7(now), 'owner@rl.test', 'rlowner', hashPassword('password1234'), 'user', 'owner', now, now);

  // Every identity gets its own jar AND its own client IP, so neither the
  // earlier login-limit test nor the other identities share a bucket with it.
  let nextIp = 10;
  const login = async (username) => {
    const ip = '203.0.113.' + nextIp++;
    const base = makeReq(app, newJar());
    const req = (path, opts = {}) =>
      base(path, { ...opts, headers: { ...(opts.headers || {}), 'cf-connecting-ip': ip } });
    await consent(req, '/');
    const altcha = await solveAltcha(req);
    const r = await req('/login', form({ identifier: username, password: 'password1234', altcha, next: '/dashboard' }));
    assert.equal(r.status, 302, `${username} logged in`);
    return req;
  };

  // The /account router is limited by `auth`; hammer it well past any ceiling.
  const hammer = async (req, n) => {
    const statuses = [];
    for (let i = 0; i < n; i++) statuses.push((await req('/account')).status);
    return statuses;
  };

  const plain = await login('rlplain');
  const plainStatuses = await hammer(plain, 700);
  assert.ok(plainStatuses.includes(429), 'ordinary user is eventually limited');

  for (const staff of ['rladmin', 'rlowner']) {
    const req = await login(staff);
    const statuses = await hammer(req, 700);
    assert.ok(!statuses.includes(429), `${staff} is never limited`);
    assert.ok(statuses.every((s) => s === 200), `${staff} requests all served`);
  }
});

test('signup email limit counts each address separately, not the domain', async () => {
  const { limiters } = require('../src/ratelimit');
  const config = require('../src/config');
  const max = config.abuse.signupEmailMax;

  // Drive the middleware directly: one shared client IP, different addresses at
  // the same domain. Only the address should decide the bucket.
  const call = (email) => new Promise((resolve) => {
    const req = { headers: { 'cf-connecting-ip': '203.0.113.200' }, body: { email }, user: null };
    const res = { setHeader() {}, status() { return this; }, render() { resolve(429); }, type() { return this; }, send() { resolve(429); } };
    limiters.signupEmail(req, res, () => resolve(200));
  });

  for (let i = 0; i < max; i++) {
    assert.equal(await call('asdf@gmail.com'), 200, `asdf attempt ${i + 1} allowed`);
  }
  assert.equal(await call('asdf@gmail.com'), 429, 'asdf is capped after its own quota');
  // A different local part at the same domain keeps a full, independent quota.
  for (let i = 0; i < max; i++) {
    assert.equal(await call('hjkl@gmail.com'), 200, `hjkl attempt ${i + 1} unaffected by asdf`);
  }
  assert.equal(await call('hjkl@gmail.com'), 429, 'hjkl is capped only by its own quota');
  // Case and surrounding whitespace still collapse to the same bucket.
  assert.equal(await call('  ASDF@Gmail.com '), 429, 'normalized to the same address');
});
