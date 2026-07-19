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
