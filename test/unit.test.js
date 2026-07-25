'use strict';

// Env must be set before requiring modules that read config.
process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'nus-unit-'));
process.env.STORAGE_BACKEND = 'local';
process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED = 'false'; // assert the shipped default, not the local .env

const { test } = require('node:test');
const assert = require('node:assert');

const { parseIp, normalizeIp, RangeSet } = require('../src/util/ip');
const { hashPassword, verifyPassword, uuidv7 } = require('../src/util/crypto');
const { parseUserAgent } = require('../src/util/device');
const ranks = require('../src/ranks');
const altcha = require('../src/altcha');
const storage = require('../src/storage');
const abuse = require('../src/abuse');
const emailDomains = require('../src/email-domains');
const config = require('../src/config');
const crypto = require('crypto');

test('ip: parse IPv4', () => {
  assert.equal(parseIp('1.2.3.4').value, (1n << 24n) + (2n << 16n) + (3n << 8n) + 4n);
  assert.equal(parseIp('999.1.1.1'), null);
  assert.equal(parseIp('not-an-ip'), null);
});

test('ip: parse + normalize IPv6 and IPv4-mapped', () => {
  assert.equal(parseIp('2001:db8::1').version, 6);
  assert.equal(normalizeIp('::ffff:192.168.0.1'), '192.168.0.1');
  assert.equal(normalizeIp('2001:DB8::1'), '2001:db8:0:0:0:0:0:1');
});

test('ip: CIDR membership via RangeSet', () => {
  const rs = new RangeSet();
  rs.addCidr('10.0.0.0/24');
  rs.addCidr('192.168.1.0/25');
  rs.finalize();
  assert.ok(rs.contains(parseIp('10.0.0.255').value));
  assert.ok(!rs.contains(parseIp('10.0.1.0').value));
  assert.ok(rs.contains(parseIp('192.168.1.100').value));
  assert.ok(!rs.contains(parseIp('192.168.1.200').value));
});

test('crypto: scrypt hash/verify', () => {
  const h = hashPassword('correct horse battery staple');
  assert.ok(h.startsWith('scrypt$'));
  assert.notEqual(h, hashPassword('correct horse battery staple'), 'each password hash uses a unique salt');
  assert.ok(verifyPassword('correct horse battery staple', h));
  assert.ok(!verifyPassword('wrong', h));
});

test('crypto: user IDs are UUIDv7', () => {
  const id = uuidv7(1700000000000);
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('storage: encrypted objects always use the .enc suffix', () => {
  assert.equal(storage.encryptedObjectName('upload/user/Images/file.png'), 'upload/user/Images/file.png.enc');
  assert.equal(storage.encryptedObjectName('upload/user/Images/file.png.enc'), 'upload/user/Images/file.png.enc');
});

test('ranks: user scans, trusted skips scans, owner has unlimited quotas', () => {
  const user = { rank: 'user' };
  const trusted = { rank: 'trusted' };
  const owner = { rank: 'owner' };
  assert.equal(ranks.shouldScan(user), true);
  assert.equal(ranks.shouldScan(trusted), false);
  assert.equal(ranks.shouldScan(owner), false);
  assert.equal(ranks.limits(owner).uploadBytes, Infinity);
  assert.equal(ranks.limits(owner).storageBytes, Infinity);
  assert.equal(ranks.limits(trusted).uploadBytes, ranks.limits(user).uploadBytes * 2);
  assert.equal(ranks.limits(trusted).storageBytes, ranks.limits(user).storageBytes * 2);
});

test('ranks: trust is never granted automatically, only by rank', () => {
  const day = 24 * 3600 * 1000;
  const old = Date.now() - 400 * day;
  // Age alone never confers trust, however old the account or how long ago its
  // signup trust delay elapsed.
  assert.equal(ranks.isTrusted({ rank: 'user', created_at: old, trust_until: old }), false);
  assert.equal(ranks.isTrusted({ rank: 'user', created_at: old, trust_until: null }), false);
  assert.equal(ranks.isTrusted({ rank: 'user', created_at: old }), false);
  assert.equal(ranks.shouldScan({ rank: 'user', created_at: old, trust_until: old }), true);
  assert.equal(ranks.limits({ rank: 'user', created_at: old }).uploadBytes, ranks.limits({ rank: 'user' }).uploadBytes);
  // An admin-granted rank still waits out the new-account delay.
  assert.equal(ranks.isTrusted({ rank: 'trusted', created_at: Date.now(), trust_until: Date.now() + day }), false);
  assert.equal(ranks.isTrusted({ rank: 'trusted', created_at: old, trust_until: old }), true);
});

test('email domains: seed list covers throwaway and alias providers', () => {
  for (const address of [
    'a@mailinator.com', 'a@yopmail.com', 'a@mozmail.com', 'a@passmail.net',
    'a@passinbox.com', 'a@duck.com', 'a@addy.io', 'a@simplelogin.com',
    'a@sub.mozmail.com', // relay subdomains are covered by the parent entry
  ]) {
    assert.equal(abuse.isDisposableEmail(address), true, address);
  }
  for (const address of ['a@gmail.com', 'a@outlook.com', 'a@example.org', 'a@notmozmail.com']) {
    assert.equal(abuse.isDisposableEmail(address), false, address);
  }
});

test('email domains: blocklist parsing ignores comments and junk', () => {
  const parsed = emailDomains._parse('# comment\n\n  Mailinator.COM \n//also comment\nnot a domain\nlocalhost\nfoo.example\n');
  assert.deepEqual([...parsed].sort(), ['foo.example', 'mailinator.com']);
});

test('email domains: allowlist ships the mainstream providers but stays off until enabled', () => {
  const allowlist = config.abuse.allowedEmailDomains;
  for (const domain of ['namelessnanashi.dev', 'gmail.com', 'icloud.com', 'yahoo.com', 'proton.me', 'outlook.com']) {
    assert.ok(allowlist.has(domain), `allowlist includes ${domain}`);
  }
  // Shipping those defaults must not restrict registration on its own.
  assert.equal(config.abuse.emailAllowlistEnabled, false, 'allowlist mode is opt-in');
  assert.equal(emailDomains.allowlistActive(), false);
  assert.equal(abuse.isAllowedEmail('a@some-company.example'), true, 'any domain allowed while off');
});

test('email domains: allowlist mode admits only approved domains', () => {
  const allowlist = config.abuse.allowedEmailDomains;
  const previous = [...allowlist];
  allowlist.clear();
  allowlist.add('example.com');
  config.abuse.emailAllowlistEnabled = true;
  try {
    assert.equal(emailDomains.allowlistActive(), true);
    assert.equal(abuse.isAllowedEmail('a@example.com'), true);
    assert.equal(abuse.isAllowedEmail('a@mail.example.com'), true, 'subdomains of an approved domain');
    assert.equal(abuse.isAllowedEmail('a@notexample.com'), false, 'suffix confusion is not a match');
    assert.equal(abuse.isAllowedEmail('a@gmail.com'), false);

    const ok = { username: 'abcd', password: 'password1234' };
    assert.equal(abuse.validateSignup({ ...ok, email: 'a@example.com' }), null);
    assert.match(abuse.validateSignup({ ...ok, email: 'a@gmail.com' }), /approved email domains/);
    // An approved domain wins even if a blocklist also names it.
    allowlist.add('mailinator.com');
    assert.equal(abuse.validateSignup({ ...ok, email: 'a@mailinator.com' }), null);
  } finally {
    config.abuse.emailAllowlistEnabled = false;
    allowlist.clear();
    for (const domain of previous) allowlist.add(domain);
  }
  // Blocking resumes once allowlist mode is off again.
  assert.match(abuse.validateSignup({ username: 'abcd', password: 'password1234', email: 'a@mailinator.com' }), /Disposable/);
});

test('device: UA parsing', () => {
  const d = parseUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
  );
  assert.equal(d.browser, 'Chrome');
  assert.equal(d.os, 'Windows');
  assert.equal(d.deviceType, 'desktop');
  const m = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile Safari');
  assert.equal(m.os, 'iOS');
  assert.equal(m.deviceType, 'mobile');
});

test('phash: deterministic, low distance for same image, high for different', async () => {
  const phash = require('../src/util/phash');
  const sharp = require('sharp');
  const a = await sharp({ create: { width: 64, height: 64, channels: 3, background: { r: 200, g: 40, b: 40 } } }).png().toBuffer();
  const b = await sharp({ create: { width: 64, height: 64, channels: 3, background: { r: 40, g: 40, b: 200 } } })
    .composite([{ input: Buffer.from('<svg width="64" height="64"><circle cx="32" cy="32" r="20" fill="white"/></svg>'), top: 0, left: 0 }])
    .png()
    .toBuffer();
  const ha1 = await phash.compute(a);
  const ha2 = await phash.compute(a);
  const hb = await phash.compute(b);
  assert.equal(ha1, ha2, 'deterministic');
  assert.equal(phash.hamming(ha1, ha2), 0, 'identical -> distance 0');
  assert.ok(phash.hamming(ha1, hb) > 5, 'different images -> larger distance');
});

test('altcha: create + verify roundtrip, reject tampering + replay', () => {
  const ch = altcha.createChallenge();
  let number = -1;
  for (let n = 0; n <= ch.maxnumber; n++) {
    if (crypto.createHash('sha256').update(ch.salt + n).digest('hex') === ch.challenge) {
      number = n;
      break;
    }
  }
  assert.ok(number >= 0);
  const payload = Buffer.from(
    JSON.stringify({ algorithm: ch.algorithm, challenge: ch.challenge, number, salt: ch.salt, signature: ch.signature })
  ).toString('base64');
  assert.ok(altcha.verifySolution(payload), 'valid solution accepted');
  assert.ok(!altcha.verifySolution(payload), 'replay rejected');
  assert.ok(!altcha.verifySolution('garbage'), 'garbage rejected');
});
