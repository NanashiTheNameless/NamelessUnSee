'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// Configure a throwaway instance before requiring the app.
process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-chunk-e2e-'));
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.STORAGE_BACKEND = 'local';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.MAXMIND_LICENSE_KEY = '';
process.env.ALTCHA_MAX_NUMBER = '4000';
process.env.RATELIMIT_ENABLED = 'false';
process.env.SECURE_COOKIES = 'false';
process.env.NSFW_CLASSIFIER_ENABLED = 'false';
process.env.TWOFA_ENABLED = 'false';
process.env.RESEND_API_KEY = '';
process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED = 'false';
process.env.UPLOAD_CHUNK_MB = '1'; // force a real multi-chunk upload

const { test, before } = require('node:test');
const assert = require('node:assert');
const sharp = require('sharp');

const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
const { newJar, makeReq, form, solveAltcha, consent, csrfFrom } = require('./helpers');

let req;
let csrf;

// Random pixels so PNG compression cannot shrink this below the chunk size.
async function bigPng() {
  const width = 900;
  const height = 900;
  const raw = Buffer.allocUnsafe(width * height * 3);
  for (let i = 0; i < raw.length; i += 1) raw[i] = (i * 2654435761) % 256;
  return sharp(raw, { raw: { width, height, channels: 3 } }).png({ compressionLevel: 0 }).toBuffer();
}

const json = (body) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

async function sendChunks(uploads, files, chunkBytes, headers = {}) {
  const responses = [];
  for (let f = 0; f < files.length; f += 1) {
    const buffer = files[f];
    for (let index = 0; index < uploads[f].totalChunks; index += 1) {
      const slice = buffer.subarray(index * chunkBytes, Math.min((index + 1) * chunkBytes, buffer.length));
      responses.push(await req(`/upload/chunk/${uploads[f].id}/${index}`, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf }, headers),
        body: slice,
      }));
    }
  }
  return responses;
}

before(async () => {
  const jar = newJar();
  req = makeReq(app, jar);
  await consent(req, '/');
  const sol = await solveAltcha(req);
  const r = await req('/signup', form({
    email: 'chunker@example.invalid',
    username: 'chunker',
    password: 'password1234',
    reason: 'Founding operator account for this instance.',
    altcha: sol,
  }));
  assert.equal(r.status, 302, 'first signup logs in');
  csrf = csrfFrom(await (await req('/dashboard')).text());
  assert.ok(csrf, 'csrf on dashboard');
});

test('chunked upload: a multi-chunk file lands as one stored image', async () => {
  const png = await bigPng();
  assert.ok(png.length > config.chunkedUpload.chunkBytes, 'fixture must span multiple chunks');

  const init = await req('/upload/init', json({
    _csrf: csrf,
    altcha: await solveAltcha(req),
    files: [{ mime: 'image/png', size: png.length }],
  }));
  assert.equal(init.status, 200, 'init accepted');
  const { uploads, chunkBytes } = await init.json();
  assert.equal(uploads.length, 1);
  assert.ok(uploads[0].totalChunks > 1, 'file is actually sliced');

  const sent = await sendChunks(uploads, [png], chunkBytes);
  assert.ok(sent.every((r) => r.status === 200), 'every chunk accepted');

  const done = await req('/upload/complete', json({
    _csrf: csrf, ids: uploads.map((u) => u.id), title: 'chunked', ttl: '1h', timer_start: 'upload',
  }));
  assert.equal(done.status, 200, 'complete accepted');
  const { redirect } = await done.json();
  assert.match(redirect, /^\/dashboard\?uploaded=1/);

  const row = db.prepare('SELECT * FROM images WHERE title = ? ORDER BY id DESC').get('chunked');
  assert.ok(row, 'image row written');
  assert.equal(row.byte_size, png.length, 'stored size matches the reassembled file');
  assert.equal(row.mime, 'image/png');
  assert.equal(row.width, 900);
  assert.equal(row.height, 900);
});

test('chunked upload: several files become a gallery, as on the multipart path', async () => {
  const files = [await bigPng(), await bigPng()];
  const init = await req('/upload/init', json({
    _csrf: csrf,
    altcha: await solveAltcha(req),
    files: files.map((f) => ({ mime: 'image/png', size: f.length })),
  }));
  assert.equal(init.status, 200);
  const { uploads, chunkBytes } = await init.json();

  await sendChunks(uploads, files, chunkBytes);
  const done = await req('/upload/complete', json({
    _csrf: csrf, ids: uploads.map((u) => u.id), title: 'chunked-gallery', ttl: '1h',
  }));
  assert.equal(done.status, 200);
  const { redirect } = await done.json();
  assert.match(redirect, /gallery=/, 'a multi-file batch produces a gallery');
});

test('chunked upload: the altcha solution is spent once, at init', async () => {
  const solution = await solveAltcha(req);
  const first = await req('/upload/init', json({ _csrf: csrf, altcha: solution, files: [{ mime: 'image/png', size: 1024 }] }));
  assert.equal(first.status, 200, 'a fresh solution is accepted');

  const replay = await req('/upload/init', json({ _csrf: csrf, altcha: solution, files: [{ mime: 'image/png', size: 1024 }] }));
  assert.equal(replay.status, 400, 'the same solution cannot start a second upload');
  assert.match((await replay.json()).error, /bot check/);
});

test('chunked upload: init rejects a missing bot check and a bad CSRF token', async () => {
  const noAltcha = await req('/upload/init', json({ _csrf: csrf, files: [{ mime: 'image/png', size: 1024 }] }));
  assert.equal(noAltcha.status, 400);

  const badCsrf = await req('/upload/init', json({ _csrf: 'wrong', altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: 1024 }] }));
  assert.equal(badCsrf.status, 403);
});

test('chunked upload: a chunk without the CSRF header is refused', async () => {
  const init = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: 4096 }],
  }));
  const { uploads } = await init.json();
  const r = await req(`/upload/chunk/${uploads[0].id}/0`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: Buffer.alloc(4096, 7),
  });
  assert.equal(r.status, 403, 'a raw chunk still needs the token');
});

test('chunked upload: init refuses disallowed types and oversized files', async () => {
  const badType = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'application/zip', size: 1024 }],
  }));
  assert.equal(badType.status, 400);
  assert.match((await badType.json()).error, /Unsupported file type/);

  const tooBig = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: config.maxUploadBytesHard * 4 }],
  }));
  assert.equal(tooBig.status, 400);
  assert.match((await tooBig.json()).error, /too large|Storage limit/);
});

test('chunked upload: an unknown session id is a 404, not a path probe', async () => {
  for (const id of ['../../etc/passwd', 'nope', 'A'.repeat(40)]) {
    const r = await req(`/upload/chunk/${encodeURIComponent(id)}/0`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf },
      body: Buffer.alloc(16, 1),
    });
    assert.equal(r.status, 404, `id ${id} rejected`);
  }
});

test('chunked upload: completing an unfinished upload stores nothing', async () => {
  const png = await bigPng();
  const init = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: png.length }],
  }));
  const { uploads, chunkBytes } = await init.json();
  // Send only the first slice, then try to finish.
  await req(`/upload/chunk/${uploads[0].id}/0`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf },
    body: png.subarray(0, chunkBytes),
  });

  const before = db.prepare('SELECT COUNT(*) AS n FROM images').get().n;
  const done = await req('/upload/complete', json({ _csrf: csrf, ids: [uploads[0].id], title: 'incomplete' }));
  assert.equal(done.status, 400);
  assert.match((await done.json()).error, /incomplete/i);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM images').get().n, before, 'no row written');
});

test('chunked upload: bytes beyond the declared size are refused', async () => {
  const init = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: 4096 }],
  }));
  const { uploads } = await init.json();
  const r = await req(`/upload/chunk/${uploads[0].id}/0`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf },
    body: Buffer.alloc(8192, 3), // twice what was declared
  });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /exceeds declared size/);
});

test('chunked upload: reassembled bytes must still be real media', async () => {
  const junk = Buffer.alloc(2 * 1024 * 1024, 0x41); // not an image
  const init = await req('/upload/init', json({
    _csrf: csrf, altcha: await solveAltcha(req), files: [{ mime: 'image/png', size: junk.length }],
  }));
  const { uploads, chunkBytes } = await init.json();
  await sendChunks(uploads, [junk], chunkBytes);

  const done = await req('/upload/complete', json({ _csrf: csrf, ids: uploads.map((u) => u.id), title: 'junk' }));
  assert.equal(done.status, 400, 'a declared mime type does not make it an image');
  assert.match((await done.json()).error, /not a valid image or video/);
  assert.ok(!db.prepare('SELECT id FROM images WHERE title = ?').get('junk'), 'nothing stored');
});
