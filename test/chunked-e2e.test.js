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
process.env.UPLOAD_CHUNK_THRESHOLD_MB = '1';
// Pinned rather than inherited: config.js loads .env when one exists, so a
// developer's local file silently changed what these tests asserted. The
// obfuscated-contact script only renders when a contact is configured, which
// is why this suite passed locally and failed in CI.
process.env.OPERATOR_CONTACT = 'operator@test.example';
process.env.RENDER_CACHE_ENABLED = 'true';
process.env.CHUNKED_UPLOAD_ENABLED = 'true';
process.env.CLIENT_VIDEO_COMPRESS = 'true';

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

test('dashboard: the upload script carries the CSP nonce and its chunk settings', async () => {
  const response = await req('/dashboard');
  const html = await response.text();
  const csp = response.headers.get('content-security-policy') || '';

  // Without a nonce the browser blocks the whole inline script under
  // `script-src 'nonce-...'`, and the upload form silently falls back to a
  // single native POST- which is exactly what chunking exists to avoid.
  const scriptSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src '));
  assert.ok(scriptSrc, 'dashboard sets a script-src policy');
  assert.ok(!scriptSrc.includes("'unsafe-inline'"), 'inline scripts are not blanket-allowed');
  const nonce = scriptSrc.match(/'nonce-([^']+)'/)[1];
  assert.ok(html.includes(`<script nonce="${nonce}">`), 'the inline upload script is nonced');

  assert.match(html, /const CHUNK_THRESHOLD = \d+;/, 'chunk threshold rendered as a number');
  assert.match(html, /const CHUNK_ENABLED = (true|false);/, 'chunking flag rendered as a boolean');
  assert.ok(html.includes(`const CHUNK_THRESHOLD = ${config.chunkedUpload.thresholdBytes};`), 'threshold matches config');
  assert.ok(html.includes(`const CHUNK_SIZE = ${config.chunkedUpload.chunkBytes};`), 'slice size matches config');
  // The two must stay distinct: slicing at the proxy limit would leave no room
  // to run several slices at once.
  assert.ok(config.chunkedUpload.chunkBytes <= config.chunkedUpload.thresholdBytes,
    'slice size must not exceed the threshold that triggers chunking');
});

test('dashboard: the rendered upload script is valid JavaScript', async () => {
  // Template interpolation lands inside a script tag, so a bad local silently
  // produces a syntax error that only shows up in a browser console.
  const html = await (await req('/dashboard')).text();
  const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/);
  assert.ok(script, 'dashboard has a nonced inline script');
  assert.doesNotThrow(() => new Function(script[1]), 'inline upload script parses');

  // The progress indicator's markup and its script must stay in agreement.
  for (const id of ['progress', 'progress-track', 'progress-bar', 'progress-label', 'progress-percent', 'progress-detail']) {
    assert.ok(html.includes(`id="${id}"`), `#${id} exists in the markup`);
    assert.ok(script[1].includes(`'${id}'`), `#${id} is referenced by the script`);
  }
  assert.ok(html.includes('class="progress-bar"'), 'progress bar element present');
  assert.ok(script[1].includes('XMLHttpRequest'), 'upload uses XHR, which can report upload progress');
  // The indicator must report both how far along it is and which slice is in
  // flight, so a long multi-segment upload never looks stalled.
  assert.match(script[1], /percent\.textContent = pct \+ '%'/, 'percentage is rendered');
  assert.match(script[1], /Segment \$\{[^}]+\} of \$\{totalChunks\}/, 'segment position is rendered');
  // Chunks are uploaded by a bounded pool, so they complete out of order and
  // progress must be summed per chunk rather than kept as a running total.
  assert.match(script[1], /const CHUNK_PARALLEL = \d+;/, 'parallelism rendered as a number');
  assert.match(script[1], /const CHUNK_SIZE = \d+;/, 'slice size rendered as a number');
  assert.ok(script[1].includes('for (const value of sent.values()) loaded += value;'),
    'progress sums in-flight chunks instead of using a running total');
  // With a pool running there is no single "current" segment to name.
  assert.match(script[1], /\$\{completed\} of \$\{totalChunks\} segments/,
    'progress reports completed segment count');
  assert.match(script[1], /\$\{inFlight\} in flight/, 'progress reports how many are on the wire');
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

test('assets: vendored third-party code is served from /vendor', async () => {
  // Third-party bundles live under public/vendor/; first-party scripts stay at
  // the root. Moving one without updating its references breaks silently in the
  // browser, so both the file and the page that loads it are checked.
  for (const asset of [
    '/vendor/altcha.min.js',
    '/vendor/altcha-obfuscation.min.js',
    '/vendor/altcha-business.css',
    '/vendor/mp4box.min.js',
    '/vendor/mp4-muxer.js',
  ]) {
    assert.equal((await req(asset)).status, 200, `GET ${asset}`);
  }
  for (const asset of ['/email-reveal.js', '/video-compress.js']) {
    assert.equal((await req(asset)).status, 200, `GET ${asset}`);
  }
  // Old locations must not silently keep working and mask a stale reference.
  assert.equal((await req('/altcha.min.js')).status, 404, 'old altcha path is gone');

  const dash = await (await req('/dashboard')).text();
  assert.ok(dash.includes('/vendor/altcha.min.js'), 'widget loads altcha from /vendor');
  assert.ok(dash.includes('/vendor/altcha-business.css'), 'widget loads altcha css from /vendor');
  const tos = await (await req('/tos')).text();
  assert.ok(tos.includes('/vendor/altcha-obfuscation.min.js'), 'legal pages load the module from /vendor');
});

test('dashboard: client-side video compression is wired up', async () => {
  const html = await (await req('/dashboard')).text();
  assert.ok(html.includes('src="/video-compress.js"'), 'compressor script is included');
  const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
  assert.match(script, /const CLIENT_VIDEO = (true|false);/, 'flag rendered as a boolean');
  assert.match(script, /maxHeight: \d+/, 'height ceiling rendered as a number');
  assert.ok(script.includes('NUSVideoCompress'), 'upload path calls the compressor');
  // A compression failure must never block the upload.
  assert.ok(script.includes('return source'), 'compression falls back to the original file');
});

test('chunked upload: concurrent, out-of-order chunks reassemble correctly', async () => {
  // The browser now runs a bounded pool, so chunks arrive interleaved and out
  // of order. The server must not care.
  const png = await bigPng();
  const init = await req('/upload/init', json({
    _csrf: csrf,
    altcha: await solveAltcha(req),
    files: [{ mime: 'image/png', size: png.length }],
  }));
  const { uploads, chunkBytes } = await init.json();
  const upload = uploads[0];
  assert.ok(upload.totalChunks > 2, 'need several chunks to interleave');

  // Reverse order, all in flight at once.
  const indices = Array.from({ length: upload.totalChunks }, (_, i) => i).reverse();
  const responses = await Promise.all(indices.map((index) => {
    const slice = png.subarray(index * chunkBytes, Math.min((index + 1) * chunkBytes, png.length));
    return req(`/upload/chunk/${upload.id}/${index}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf },
      body: slice,
    });
  }));
  assert.ok(responses.every((r) => r.status === 200), 'every concurrent chunk accepted');

  const done = await req('/upload/complete', json({
    _csrf: csrf, ids: [upload.id], title: 'parallel', ttl: '1h',
  }));
  assert.equal(done.status, 200, await done.text());

  const row = db.prepare('SELECT * FROM images WHERE title = ? ORDER BY id DESC').get('parallel');
  assert.ok(row, 'image row written');
  assert.equal(row.byte_size, png.length, 'reassembled size matches the original exactly');
  assert.equal(row.width, 900, 'and it is still a decodable image');
  assert.equal(row.height, 900);
});

test('video uploads can be disabled entirely', async () => {
  // Reload config and routes with video off, in an isolated app instance.
  const previous = process.env.VIDEO_UPLOADS_ENABLED;
  process.env.VIDEO_UPLOADS_ENABLED = 'false';
  for (const mod of ['../src/config', '../src/routes/upload', '../src/server', '../src/watermark']) {
    delete require.cache[require.resolve(mod)];
  }
  const noVideoConfig = require('../src/config');
  assert.equal(noVideoConfig.video.uploadsEnabled, false);

  // The allow-list is what every upload path checks, so a video type is refused
  // at init before a single byte is staged.
  const noVideoApp = require('../src/server');
  const jar2 = newJar();
  const req2 = makeReq(noVideoApp, jar2);
  await consent(req2, '/');
  const sol = await solveAltcha(req2);
  await req2('/login', form({ identifier: 'chunker', password: 'password1234', altcha: sol, next: '/dashboard' }));
  const dash = await (await req2('/dashboard')).text();
  const csrf2 = csrfFrom(dash);

  if (csrf2) {
    const rejected = await req2('/upload/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ _csrf: csrf2, altcha: await solveAltcha(req2), files: [{ mime: 'video/mp4', size: 1024 }] }),
    });
    assert.equal(rejected.status, 400, 'a video upload is refused');
    assert.match((await rejected.json()).error, /Unsupported file type/);
    assert.ok(!dash.includes('video/mp4'), 'the file picker no longer offers video');
    assert.ok(!dash.includes('/video-compress.js'), 'the video compressor is not loaded');
  }

  if (previous === undefined) delete process.env.VIDEO_UPLOADS_ENABLED;
  else process.env.VIDEO_UPLOADS_ENABLED = previous;
  for (const mod of ['../src/config', '../src/routes/upload', '../src/server', '../src/watermark']) {
    delete require.cache[require.resolve(mod)];
  }
});
