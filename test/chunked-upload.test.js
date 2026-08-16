'use strict';

// Env must be set before requiring modules that read config.
process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'nus-chunk-'));
process.env.STORAGE_BACKEND = 'local';
process.env.UPLOAD_CHUNK_MB = '1';
// Pinned so a local .env cannot change what these assert (see chunked-e2e).
process.env.UPLOAD_CHUNK_THRESHOLD_MB = '1';
process.env.UPLOAD_SESSION_TTL_MIN = '60';
process.env.RENDER_CACHE_ENABLED = 'true';
process.env.RENDER_CACHE_TTL_SEC = '300';
process.env.RENDER_CACHE_MAX_ENTRY_MB = '512';
process.env.RENDER_CACHE_MAX_TOTAL_MB = '2048';
process.env.WATERMARK_TILE_SPACING = '1.02';
process.env.WATERMARK_TILE_PADDING = '20';
process.env.WATERMARK_STAGGER = '0.5';
process.env.VIDEO_MAX_HEIGHT = '1080';
process.env.VIDEO_MAX_FPS = '30';
process.env.FFMPEG_HWACCEL = 'off'; // deterministic timings, no GPU dependency

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const chunked = require('../src/chunked-upload');
const config = require('../src/config');

const MB = 1024 * 1024;

function fill(byte, length) {
  return Buffer.alloc(length, byte);
}

test('chunked: a whole file round-trips through slices, in any order', async () => {
  const size = 2 * MB + 512;
  const session = chunked.create({ userId: 1, mime: 'image/png', size, ext: '.png' });
  assert.equal(session.totalChunks, 3);

  // Deliberately out of order: chunks are index-addressed, not appended.
  await chunked.writeChunk(session, 2, fill(3, 512));
  await chunked.writeChunk(session, 0, fill(1, MB));
  assert.equal(chunked.isComplete(session), false);
  await chunked.writeChunk(session, 1, fill(2, MB));
  assert.equal(chunked.isComplete(session), true);

  const assembled = await chunked.assemble(session);
  const bytes = await fs.promises.readFile(assembled);
  assert.equal(bytes.length, size);
  assert.ok(bytes.subarray(0, MB).every((b) => b === 1));
  assert.ok(bytes.subarray(MB, 2 * MB).every((b) => b === 2));
  assert.ok(bytes.subarray(2 * MB).every((b) => b === 3));
  await fs.promises.unlink(assembled);
});

test('chunked: declared size is a hard budget, not a hint', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: MB, ext: '.png' });
  await assert.rejects(
    () => chunked.writeChunk(session, 0, fill(1, MB + 1)),
    /exceeds declared size|chunk too large/
  );
  chunked.discard(session);
});

test('chunked: a retried chunk replaces rather than accumulates', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: MB, ext: '.png' });
  await chunked.writeChunk(session, 0, fill(1, MB));
  await chunked.writeChunk(session, 0, fill(9, MB)); // retry of the same index
  assert.equal(session.bytes, MB);
  assert.equal(chunked.isComplete(session), true);

  const assembled = await chunked.assemble(session);
  const bytes = await fs.promises.readFile(assembled);
  assert.ok(bytes.every((b) => b === 9), 'the retry should win');
  await fs.promises.unlink(assembled);
});

test('chunked: out-of-range and empty chunks are rejected', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: MB, ext: '.png' });
  await assert.rejects(() => chunked.writeChunk(session, 1, fill(1, 10)), /out of range/);
  await assert.rejects(() => chunked.writeChunk(session, -1, fill(1, 10)), /out of range/);
  await assert.rejects(() => chunked.writeChunk(session, 0, Buffer.alloc(0)), /empty chunk/);
  await assert.rejects(() => chunked.writeChunk(session, 0, 'not-a-buffer'), /empty chunk/);
  chunked.discard(session);
});

test('chunked: an incomplete upload cannot be assembled', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: 2 * MB, ext: '.png' });
  await chunked.writeChunk(session, 0, fill(1, MB));
  await assert.rejects(() => chunked.assemble(session), /incomplete/);
  chunked.discard(session);
});

test('chunked: a session belongs to exactly one user', async () => {
  const session = chunked.create({ userId: 42, mime: 'image/png', size: MB, ext: '.png' });
  assert.equal(chunked.get(session.id, 42).id, session.id);
  assert.equal(chunked.get(session.id, 43), null, 'another user must not reach it');
  assert.equal(chunked.get('../../etc/passwd', 42), null);
  chunked.discard(session);
});

test('chunked: a client-supplied id can never escape the temp directory', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: MB, ext: '.png' });
  for (const evil of ['../escape', 'a/b', '..', 'x'.repeat(200), '']) {
    assert.equal(chunked.get(evil, 1), null, `id ${JSON.stringify(evil)} must not resolve`);
  }
  chunked.discard(session);
});

test('chunked: discarding removes every staged chunk', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: 2 * MB, ext: '.png' });
  await chunked.writeChunk(session, 0, fill(1, MB));
  await chunked.writeChunk(session, 1, fill(2, MB));
  chunked.discard(session);

  await new Promise((resolve) => setTimeout(resolve, 50)); // unlinks are async
  const left = (await fs.promises.readdir(config.tempDir)).filter((f) => f.includes(session.id));
  assert.deepEqual(left, [], 'no chunk files should survive a discard');
  assert.equal(chunked.get(session.id, 1), null);
});

test('chunked: the sweeper collects chunks orphaned by a restart', async () => {
  // Sessions live in memory, so a restart leaves the files with no owner.
  const orphan = path.join(config.tempDir, 'chunk-orphaned0000000000000000-0');
  await fs.promises.writeFile(orphan, fill(1, 32));
  const old = Date.now() - (config.chunkedUpload.sessionTtlMs + 60_000);
  await fs.promises.utimes(orphan, old / 1000, old / 1000);

  await chunked.sweep();
  assert.equal(fs.existsSync(orphan), false, 'stale orphaned chunk should be swept');
});

test('chunked: the sweeper leaves fresh chunks alone', async () => {
  const fresh = path.join(config.tempDir, 'chunk-fresh00000000000000000-0');
  await fs.promises.writeFile(fresh, fill(1, 32));
  await chunked.sweep();
  assert.equal(fs.existsSync(fresh), true, 'an in-flight upload must survive a sweep');
  await fs.promises.unlink(fresh);
});

test('chunked: an expired session is unreachable and cleaned up', async () => {
  const session = chunked.create({ userId: 1, mime: 'image/png', size: MB, ext: '.png' });
  await chunked.writeChunk(session, 0, fill(1, MB));
  session.createdAt = Date.now() - (config.chunkedUpload.sessionTtlMs + 1000);
  assert.equal(chunked.get(session.id, 1), null, 'expired sessions must not resume');
});

// --- streaming storage encryption -------------------------------------------
// put/materialize stream rather than buffer, so a 4 GB ceiling no longer means
// gigabytes of resident memory. The on-disk format is unchanged.

const storage = require('../src/storage');

test('storage: encrypt/decrypt round-trips through the streaming path', async () => {
  const source = path.join(config.tempDir, 'plain-src.bin');
  const payload = Buffer.concat([fill(7, 3 * MB), Buffer.from('tail-marker')]);
  await fs.promises.writeFile(source, payload);

  const stored = await storage.put(source, 'upload/1/Images/roundtrip.bin');
  assert.equal(stored.storage_encrypted, 1);

  const materialized = await storage.materialize({ ...stored, mime: 'application/octet-stream' });
  const got = await fs.promises.readFile(materialized.path);
  assert.equal(got.length, payload.length, 'byte length survives');
  assert.ok(got.equals(payload), 'bytes survive exactly');
  await materialized.cleanup();
  await fs.promises.unlink(source);
});

test('storage: the ciphertext on disk keeps the documented header layout', async () => {
  const source = path.join(config.tempDir, 'plain-header.bin');
  await fs.promises.writeFile(source, fill(3, 1024));
  const stored = await storage.put(source, 'upload/1/Images/header.bin');

  const onDisk = await fs.promises.readFile(
    path.join(config.uploadDir, 'upload/1/Images/header.bin.enc')
  );
  assert.equal(onDisk.subarray(0, 4).toString(), 'NUS1', 'magic intact');
  assert.equal(onDisk.length, 32 + 1024, 'header + ciphertext, no padding');
  // The tag placeholder must have been overwritten with the real tag.
  assert.ok(!onDisk.subarray(16, 32).equals(Buffer.alloc(16)), 'auth tag written back');

  const materialized = await storage.materialize({ ...stored });
  assert.ok((await fs.promises.readFile(materialized.path)).equals(fill(3, 1024)));
  await materialized.cleanup();
  await fs.promises.unlink(source);
});

test('storage: a tampered ciphertext is rejected, not silently served', async () => {
  const source = path.join(config.tempDir, 'plain-tamper.bin');
  await fs.promises.writeFile(source, fill(9, 4096));
  const stored = await storage.put(source, 'upload/1/Images/tamper.bin');

  const target = path.join(config.uploadDir, 'upload/1/Images/tamper.bin.enc');
  const bytes = await fs.promises.readFile(target);
  bytes[40] ^= 0xff; // flip a bit inside the ciphertext
  await fs.promises.writeFile(target, bytes);

  await assert.rejects(() => storage.materialize({ ...stored }), /auth|decrypt|unable/i);
  await fs.promises.unlink(source);
});

test('storage: objects written by the old buffered encrypt still decrypt', async () => {
  // Byte-for-byte reproduction of the pre-streaming implementation. Existing
  // stored media must keep working after the switch to streaming.
  const crypto = require('crypto');
  const keyInput = config.storage.encryptionKey || config.cookieSecret;
  const KEY = /^[0-9a-f]{64}$/i.test(keyInput)
    ? Buffer.from(keyInput, 'hex')
    : crypto.createHash('sha256').update('namelessunsee-storage:' + keyInput).digest();
  const legacyEncrypt = (plain) => {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', KEY, nonce);
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([Buffer.from('NUS1'), nonce, cipher.getAuthTag(), ciphertext]);
  };

  const payload = Buffer.concat([fill(4, 2 * MB), Buffer.from('legacy-tail')]);
  const target = path.join(config.uploadDir, 'upload/1/Images/legacy.bin.enc');
  await fs.promises.mkdir(path.dirname(target), { recursive: true });
  await fs.promises.writeFile(target, legacyEncrypt(payload));

  const materialized = await storage.materialize({
    storage_name: 'upload/1/Images/legacy.bin',
    storage_backend: 'local',
    storage_encrypted: 1,
  });
  assert.ok((await fs.promises.readFile(materialized.path)).equals(payload), 'legacy object round-trips');
  await materialized.cleanup();
});

// --- video quality ceiling ---------------------------------------------------

const { execFileSync } = require('child_process');
const watermark = require('../src/watermark');

const haveFfmpeg = (() => {
  try { execFileSync('ffmpeg', ['-version'], { stdio: 'ignore' }); return true; } catch { return false; }
})();

test('video: normalisation caps resolution and framerate, and never upscales', { skip: !haveFfmpeg }, async () => {
  const src = path.join(config.tempDir, 'src-4k.mp4');
  const out = path.join(config.tempDir, 'out-4k.mp4');
  execFileSync('ffmpeg', ['-y', '-f', 'lavfi', '-i', 'testsrc=size=3840x2160:rate=60:duration=1',
    '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', src], { stdio: 'ignore' });

  await watermark.transcodeVideo(src, out);
  const capped = await watermark.probe(out);
  assert.equal(capped.height, config.video.maxHeight, 'height capped');
  assert.equal(capped.width, 1920, 'aspect ratio preserved');
  assert.ok((await fs.promises.stat(out)).size < (await fs.promises.stat(src)).size, 'capping shrinks the file');

  // A source already under the cap must come back at its own size.
  const small = path.join(config.tempDir, 'src-small.mp4');
  const smallOut = path.join(config.tempDir, 'out-small.mp4');
  execFileSync('ffmpeg', ['-y', '-f', 'lavfi', '-i', 'testsrc=size=640x360:rate=24:duration=1',
    '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p', small], { stdio: 'ignore' });
  await watermark.transcodeVideo(small, smallOut);
  const kept = await watermark.probe(smallOut);
  assert.equal(kept.width, 640, 'small source is not upscaled');
  assert.equal(kept.height, 360, 'small source is not upscaled');
});

test('video: an odd-dimension source still encodes (libx264 needs even dims)', { skip: !haveFfmpeg }, async () => {
  const src = path.join(config.tempDir, 'src-odd.mkv');
  const out = path.join(config.tempDir, 'out-odd.mp4');
  // ffv1 tolerates odd dimensions, so this reproduces a real awkward upload.
  execFileSync('ffmpeg', ['-y', '-f', 'lavfi', '-i', 'testsrc=size=1281x717:rate=25:duration=1',
    '-c:v', 'ffv1', src], { stdio: 'ignore' });

  await watermark.transcodeVideo(src, out);
  const dims = await watermark.probe(out);
  assert.equal(dims.width % 2, 0, 'width rounded to even');
  assert.equal(dims.height % 2, 0, 'height rounded to even');
});

test('storage: a client disconnecting mid-download does not throw past send()', async () => {
  const { PassThrough } = require('stream');
  const source = path.join(config.tempDir, 'plain-abort.bin');
  await fs.promises.writeFile(source, fill(5, 4 * MB));
  const stored = await storage.put(source, 'upload/1/Images/abort.bin');

  // A response that dies part-way through, as a viewer navigating away does.
  const res = new PassThrough();
  res.setHeader = () => {};
  res.headersSent = false;
  res.destroy = PassThrough.prototype.destroy.bind(res);
  res.once('data', () => { res.headersSent = true; res.emit('error', new Error('aborted')); });

  // Must resolve, not reject: callers answer a rejection with res.status(404),
  // which would throw on a response that has already sent headers.
  await storage.send(res, { ...stored, mime: 'application/octet-stream' });
  await fs.promises.unlink(source);
});

test('storage: a missing object still reports failure before any bytes are sent', async () => {
  const { PassThrough } = require('stream');
  const res = new PassThrough();
  res.setHeader = () => {};
  res.headersSent = false;
  await assert.rejects(
    () => storage.send(res, { storage_name: 'upload/1/Images/nope.bin', storage_backend: 'local', storage_encrypted: 1 }),
    'a failure before the first byte must still be reportable'
  );
});

test('chunked: assembling many chunks leaks no stream listeners', async () => {
  // A 4 GB upload at 95 MB is ~44 chunks. Attaching an error handler per chunk
  // to the same write stream trips Node's MaxListeners warning at 11 and holds
  // a closure per chunk.
  const warnings = [];
  const onWarning = (w) => warnings.push(w.name);
  process.on('warning', onWarning);
  try {
    const chunks = 44;
    const session = chunked.create({ userId: 1, mime: 'video/mp4', size: chunks * MB, ext: '.mp4' });
    for (let i = 0; i < chunks; i += 1) await chunked.writeChunk(session, i, fill(i % 256, MB));

    const assembled = await chunked.assemble(session);
    const bytes = await fs.promises.readFile(assembled);
    assert.equal(bytes.length, chunks * MB, 'every chunk landed');
    assert.equal(bytes[0], 0, 'first chunk first');
    assert.equal(bytes[MB * 43], 43, 'last chunk last, in order');
    await fs.promises.unlink(assembled);

    await new Promise((resolve) => setTimeout(resolve, 100)); // warnings are async
    assert.ok(
      !warnings.includes('MaxListenersExceededWarning'),
      'assembling must not stack a listener per chunk'
    );
  } finally {
    process.removeListener('warning', onWarning);
  }
});

test('chunked: concurrent chunks cannot race past the declared size', async () => {
  // Nothing serialises chunk requests, so the budget check must not be a
  // check-then-await-then-commit: concurrent chunks would all read the same
  // stale total and every one would pass.
  const half = MB / 2;
  const session = chunked.create({ userId: 1, mime: 'video/mp4', size: 3 * MB + half, ext: '.mp4' });
  assert.equal(session.totalChunks, 4, 'the last chunk has only half a slot');

  const results = await Promise.allSettled(
    [0, 1, 2, 3].map((i) => chunked.writeChunk(session, i, fill(i, MB)))
  );
  assert.ok(
    results.some((r) => r.status === 'rejected'),
    'the chunk that overflows the declared size must be refused'
  );
  assert.ok(session.bytes <= session.size, `staged ${session.bytes} bytes for a ${session.size} byte session`);
  chunked.discard(session);
});

test('chunked: parallel chunks that fit are all accepted', async () => {
  const session = chunked.create({ userId: 1, mime: 'video/mp4', size: 4 * MB, ext: '.mp4' });
  await Promise.all([0, 1, 2, 3].map((i) => chunked.writeChunk(session, i, fill(i, MB))));
  assert.equal(session.bytes, 4 * MB, 'every parallel chunk counted exactly once');
  assert.ok(chunked.isComplete(session), 'a parallel upload still completes');

  const assembled = await chunked.assemble(session);
  const bytes = await fs.promises.readFile(assembled);
  assert.equal(bytes[0], 0);
  assert.equal(bytes[MB * 3], 3, 'out-of-order arrival still assembles in index order');
  await fs.promises.unlink(assembled);
});

// --- watermark rendering + render cache -------------------------------------

const renderCache = require('../src/render-cache');

test('watermark: the tiled overlay still covers the whole image', async () => {
  const sharpLib = require('sharp');
  const lines = ['NamelessUnSee', 'CONFIDENTIAL', 'IP 203.0.113.44 - Berlin, DE', 'Viewed now'];
  const src = path.join(config.tempDir, 'wm-src.jpg');
  await sharpLib({ create: { width: 1200, height: 800, channels: 3, background: { r: 20, g: 20, b: 20 } } })
    .jpeg().toFile(src);

  const out = await watermark.renderWatermarked(src, lines, lines);
  const meta = await sharpLib(out).metadata();
  assert.equal(meta.width, 1200, 'dimensions preserved');
  assert.equal(meta.height, 800);

  // The mark must reach every quadrant, or a crop could remove it entirely.
  // Against a flat dark background any light pixel is overlay.
  const quadrants = [[0, 0], [600, 0], [0, 400], [600, 400]];
  for (const [left, top] of quadrants) {
    const stats = await sharpLib(out).extract({ left, top, width: 600, height: 400 }).stats();
    assert.ok(stats.channels[0].max > 100, `quadrant ${left},${top} carries watermark pixels`);
  }
  await fs.promises.unlink(src);
});

test('render cache: a different viewer never receives another viewer\'s render', async () => {
  const base = { imageToken: 'tok', viewId: 'view-1' };
  const alice = renderCache.keyFor({ ...base, identity: { ip: '1.1.1.1', geoSummary: 'Berlin, DE', deviceSummary: 'Chrome/Win' } });
  const sameAgain = renderCache.keyFor({ ...base, identity: { ip: '1.1.1.1', geoSummary: 'Berlin, DE', deviceSummary: 'Chrome/Win' } });
  assert.equal(alice, sameAgain, 'the same viewer replaying hits the same entry');

  // A stolen view id must not reach Alice's render: view ids travel in the URL.
  for (const other of [
    { ip: '2.2.2.2', geoSummary: 'Berlin, DE', deviceSummary: 'Chrome/Win' },
    { ip: '1.1.1.1', geoSummary: 'Paris, FR', deviceSummary: 'Chrome/Win' },
    { ip: '1.1.1.1', geoSummary: 'Berlin, DE', deviceSummary: 'Safari/macOS' },
  ]) {
    assert.notEqual(renderCache.keyFor({ ...base, identity: other }), alice,
      'any difference in the burned-in identity must produce a different key');
  }
  // A different link label is a different watermark too.
  assert.notEqual(
    renderCache.keyFor({ ...base, identity: { ip: '1.1.1.1', geoSummary: 'Berlin, DE', deviceSummary: 'Chrome/Win', linkLabel: 'press' } }),
    alice
  );
  assert.equal(renderCache.keyFor({ imageToken: 'tok', viewId: null, identity: {} }), null,
    'no view id means no caching');
});

test('render cache: entries expire and are evicted from disk', async () => {
  const file = path.join(config.tempDir, 'to-cache.bin');
  await fs.promises.writeFile(file, fill(1, 1024));
  const key = renderCache.keyFor({ imageToken: 't', viewId: 'v', identity: { ip: '9.9.9.9' } });

  const served = await renderCache.put(key, file);
  assert.notEqual(served, file, 'the cache adopts the file');
  assert.equal(renderCache.get(key), served, 'and serves it back');

  renderCache.invalidate();
  assert.equal(renderCache.get(key), null, 'invalidated entries are gone');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(fs.existsSync(served), false, 'and the file is removed from disk');
});

test('watermark: tiny images render rather than failing the composite', async () => {
  // sharp refuses a composite larger than its base, and the mark tile is
  // hundreds of pixels wide, so thumbnails must clamp rather than throw.
  const sharpLib = require('sharp');
  const lines = ['NamelessUnSee', 'CONFIDENTIAL', 'IP 1.2.3.4', 'Viewed now'];
  for (const [w, h] of [[1, 1], [40, 30], [120, 90]]) {
    const src = path.join(config.tempDir, `tiny-${w}x${h}.png`);
    await sharpLib({ create: { width: w, height: h, channels: 3, background: { r: 10, g: 10, b: 10 } } })
      .png().toFile(src);
    const out = await watermark.renderWatermarked(src, lines, lines);
    const meta = await sharpLib(out).metadata();
    assert.equal(meta.width, w, `${w}x${h} keeps its width`);
    assert.equal(meta.height, h, `${w}x${h} keeps its height`);
    await fs.promises.unlink(src);
  }
});

test('watermark: the identity mark is never cut off mid-string', async () => {
  // Predicting text width from character count understates a monospace face and
  // sliced the ends off the longest line. The stamp is measured from the ink it
  // actually produced, so it must always fit inside the canvas it was drawn on.
  const long = 'Ref 0192f3a7-8c14-7b2e-9d55-1f4a6b8c0e33/7f3c9a12 via press-kit';
  const lines = ['NamelessUnSee', 'CONFIDENTIAL', 'Traceable Copy', 'Do Not Redistribute',
    'IP 203.0.113.44  - Berlin, Berlin, DE - Deutsche Telekom AG',
    'Chrome 141 on Windows 11 (desktop)', 'Viewed 2026-08-16 05:28:57 UTC', long];

  for (const [w, h] of [[800, 804], [1920, 1080], [4000, 3000]]) {
    const drawn = watermark.buildMarkSvg(w, h, lines);
    const stamp = await watermark.buildMarkStamp(w, h, lines);
    assert.ok(stamp.width < drawn.width, `${w}x${h}: ink must not reach the canvas width`);
    assert.ok(stamp.height < drawn.height, `${w}x${h}: ink must not reach the canvas height`);
  }
});

test('watermark: alternate columns are offset vertically', async () => {
  // The mark is tilted, so an unstaggered grid lines each mark's tail up with
  // the next one's head. Offsetting down alternate columns breaks that up.
  const lines = ['NamelessUnSee', 'CONFIDENTIAL', 'IP 203.0.113.44 - Berlin, DE', 'Viewed now'];
  const staggered = await watermark.buildMarkPeriod(1200, 900, lines);

  const previous = process.env.WATERMARK_STAGGER;
  process.env.WATERMARK_STAGGER = '0';
  delete require.cache[require.resolve('../src/config')];
  delete require.cache[require.resolve('../src/watermark')];
  const plainWatermark = require('../src/watermark');
  const flat = await plainWatermark.buildMarkPeriod(1200, 900, lines);
  if (previous === undefined) delete process.env.WATERMARK_STAGGER;
  else process.env.WATERMARK_STAGGER = previous;
  delete require.cache[require.resolve('../src/config')];
  delete require.cache[require.resolve('../src/watermark')];

  assert.ok(!staggered.equals(flat), 'staggering must change the layout');
});
