'use strict';

// Env must be set before requiring modules that read config.
process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'nus-chunk-'));
process.env.STORAGE_BACKEND = 'local';
process.env.UPLOAD_CHUNK_MB = '1';

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
