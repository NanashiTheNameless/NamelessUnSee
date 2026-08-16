'use strict';

// Chunked upload staging.
//
// A reverse proxy (Cloudflare on most plans) rejects request bodies over
// 100 MB, which would cap uploads well below MAX_UPLOAD_MB. The browser slices
// each file into UPLOAD_CHUNK_MB pieces and posts them separately; this module
// stages the pieces on disk and reassembles them into a single file that the
// normal upload pipeline (probe -> moderation -> storage) then consumes
// unchanged.
//
// Chunks are index-addressed rather than appended, so a dropped chunk can be
// retried on its own and chunks may arrive out of order. Sessions live in
// memory: the chunks themselves are on this instance's local disk, so a session
// is inherently instance-local either way.

const fs = require('fs');
const path = require('path');
const config = require('./config');
const { randomToken } = require('./util/crypto');
const { beneath } = require('./util/safe-path');

// base64url, as produced by randomToken. Never interpolate a client-supplied id
// into a path without this check.
const ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const CHUNK_PREFIX = 'chunk-';

const sessions = new Map(); // id -> session

function chunkPath(id, index) {
  if (typeof id !== 'string' || !ID_RE.test(id)) throw new Error('invalid upload id');
  if (!Number.isInteger(index) || index < 0) throw new Error('invalid chunk index');
  return beneath(config.tempDir, `${CHUNK_PREFIX}${id}-${index}`);
}

function expired(session, now = Date.now()) {
  return now - session.createdAt > config.chunkedUpload.sessionTtlMs;
}

/**
 * Register a file the client intends to upload. `size` is the client's declared
 * length; it is only a budget hint here, and every byte written is checked
 * against it, so understating it cannot buy extra quota.
 */
function create({ userId, mime, size, ext }) {
  const chunkBytes = config.chunkedUpload.chunkBytes;
  const session = {
    id: randomToken(24),
    userId,
    mime,
    ext: ext || '.bin',
    size,
    totalChunks: Math.max(1, Math.ceil(size / chunkBytes)),
    received: new Map(), // index -> byte length
    bytes: 0,
    createdAt: Date.now(),
    done: false,
  };
  sessions.set(session.id, session);
  return session;
}

function get(id, userId) {
  const session = sessions.get(id);
  if (!session || session.userId !== userId) return null;
  if (expired(session)) {
    discard(session);
    return null;
  }
  return session;
}

/**
 * Stage one chunk. Rejects an index outside the declared chunk count and any
 * write that would push the total past the declared size, so a client cannot
 * stream unbounded bytes by lying at init.
 */
async function writeChunk(session, index, buffer) {
  if (session.done) throw new Error('upload already completed');
  if (!Number.isInteger(index) || index < 0 || index >= session.totalChunks) {
    throw new Error('chunk index out of range');
  }
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw new Error('empty chunk');
  if (buffer.length > config.chunkedUpload.chunkBytes) throw new Error('chunk too large');

  // A retried chunk replaces the previous copy rather than adding to the total.
  const previous = session.received.get(index) || 0;
  const total = session.bytes - previous + buffer.length;
  if (total > session.size) throw new Error('upload exceeds declared size');

  // Reserve the budget *before* awaiting the write. Nothing serialises these
  // calls- a client is free to post several chunks at once- so checking and
  // then committing after the await lets concurrent chunks all read the same
  // stale total and every one of them pass a check that only one should.
  session.bytes = total;
  session.received.set(index, buffer.length);
  try {
    await fs.promises.writeFile(chunkPath(session.id, index), buffer, { mode: 0o600 });
  } catch (error) {
    // Hand the reservation back so a failed write does not consume budget.
    session.bytes -= buffer.length - previous;
    if (previous) session.received.set(index, previous);
    else session.received.delete(index);
    throw error;
  }
  return { received: session.received.size, total: session.totalChunks, bytes: session.bytes };
}

function isComplete(session) {
  return session.received.size === session.totalChunks && session.bytes === session.size;
}

/**
 * Concatenate the staged chunks in index order into a single file and drop the
 * pieces. Returns the assembled path, which the caller owns (and must unlink).
 */
async function assemble(session) {
  if (!isComplete(session)) throw new Error('upload is incomplete');
  const target = beneath(config.tempDir, randomToken(20) + session.ext);
  // A file handle rather than a write stream: piping N chunks into one shared
  // stream stacks listeners on it per chunk (pipeline included), and a 4 GB
  // upload is ~44 chunks- well past Node's MaxListeners threshold. Reading each
  // chunk by async iteration keeps memory flat without any shared emitter.
  const handle = await fs.promises.open(target, 'w', 0o600);
  try {
    for (let i = 0; i < session.totalChunks; i += 1) {
      const input = fs.createReadStream(chunkPath(session.id, i));
      try {
        for await (const buffer of input) await handle.write(buffer);
      } finally {
        input.destroy();
      }
    }
  } catch (error) {
    await handle.close().catch(() => {});
    fs.unlink(target, () => {});
    throw error;
  }
  await handle.close();
  session.done = true;
  discard(session);
  return target;
}

/** Drop a session and every chunk it staged. */
function discard(session) {
  if (!session) return;
  sessions.delete(session.id);
  for (const index of session.received.keys()) {
    try {
      fs.unlink(chunkPath(session.id, index), () => {});
    } catch { /* invalid path: nothing staged under it */ }
  }
  session.received.clear();
}

/**
 * Collect abandoned uploads. Sessions are in memory, so a restart orphans the
 * chunk files themselves- the on-disk pass catches those too.
 */
async function sweep() {
  const now = Date.now();
  for (const session of [...sessions.values()]) {
    if (expired(session, now)) discard(session);
  }
  let entries;
  try {
    entries = await fs.promises.readdir(config.tempDir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (!name.startsWith(CHUNK_PREFIX)) continue;
    const full = path.join(config.tempDir, name);
    try {
      const stat = await fs.promises.stat(full);
      if (now - stat.mtimeMs > config.chunkedUpload.sessionTtlMs) await fs.promises.unlink(full);
    } catch { /* already gone */ }
  }
}

setInterval(() => sweep().catch(() => {}), 15 * 60 * 1000).unref();

module.exports = { create, get, writeChunk, isComplete, assemble, discard, sweep, _sessions: sessions };
