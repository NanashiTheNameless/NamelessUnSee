'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');
const { GetObjectCommand, PutObjectCommand, DeleteObjectCommand, S3Client } = require('@aws-sdk/client-s3');
const config = require('./config');
const { beneath } = require('./util/safe-path');

const MAGIC = Buffer.from('NUS1');
const keyInput = config.storage.encryptionKey || config.cookieSecret;
const KEY = /^[0-9a-f]{64}$/i.test(keyInput)
  ? Buffer.from(keyInput, 'hex')
  : crypto.createHash('sha256').update('namelessunsee-storage:' + keyInput).digest();
// R2 uses Cloudflare's S3-compatible API. Other S3-compatible stores are also
// supported. Only encrypted bytes are uploaded.
const S3_BACKENDS = new Set(['r2', 's3']);
const useS3 = S3_BACKENDS.has(config.storage.backend);
const s3cfg = config.storage.s3;
if (!useS3 && config.storage.backend !== 'local') throw new Error('STORAGE_BACKEND must be local, r2, or s3');
if (useS3 && (!s3cfg.endpoint || !s3cfg.bucket || !s3cfg.accessKeyId || !s3cfg.secretAccessKey)) {
  const prefix = config.storage.backend === 'r2' ? 'R2_ACCOUNT_ID or R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID, and R2_SECRET_ACCESS_KEY' : 'S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY';
  throw new Error(`STORAGE_BACKEND=${config.storage.backend} requires ${prefix}`);
}
const client = useS3 ? new S3Client({
  region: s3cfg.region,
  endpoint: s3cfg.endpoint,
  forcePathStyle: s3cfg.forcePathStyle,
  credentials: { accessKeyId: s3cfg.accessKeyId, secretAccessKey: s3cfg.secretAccessKey },
}) : null;

function encryptedObjectName(name) {
  return name.endsWith('.enc') ? name : name + '.enc';
}

function localEncryptedPath(name) {
  return beneath(config.uploadDir, encryptedObjectName(name));
}

// Header layout, unchanged from the buffered implementation so existing objects
// still decrypt: MAGIC(4) | nonce(12) | tag(16) | ciphertext.
const HEADER_BYTES = MAGIC.length + 12 + 16;
const TAG_OFFSET = MAGIC.length + 12;

/**
 * Encrypt a file to another file without ever holding it in memory. GCM only
 * yields its auth tag once the whole stream is consumed, so the header goes
 * down with a placeholder tag which is overwritten in place at the end.
 */
async function encryptToFile(sourcePath, destPath) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, nonce);
  const handle = await fs.promises.open(destPath, 'w', 0o600);
  try {
    await handle.write(Buffer.concat([MAGIC, nonce, Buffer.alloc(16)]), 0, HEADER_BYTES, 0);
    await pipeline(
      fs.createReadStream(sourcePath),
      cipher,
      fs.createWriteStream(destPath, { flags: 'r+', start: HEADER_BYTES })
    );
    await handle.write(cipher.getAuthTag(), 0, 16, TAG_OFFSET);
  } finally {
    await handle.close();
  }
  return (await fs.promises.stat(destPath)).size;
}

/** Decrypt a stream of stored bytes to a file, again without buffering it. */
async function decryptStreamToFile(source, destPath) {
  const header = await readExactly(source, HEADER_BYTES);
  if (header.subarray(0, MAGIC.length).compare(MAGIC) !== 0) throw new Error('invalid encrypted image');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, header.subarray(4, 16));
  decipher.setAuthTag(header.subarray(16, HEADER_BYTES));
  await pipeline(source, decipher, fs.createWriteStream(destPath, { mode: 0o600 }));
}

// Pull a fixed number of bytes off a stream, leaving the remainder for piping.
function readExactly(stream, length) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let have = 0;
    const onReadable = () => {
      let chunk;
      while (have < length && (chunk = stream.read()) !== null) {
        chunks.push(chunk);
        have += chunk.length;
      }
      if (have < length) return;
      cleanup();
      const buffer = Buffer.concat(chunks);
      // Anything read past the header belongs to the ciphertext.
      if (buffer.length > length) stream.unshift(buffer.subarray(length));
      resolve(buffer.subarray(0, length));
    };
    const onEnd = () => { cleanup(); reject(new Error('invalid encrypted image')); };
    const onError = (err) => { cleanup(); reject(err); };
    const cleanup = () => {
      stream.removeListener('readable', onReadable);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };
    stream.on('readable', onReadable);
    stream.on('end', onEnd);
    stream.on('error', onError);
    onReadable();
  });
}

async function put(sourcePath, storageName) {
  if (useS3) {
    // Encrypt to a scratch file first: the auth tag sits in the header, so the
    // ciphertext cannot be produced in a single forward pass to the network.
    // Uploading from that file still streams, and memory stays flat.
    const scratch = path.join(config.tempDir, 'enc-' + crypto.randomBytes(16).toString('hex') + '.bin');
    try {
      const contentLength = await encryptToFile(sourcePath, scratch);
      await client.send(new PutObjectCommand({
        Bucket: s3cfg.bucket,
        Key: encryptedObjectName(storageName),
        Body: fs.createReadStream(scratch),
        ContentLength: contentLength,
        ContentType: 'application/octet-stream',
        ServerSideEncryption: 'AES256',
      }));
    } finally {
      fs.promises.unlink(scratch).catch(() => {});
    }
  } else {
    const dest = localEncryptedPath(storageName);
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    await encryptToFile(sourcePath, dest);
  }
  return { storage_name: storageName, storage_backend: useS3 ? config.storage.backend : 'local', storage_encrypted: 1 };
}

// A readable stream of the stored (still encrypted) bytes.
async function encryptedStream(img) {
  if (img.storage_backend !== 'local') {
    const obj = await client.send(new GetObjectCommand({
      Bucket: s3cfg.bucket,
      Key: encryptedObjectName(img.storage_name),
    }));
    return obj.Body;
  }
  return fs.createReadStream(localEncryptedPath(img.storage_name));
}

async function materialize(img) {
  if (!img.storage_encrypted) {
    const legacy = beneath(config.uploadDir, img.storage_name);
    if (!fs.existsSync(legacy)) throw new Error('image not found');
    return { path: legacy, cleanup: async () => {} };
  }
  // Streamed rather than buffered: this runs on every view, and a buffered
  // decrypt held the entire file in memory twice for the length of the render.
  const tempPath = path.join(config.tempDir, 'image-' + crypto.randomBytes(16).toString('hex') + '.bin');
  try {
    await decryptStreamToFile(await encryptedStream(img), tempPath);
  } catch (error) {
    await fs.promises.unlink(tempPath).catch(() => {});
    throw error;
  }
  return { path: tempPath, cleanup: async () => fs.promises.unlink(tempPath).catch(() => {}) };
}

async function remove(img) {
  if (img.storage_encrypted && img.storage_backend !== 'local') {
    await client.send(new DeleteObjectCommand({
      Bucket: s3cfg.bucket,
      Key: encryptedObjectName(img.storage_name),
    }));
    return;
  }
  await Promise.all([
    fs.promises.unlink(localEncryptedPath(img.storage_name)).catch(() => {}),
    fs.promises.unlink(beneath(config.uploadDir, img.storage_name)).catch(() => {}),
  ]);
}

async function send(res, img) {
  if (!img.storage_encrypted) {
    const legacyPath = beneath(config.uploadDir, img.storage_name);
    if (!fs.existsSync(legacyPath)) throw new Error('image not found');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', img.mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', 'inline');
    return new Promise((resolve, reject) => {
      const stream = fs.createReadStream(legacyPath);
      stream.on('error', reject);
      stream.on('end', resolve);
      stream.pipe(res);
    });
  }
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', img.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline');
  // Decrypt straight to the socket rather than buffering the whole object.
  const source = await encryptedStream(img);
  const header = await readExactly(source, HEADER_BYTES);
  if (header.subarray(0, MAGIC.length).compare(MAGIC) !== 0) throw new Error('invalid encrypted image');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, header.subarray(4, 16));
  decipher.setAuthTag(header.subarray(16, HEADER_BYTES));
  try {
    await pipeline(source, decipher, res);
  } catch (error) {
    // Once bytes are on the wire there is no status left to send: a viewer
    // navigating away mid-download lands here, and callers answer a throw with
    // res.status(404), which would itself throw on an already-sent response.
    // Only a failure before the first byte is still reportable.
    if (!res.headersSent) throw error;
    res.destroy();
  }
}

module.exports = { put, materialize, remove, send, useS3, encryptedObjectName };
