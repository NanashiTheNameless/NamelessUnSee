'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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

function encrypt(plain) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, nonce);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([MAGIC, nonce, cipher.getAuthTag(), ciphertext]);
}

function decrypt(encrypted) {
  if (encrypted.subarray(0, MAGIC.length).compare(MAGIC) !== 0) throw new Error('invalid encrypted image');
  const nonce = encrypted.subarray(4, 16);
  const tag = encrypted.subarray(16, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted.subarray(32)), decipher.final()]);
}

function encryptedObjectName(name) {
  return name.endsWith('.enc') ? name : name + '.enc';
}

function localEncryptedPath(name) {
  return beneath(config.uploadDir, encryptedObjectName(name));
}

async function put(sourcePath, storageName) {
  const encrypted = encrypt(await fs.promises.readFile(sourcePath));
  if (useS3) {
    await client.send(new PutObjectCommand({
      Bucket: s3cfg.bucket,
      Key: encryptedObjectName(storageName),
      Body: encrypted,
      ContentType: 'application/octet-stream',
      ServerSideEncryption: 'AES256',
    }));
  } else {
    await fs.promises.mkdir(path.dirname(localEncryptedPath(storageName)), { recursive: true });
    await fs.promises.writeFile(localEncryptedPath(storageName), encrypted, { mode: 0o600 });
  }
  return { storage_name: storageName, storage_backend: useS3 ? config.storage.backend : 'local', storage_encrypted: 1 };
}

async function encryptedBytes(img) {
  if (img.storage_backend !== 'local') {
    const obj = await client.send(new GetObjectCommand({
      Bucket: s3cfg.bucket,
      Key: encryptedObjectName(img.storage_name),
    }));
    return Buffer.from(await obj.Body.transformToByteArray());
  }
  return fs.promises.readFile(localEncryptedPath(img.storage_name));
}

async function materialize(img) {
  if (!img.storage_encrypted) {
    const legacy = beneath(config.uploadDir, img.storage_name);
    if (!fs.existsSync(legacy)) throw new Error('image not found');
    return { path: legacy, cleanup: async () => {} };
  }
  const plain = decrypt(await encryptedBytes(img));
  const tempPath = path.join(config.tempDir, 'image-' + crypto.randomBytes(16).toString('hex') + '.bin');
  await fs.promises.writeFile(tempPath, plain, { mode: 0o600 });
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
  const data = decrypt(await encryptedBytes(img));
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', img.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline');
  res.end(data);
}

module.exports = { put, materialize, remove, send, useS3, encryptedObjectName };
