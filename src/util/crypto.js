'use strict';

const crypto = require('crypto');

// Password hashing using scrypt (Node stdlib, no native dependency).
// Stored format: scrypt$N$r$p$saltHex$hashHex
// OWASP-recommended scrypt baseline for password storage: N=2^17, r=8, p=1.
// The parameters are stored with each hash for deterministic verification.
const SCRYPT_PARAMS = { N: 131072, r: 8, p: 1, keylen: 64, maxmem: 256 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_PARAMS.maxmem,
  });
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt.toString(
    'hex'
  )}$${derived.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length, {
      N: parseInt(N, 10),
      r: parseInt(r, 10),
      p: parseInt(p, 10),
      maxmem: Math.max(128 * parseInt(N, 10) * parseInt(r, 10) * 2, SCRYPT_PARAMS.maxmem),
    });
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

// URL-safe random token.
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// UUID version 7: sortable by millisecond timestamp, with random remainder.
function uuidv7(now = Date.now()) {
  const b = crypto.randomBytes(16);
  const ms = BigInt(now);
  b[0] = Number((ms >> 40n) & 0xffn);
  b[1] = Number((ms >> 32n) & 0xffn);
  b[2] = Number((ms >> 24n) & 0xffn);
  b[3] = Number((ms >> 16n) & 0xffn);
  b[4] = Number((ms >> 8n) & 0xffn);
  b[5] = Number(ms & 0xffn);
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

module.exports = { hashPassword, verifyPassword, randomToken, uuidv7 };
