'use strict';

// Self-hosted ALTCHA proof-of-work: challenge creation and verification,
// implemented against the ALTCHA spec so the official <altcha-widget> works
// against it. No external service, no third-party requests.

const crypto = require('crypto');
const config = require('./config');

const HMAC_KEY = config.altcha.hmacKey;
const MAX_NUMBER = config.altcha.maxNumber;
const ALGO = 'SHA-256';
const CHALLENGE_TTL_MS = 10 * 60 * 1000;

// Replay prevention: remember solved challenges until they expire.
const used = new Map(); // challenge -> expiresAt
function sweepUsed() {
  const now = Date.now();
  for (const [k, exp] of used) if (exp < now) used.delete(k);
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function hmacHex(s) {
  return crypto.createHmac('sha256', HMAC_KEY).update(s).digest('hex');
}

function createChallenge() {
  const expires = Math.floor((Date.now() + CHALLENGE_TTL_MS) / 1000);
  const salt = crypto.randomBytes(12).toString('hex') + '?expires=' + expires;
  const number = crypto.randomInt(0, MAX_NUMBER);
  const challenge = sha256hex(salt + number);
  const signature = hmacHex(challenge);
  return { algorithm: ALGO, challenge, maxnumber: MAX_NUMBER, salt, signature };
}

function saltExpiry(salt) {
  const q = salt.split('?')[1];
  if (!q) return null;
  const p = new URLSearchParams(q).get('expires');
  return p ? parseInt(p, 10) * 1000 : null;
}

function verifySolution(payloadB64) {
  try {
    if (!payloadB64 || typeof payloadB64 !== 'string') return false;
    const json = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    const { algorithm, challenge, number, salt, signature } = json;
    if (algorithm !== ALGO) return false;
    if (typeof challenge !== 'string' || typeof salt !== 'string') return false;
    if (!Number.isInteger(number) || number < 0 || number > MAX_NUMBER * 4) return false;

    const exp = saltExpiry(salt);
    if (exp !== null && exp < Date.now()) return false;

    // Recompute and constant-time compare.
    const expectedChallenge = sha256hex(salt + number);
    if (!timingEqualHex(expectedChallenge, challenge)) return false;
    const expectedSig = hmacHex(expectedChallenge);
    if (!timingEqualHex(expectedSig, signature)) return false;

    // Reject replays.
    sweepUsed();
    if (used.has(challenge)) return false;
    used.set(challenge, exp || Date.now() + CHALLENGE_TTL_MS);

    return true;
  } catch {
    return false;
  }
}

// --- ALTCHA "Obfuscation" module (server side) ------------------------------
// Produces the payload the official obfuscation plugin's deobfuscate() expects:
//   base64(JSON{ parameters, cipher })
// The plaintext is AES-256-GCM encrypted with a key derived by
// PBKDF2-SHA256(nonce||counter_be32, salt, cost). Only half the derived key is
// published (parameters.keyPrefix); the browser brute-forces the counter
// (a small proof-of-work) to recover the full key and decrypt. Entirely
// offline- no challenge endpoint, no logging, nothing leaves the page.
const OBFUSCATE_COST = 5000;
const OBFUSCATE_KEY_LENGTH = 32; // bytes
const OBFUSCATE_COUNTER_MIN = 20;
const OBFUSCATE_COUNTER_MAX = 200;

function obfuscate(plaintext) {
  const nonce = crypto.randomBytes(16);
  const salt = crypto.randomBytes(16);
  const counter = crypto.randomInt(OBFUSCATE_COUNTER_MIN, OBFUSCATE_COUNTER_MAX + 1);

  // password = nonce || big-endian uint32 counter (plugin's "uint32" mode)
  const password = Buffer.alloc(nonce.length + 4);
  nonce.copy(password, 0);
  password.writeUInt32BE(counter, nonce.length);
  const derivedKey = crypto.pbkdf2Sync(password, salt, OBFUSCATE_COST, OBFUSCATE_KEY_LENGTH, 'sha256');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final(), cipher.getAuthTag()]);

  return Buffer.from(
    JSON.stringify({
      parameters: {
        algorithm: 'PBKDF2/SHA-256',
        cost: OBFUSCATE_COST,
        keyLength: OBFUSCATE_KEY_LENGTH,
        // Publish only the first half of the derived key; the solver searches
        // for the counter whose derived key starts with it.
        keyPrefix: derivedKey.toString('hex').slice(0, OBFUSCATE_KEY_LENGTH),
        nonce: nonce.toString('hex'),
        salt: salt.toString('hex'),
      },
      cipher: {
        iv: iv.toString('hex'),
        data: encrypted.toString('hex'),
      },
    }),
    'utf8'
  ).toString('base64');
}

function timingEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

module.exports = { createChallenge, verifySolution, obfuscate };
