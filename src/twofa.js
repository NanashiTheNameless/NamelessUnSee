'use strict';

const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(input) {
  const clean = String(input || '').toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const n = ALPHABET.indexOf(char);
    if (n < 0) throw new Error('invalid base32');
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function newTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
  return value;
}

function matchingTotpCounter(secret, code, timestamp = Date.now()) {
  const supplied = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(supplied)) return null;
  const current = Math.floor(timestamp / 1000 / 30);
  for (const delta of [-1, 0, 1]) {
    const counter = current + delta;
    const expected = totpCode(secret, counter * 30000);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(supplied))) return counter;
  }
  return null;
}

function verifyTotp(secret, code, timestamp = Date.now()) {
  return matchingTotpCounter(secret, code, timestamp) !== null;
}

function otpHash(code) {
  return crypto.createHash('sha256').update(String(code)).digest('hex');
}

function newEmailCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function provisioningUri(secret, email) {
  return `otpauth://totp/NamelessUnSee:${encodeURIComponent(email)}?secret=${secret}&issuer=NamelessUnSee&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  newTotpSecret,
  totpCode,
  verifyTotp,
  matchingTotpCounter,
  otpHash,
  newEmailCode,
  provisioningUri,
};
