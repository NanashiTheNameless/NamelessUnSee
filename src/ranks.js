'use strict';

const config = require('./config');

const TRUSTED_MULTIPLIER = 2;

function isOwner(user) {
  return !!user && user.rank === 'owner';
}

function isTrusted(user) {
  if (!user) return false;
  if (user.rank === 'owner') return true;
  const created = Number(user.created_at) || 0;
  const delayedUntil = created + config.abuse.newAccountTrustDelayMs;
  return user.rank === 'trusted' &&
    (!user.trust_until || user.trust_until <= Date.now()) && delayedUntil <= Date.now();
}

function limits(user) {
  if (isOwner(user)) return { uploadBytes: Infinity, storageBytes: Infinity };
  const multiplier = isTrusted(user) ? TRUSTED_MULTIPLIER : 1;
  return {
    uploadBytes: ((user && user.upload_max_bytes) || config.maxUploadBytes) * multiplier,
    storageBytes: ((user && user.storage_limit_bytes) || config.maxStorageBytes) * multiplier,
  };
}

function shouldScan(user) {
  return !isTrusted(user);
}

module.exports = { isOwner, isTrusted, limits, shouldScan, TRUSTED_MULTIPLIER };
