'use strict';

const config = require('./config');

const TRUSTED_MULTIPLIER = 2;

function isOwner(user) {
  return !!user && user.rank === 'owner';
}

function isTrusted(user) {
  return !!user && (user.rank === 'trusted' || user.rank === 'owner');
}

function limits(user) {
  if (isOwner(user)) return { uploadBytes: Infinity, storageBytes: Infinity };
  const multiplier = user && user.rank === 'trusted' ? TRUSTED_MULTIPLIER : 1;
  return {
    uploadBytes: ((user && user.upload_max_bytes) || config.maxUploadBytes) * multiplier,
    storageBytes: ((user && user.storage_limit_bytes) || config.maxStorageBytes) * multiplier,
  };
}

function shouldScan(user) {
  return !isTrusted(user);
}

module.exports = { isOwner, isTrusted, limits, shouldScan, TRUSTED_MULTIPLIER };
