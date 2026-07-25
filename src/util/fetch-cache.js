'use strict';

const fs = require('fs');

// Conditional GET with ETag / Last-Modified caching, shared by the datasets that
// are downloaded once and then matched locally. Returns:
//   { status: 'ok', text } | { status: 'notmodified' } | { status: 'error' }
async function fetchText(url, cacheFile, timeoutMs = 15000) {
  const metaFile = cacheFile + '.meta';
  let meta = {};
  try {
    meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
  } catch { /* no meta yet */ }

  const headers = { 'User-Agent': 'NamelessUnSee/1.0 (+forensic-watermark)' };
  if (meta.etag) headers['If-None-Match'] = meta.etag;
  if (meta.lastModified) headers['If-Modified-Since'] = meta.lastModified;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (res.status === 304) return { status: 'notmodified' };
    if (!res.ok) return { status: 'error', code: res.status };
    const text = await res.text();
    fs.writeFileSync(cacheFile, text);
    fs.writeFileSync(
      metaFile,
      JSON.stringify({ etag: res.headers.get('etag') || null, lastModified: res.headers.get('last-modified') || null })
    );
    return { status: 'ok', text };
  } catch (e) {
    return { status: 'error', message: e.message };
  } finally {
    clearTimeout(t);
  }
}

function readCache(cacheFile) {
  try {
    return fs.readFileSync(cacheFile, 'utf8');
  } catch {
    return null;
  }
}

module.exports = { fetchText, readCache };
