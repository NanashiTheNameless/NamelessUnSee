'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');
const { parseIp, normalizeIp, RangeSet } = require('./util/ip');

const DIR = config.ipIntel.cacheDir;

// vpn/dc hold one RangeSet per address family: values from parseIp() are plain
// BigInts, so IPv4 and IPv6 must never share a set.
function emptyRanges() {
  return { v4: new RangeSet().finalize(), v6: new RangeSet().finalize() };
}

const state = {
  tor: new Set(),
  vpn: emptyRanges(),
  dc: emptyRanges(),
  torLoaded: false,
  vpnLoaded: false,
  dcLoaded: false,
};

function cachePath(name) {
  return path.join(DIR, name);
}

// Conditional GET with ETag / Last-Modified caching. Returns:
//   { status: 'ok', text } | { status: 'notmodified' } | { status: 'error' }
async function fetchText(url, cacheFile) {
  const metaFile = cacheFile + '.meta';
  let meta = {};
  try {
    meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
  } catch { /* no meta yet */ }

  const headers = { 'User-Agent': 'NamelessUnSee/1.0 (+forensic-watermark)' };
  if (meta.etag) headers['If-None-Match'] = meta.etag;
  if (meta.lastModified) headers['If-Modified-Since'] = meta.lastModified;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 15000);
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

function buildTor(text) {
  const set = new Set();
  for (const line of text.split(/\r?\n/)) {
    const ip = line.trim();
    if (!ip || ip.startsWith('#')) continue;
    const norm = normalizeIp(ip);
    if (norm) set.add(norm);
  }
  return set;
}

// Parse a list of CIDRs/IPs into per-family range sets. A line's family is
// decided by its address, so one source may mix IPv4 and IPv6 freely.
function buildRanges(texts) {
  const v4 = new RangeSet();
  const v6 = new RangeSet();
  for (const text of texts) {
    for (const line of text.split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith('#')) continue;
      const addr = l.split('/')[0];
      const p = parseIp(addr);
      if (!p) continue;
      (p.version === 4 ? v4 : v6).addCidr(l);
    }
  }
  return { v4: v4.finalize(), v6: v6.finalize() };
}

// Stable cache filename for each source URL (the first URL keeps the historic
// name so existing caches carry over).
function cacheFileFor(kind, url, index) {
  if (index === 0) return `${kind}-ipv4.txt`;
  const tag = require('crypto').createHash('sha256').update(url).digest('hex').slice(0, 12);
  return `${kind}-extra-${tag}.txt`;
}

async function refreshTor() {
  if (!config.ipIntel.tor.enabled) return;
  const cache = cachePath('tor-exits.txt');
  const r = await fetchText(config.ipIntel.tor.url, cache);
  let text = r.status === 'ok' ? r.text : readCache(cache);
  if (r.status === 'error' && !text) {
    console.warn('[NamelessUnSee] Tor list unavailable:', r.code || r.message || 'fetch failed');
    return;
  }
  if (r.status === 'notmodified' && state.torLoaded) return;
  if (text != null) {
    state.tor = buildTor(text);
    state.torLoaded = true;
    console.log(`[NamelessUnSee] Tor exit list loaded: ${state.tor.size} nodes`);
  }
}

async function refreshVpnLists() {
  if (!config.ipIntel.vpnLists.enabled) return;
  const jobs = [
    { key: 'vpn', urls: config.ipIntel.vpnLists.vpnUrls, flag: 'vpnLoaded' },
    { key: 'dc', urls: config.ipIntel.vpnLists.datacenterUrls, flag: 'dcLoaded' },
  ];
  for (const j of jobs) {
    const texts = [];
    let changed = false;
    for (let i = 0; i < j.urls.length; i++) {
      const cache = cachePath(cacheFileFor(j.key === 'dc' ? 'datacenter' : 'vpn', j.urls[i], i));
      const r = await fetchText(j.urls[i], cache);
      if (r.status === 'ok') changed = true;
      const text = r.status === 'ok' ? r.text : readCache(cache);
      if (text == null) {
        if (r.status === 'error') console.warn(`[NamelessUnSee] ${j.key} list unavailable:`, r.code || r.message || 'fetch failed');
        continue;
      }
      texts.push(text);
    }
    if (!texts.length || (!changed && state[j.flag])) continue;
    state[j.key] = buildRanges(texts);
    state[j.flag] = true;
    console.log(
      `[NamelessUnSee] ${j.key} list loaded: ${state[j.key].v4.size} IPv4 + ${state[j.key].v6.size} IPv6 ranges`
    );
  }
}

// Populate immediately from any cached copies (fast, offline-friendly).
function loadFromCache() {
  const tor = readCache(cachePath('tor-exits.txt'));
  if (tor) { state.tor = buildTor(tor); state.torLoaded = true; }
  const jobs = [
    { key: 'vpn', kind: 'vpn', urls: config.ipIntel.vpnLists.vpnUrls, flag: 'vpnLoaded' },
    { key: 'dc', kind: 'datacenter', urls: config.ipIntel.vpnLists.datacenterUrls, flag: 'dcLoaded' },
  ];
  for (const j of jobs) {
    const texts = [];
    for (let i = 0; i < j.urls.length; i++) {
      const text = readCache(cachePath(cacheFileFor(j.kind, j.urls[i], i)));
      if (text != null) texts.push(text);
    }
    if (texts.length) {
      state[j.key] = buildRanges(texts);
      state[j.flag] = true;
    }
  }
}

// Classify an IP against the loaded lists.
function classify(ip) {
  const available = state.torLoaded || state.vpnLoaded || state.dcLoaded;
  const out = { isTor: false, isVpn: false, isDatacenter: false, available };
  const p = parseIp(ip);
  if (!p) return out;

  const norm = normalizeIp(ip);
  if (state.torLoaded && norm && state.tor.has(norm)) out.isTor = true;
  const family = p.version === 4 ? 'v4' : 'v6';
  if (state.vpnLoaded && state.vpn[family].contains(p.value)) out.isVpn = true;
  if (state.dcLoaded && state.dc[family].contains(p.value)) out.isDatacenter = true;
  return out;
}

module.exports = { refreshTor, refreshVpnLists, loadFromCache, classify, _state: state };
