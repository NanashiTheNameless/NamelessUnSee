'use strict';

const path = require('path');
const config = require('./config');
const { fetchText, readCache } = require('./util/fetch-cache');

const CFG = config.abuse.disposableList;
const CACHE_FILE = path.join(CFG.cacheDir, 'disposable-email-domains.txt');

// Domains from the downloaded community blocklist. The seed list in config is
// kept separate so a failed or empty download can never weaken it.
let fetched = new Set();

function parse(text) {
  const out = new Set();
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim().toLowerCase();
    // The upstream file is one bare domain per line; tolerate comments and
    // stray whitespace in case an operator points this at their own list.
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(line)) continue;
    out.add(line);
  }
  return out;
}

// Exact match, or any parent domain of the address. Walking the labels keeps
// this O(number of dots) Set lookups rather than a scan of thousands of entries
// on every signup.
function matches(domain, ...sets) {
  if (!domain) return false;
  const candidates = [domain];
  let idx = domain.indexOf('.');
  while (idx !== -1) {
    candidates.push(domain.slice(idx + 1));
    idx = domain.indexOf('.', idx + 1);
  }
  for (const set of sets) {
    if (!set || !set.size) continue;
    for (const candidate of candidates) {
      if (set.has(candidate)) return true;
    }
  }
  return false;
}

function isDisposableDomain(domain) {
  return matches(domain, config.abuse.disposableEmailDomains, fetched);
}

// Allowlist mode: while it is off every domain is permitted here and the
// blocklists decide. While it is on, nothing outside the list may register.
function allowlistActive() {
  return config.abuse.emailAllowlistEnabled && config.abuse.allowedEmailDomains.size > 0;
}

function isAllowedDomain(domain) {
  if (!allowlistActive()) return true;
  return matches(domain, config.abuse.allowedEmailDomains);
}

function load(text) {
  const parsed = parse(text);
  // An empty or truncated response must not silently clear the blocklist.
  if (!parsed.size) return false;
  fetched = parsed;
  return true;
}

function loadFromCache() {
  if (!CFG.enabled) return false;
  const text = readCache(CACHE_FILE);
  return text ? load(text) : false;
}

async function refresh() {
  if (!CFG.enabled) return false;
  const res = await fetchText(CFG.url, CACHE_FILE);
  if (res.status === 'ok') return load(res.text);
  if (res.status === 'notmodified') return loadFromCache();
  return false;
}

function stats() {
  return { seed: config.abuse.disposableEmailDomains.size, fetched: fetched.size, allowlist: config.abuse.allowedEmailDomains.size };
}

// Load the cached copy, then refresh in the background on the configured
// schedule. Never throws: a missing list leaves the seed list in force.
function init() {
  if (!CFG.enabled) return;
  loadFromCache();
  refresh().catch(() => {});
  setInterval(() => refresh().catch(() => {}), Math.max(1, CFG.refreshHours) * 3600 * 1000).unref();
}

module.exports = { init, refresh, loadFromCache, isDisposableDomain, isAllowedDomain, allowlistActive, stats, _parse: parse };
