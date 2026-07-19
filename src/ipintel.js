'use strict';

const config = require('./config');
const geo = require('./geo');
const geoip = require('./geoip');
const netlists = require('./netlists');

const CFG = config.ipIntel;

function hours(h) {
  return Math.max(1, h) * 3600 * 1000;
}

// Load cached datasets, open MaxMind readers, then refresh in the background and
// schedule automatic updates. Never throws.
async function init() {
  try {
    netlists.loadFromCache();
    await geoip.openReaders();
  } catch (e) {
    console.warn('[NamelessUnSee] ipintel init warning:', e.message);
  }

  // Initial fetch of the latest datasets (non-blocking).
  netlists.refreshTor().catch(() => {});
  netlists.refreshVpnLists().catch(() => {});
  geoip.refresh().catch(() => {});

  // Auto-update schedules.
  setInterval(() => netlists.refreshTor().catch(() => {}), hours(CFG.tor.refreshHours)).unref();
  setInterval(() => netlists.refreshVpnLists().catch(() => {}), hours(CFG.vpnLists.refreshHours)).unref();
  setInterval(() => geoip.refresh().catch(() => {}), hours(CFG.maxmind.refreshHours)).unref();
}

/**
 * Assess a viewer entirely locally (no per-viewer external calls).
 * Returns { ip, country, allowed, reason, proxy, geo, geoSummary, org }.
 */
async function assess(req) {
  const ip = geo.clientIp(req);
  const country = geo.countryFromHeaders(req);
  const base = { ip: ip || 'unknown', country, proxy: null, geo: null, org: null };

  if (!ip || geo.isPrivateIp(ip)) {
    if (CFG.allowPrivateIps) {
      return { ...base, allowed: true, reason: 'local', geoSummary: geo.geoSummary(country, null) };
    }
    return { ...base, allowed: false, reason: 'no-public-ip', geoSummary: 'Unknown location' };
  }

  const enrich = geoip.lookup(ip); // { geo, asn, org }
  const cls = netlists.classify(ip); // { isTor, isVpn, isDatacenter, available }

  const geoObj = enrich.geo
    ? { ...enrich.geo, org: enrich.org, asn: enrich.asn }
    : country || enrich.org
      ? { country: null, org: enrich.org, asn: enrich.asn }
      : null;

  const blockDc = CFG.vpnLists.blockDatacenter;
  const isProxy = cls.isTor || cls.isVpn || (blockDc && cls.isDatacenter);
  const type = cls.isTor ? 'Tor' : cls.isVpn ? 'VPN' : cls.isDatacenter ? 'Datacenter' : null;
  const proxy = {
    isProxy,
    type,
    isTor: cls.isTor,
    isVpn: cls.isVpn,
    isDatacenter: cls.isDatacenter,
    source: 'local-lists',
  };

  const geoSummary = geo.geoSummary(country, enrich.geo);
  const result = { ...base, proxy, geo: geoObj, org: enrich.org, geoSummary };

  if (!cls.available) {
    // No proxy/VPN datasets are loaded yet- we cannot verify the connection.
    const allowed = !CFG.blockOnUnknown;
    return { ...result, allowed, reason: allowed ? 'intel-unavailable-allowed' : 'intel-unavailable' };
  }

  if (isProxy && CFG.blockProxies) {
    return { ...result, allowed: false, reason: 'proxy' };
  }
  return { ...result, allowed: true, reason: 'ok' };
}

module.exports = { init, assess };
