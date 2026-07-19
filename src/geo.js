'use strict';

// Resolve the real client IP. Behind a Cloudflare Tunnel the true visitor IP is
// in CF-Connecting-IP; otherwise fall back to X-Forwarded-For / socket address.
function clientIp(req) {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf).trim();
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || req.ip || '';
}

// Country is free via Cloudflare's CF-IPCountry header (no external request).
function countryFromHeaders(req) {
  const c = req.headers['cf-ipcountry'];
  if (c && c !== 'XX' && c !== 'T1') return String(c).toUpperCase();
  return null;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  return (
    ip === '::1' ||
    ip === '127.0.0.1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('::ffff:127.') ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  );
}

function geoSummary(country, geo) {
  const parts = [];
  if (geo) {
    if (geo.city) parts.push(geo.city);
    if (geo.region && geo.region !== geo.city) parts.push(geo.region);
    if (geo.country) parts.push(geo.country);
  }
  if (!parts.length && country) parts.push(country);
  return parts.join(', ') || 'Unknown location';
}

module.exports = { clientIp, countryFromHeaders, isPrivateIp, geoSummary };
