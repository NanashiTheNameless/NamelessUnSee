'use strict';

// Whitelist + size bounds for the browser-collected details posted by the view
// page and the blocked page. Anything not listed here is dropped, and every
// value is truncated, so a beacon can never become an arbitrary blob store.
const KEYS = [
  'screenW', 'screenH', 'availW', 'availH', 'viewportW', 'viewportH',
  'colorDepth', 'pixelDepth', 'pixelRatio', 'screenOrientation', 'isExtended',
  'timezone', 'timezoneOffset', 'languages', 'locale',
  'platform', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
  'vendor', 'product', 'appVersion', 'webdriver', 'pdfViewerEnabled',
  'plugins', 'mimeTypes', 'cookieEnabled', 'doNotTrack', 'globalPrivacyControl',
  'onLine', 'referrer', 'connection', 'displayPreferences', 'storage',
  'performance', 'capabilities', 'userAgentData', 'webgl',
  'battery', 'mediaCapabilities', 'fontFeatures',
];

function bounded(value, depth = 0) {
  if (typeof value === 'string') return value.slice(0, 300);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => bounded(v, depth + 1));
  if (value && typeof value === 'object' && depth < 2) {
    return Object.fromEntries(Object.entries(value).slice(0, 20).map(([k, v]) => [k.slice(0, 80), bounded(v, depth + 1)]));
  }
  return undefined;
}

/** Whitelist and bound a posted telemetry payload. Always returns an object. */
function sanitize(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const out = {};
  for (const key of KEYS) {
    if (input[key] !== undefined) out[key] = bounded(input[key]);
  }
  return out;
}

module.exports = { sanitize, KEYS };
