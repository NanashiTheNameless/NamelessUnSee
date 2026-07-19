'use strict';

const crypto = require('crypto');
const config = require('./config');
const geo = require('./geo');
const bans = require('./bans');

const CONSENT_COOKIE = 'consent';
const CLOUDFLARE_INSIGHTS_SCRIPT = 'https://static.cloudflareinsights.com';
const CLOUDFLARE_INSIGHTS_CONNECT =
  'https://cloudflareinsights.com https://*.cloudflareinsights.com';

function ensureScriptNonce(res) {
  if (!res.locals.nonce) res.locals.nonce = crypto.randomBytes(16).toString('base64');
  return res.locals.nonce;
}

function scriptPolicy(res) {
  const nonce = ensureScriptNonce(res);
  return `script-src 'nonce-${nonce}' 'self' ${CLOUDFLARE_INSIGHTS_SCRIPT}; ` +
    `script-src-elem 'nonce-${nonce}' 'self' ${CLOUDFLARE_INSIGHTS_SCRIPT}`;
}

// Refuse all access from view-banned IPs (or logged-in view-banned users) before
// anything else is served. Only a lookup- no logging, no external calls.
function enforceViewBan(req, res, next) {
  if (req.path === '/healthz') return next();
  const ip = geo.clientIp(req);
  let banned = bans.isViewBannedIp(ip);
  if (!banned && req.user) banned = bans.userBan(req.user.id).view;
  if (banned) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(403).render('banned', {});
  }
  next();
}

// Applied to every response: conservative defaults, no referrer leakage,
// lock down browser features. Individual routes tighten the CSP further.
function baseSecurity(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Accept-CH',
    'UA-Arch, UA-Bitness, UA-Model, UA-Platform-Version, UA-Full-Version, UA-Full-Version-List'
  );
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()'
  );
  // Cloudflare Insights is allowlisted by origin; application inline scripts use
  // a per-response nonce instead of unsafe-inline.
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; " +
      `font-src 'self'; ${scriptPolicy(res)}; worker-src 'self' blob:; ` +
      `form-action 'self'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self' ${CLOUDFLARE_INSIGHTS_CONNECT}`
  );
  next();
}

// The ToS and Privacy pages remain collection-free on the application side.
// Cloudflare Insights is allowlisted here too because Cloudflare may inject its
// beacon automatically before the response reaches the browser.
function legalPage(req, res, next) {
  res.locals.noCollect = true; // signal: never log this request
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; " + scriptPolicy(res) + "; style-src 'unsafe-inline'; " +
      `font-src 'self'; connect-src 'self' ${CLOUDFLARE_INSIGHTS_CONNECT}; ` +
      "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader('Cache-Control', 'no-store');
  next();
}

// The consent gate (/welcome) needs the self-hosted ALTCHA proof-of-work widget
// to keep bots and scrapers out. It may load same-origin ALTCHA assets plus the
// explicitly allowlisted Cloudflare Insights script and beacon.
// Like the legal pages, the server still performs NO access logging or IP
// geolocation here: no visitor data is collected on the gate itself.
function gatePage(req, res, next) {
  res.locals.noCollect = true;
  // ALTCHA v3 solves the proof-of-work in Web Workers spawned from blob: URLs,
  // so worker-src must allow blob: while script sources remain explicitly
  // restricted to self-hosted assets and Cloudflare Insights.
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; img-src 'self' data:; media-src 'self'; " + scriptPolicy(res) + "; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; " +
      `font-src 'self'; img-src 'self' data:; connect-src 'self' ${CLOUDFLARE_INSIGHTS_CONNECT}; ` +
      "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader('Cache-Control', 'no-store');
  next();
}

// Pages that embed the ALTCHA widget but are not legal/gate pages.
// Self-hosted scripts plus Cloudflare Insights, and blob workers for the
// widget's PoW worker.
function widgetPage(req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; img-src 'self' data:; media-src 'self'; " + scriptPolicy(res) + "; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; " +
      `font-src 'self'; img-src 'self' data:; connect-src 'self' ${CLOUDFLARE_INSIGHTS_CONNECT}; ` +
      "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader('Cache-Control', 'no-store');
  next();
}

// A per-response nonce so the image-view page can run its one inline telemetry
// script without opening the door to arbitrary inline scripts.
function withScriptNonce(req, res, next) {
  const nonce = ensureScriptNonce(res);
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; " +
      `font-src 'self'; ${scriptPolicy(res)}; worker-src 'self' blob:; ` +
      `connect-src 'self' ${CLOUDFLARE_INSIGHTS_CONNECT}; form-action 'self'; ` +
      "base-uri 'none'; frame-ancestors 'none'"
  );
  next();
}

function hasConsent(req) {
  return req.signedCookies && req.signedCookies[CONSENT_COOKIE] === '1';
}

// Session-scoped consent cookie (no maxAge => cleared when the browser closes,
// so the warning is shown once per browsing session).
function grantConsent(res) {
  res.cookie(CONSENT_COOKIE, '1', {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    signed: true,
    path: '/',
    // no maxAge / expires => session cookie
  });
}

// Gate for image-view routes: require consent before any viewer data is
// collected or any image is rendered.
function requireConsent(req, res, next) {
  if (hasConsent(req)) return next();
  return res.redirect('/welcome?next=' + encodeURIComponent(req.originalUrl));
}

module.exports = {
  CONSENT_COOKIE,
  baseSecurity,
  legalPage,
  gatePage,
  widgetPage,
  withScriptNonce,
  hasConsent,
  grantConsent,
  requireConsent,
  enforceViewBan,
};
