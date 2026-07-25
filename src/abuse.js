'use strict';

const config = require('./config');
const geo = require('./geo');
const emailDomains = require('./email-domains');

// Short-lived, process-local signals. The durable controls are the database
// quotas and the rate limiter; these signals catch obvious scripted bursts
// without storing a browser fingerprint or collecting extra user data.
const activity = new Map();
const MAX_EVENTS = 40;
const WINDOW_MS = 15 * 60 * 1000;

function emailDomain(email) {
  const at = String(email || '').lastIndexOf('@');
  return at > 0 ? String(email).slice(at + 1).toLowerCase() : '';
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isDisposableEmail(email) {
  return emailDomains.isDisposableDomain(emailDomain(email));
}

function isAllowedEmail(email) {
  return emailDomains.isAllowedDomain(emailDomain(email));
}

function keyFor(req) {
  return geo.clientIp(req) || 'unknown';
}

function recordSignup(req, email) {
  const now = Date.now();
  const key = keyFor(req);
  const old = activity.get(key) || [];
  const events = old.filter((e) => e.at > now - WINDOW_MS);
  events.push({ at: now, email: emailDomain(email) });
  activity.set(key, events.slice(-MAX_EVENTS));
}

function registrationRisk(req, email) {
  const events = (activity.get(keyFor(req)) || []).filter((e) => e.at > Date.now() - WINDOW_MS);
  const domains = new Set(events.map((e) => e.email).filter(Boolean));
  // Multiple accounts for multiple domains from one network in a short period
  // is a useful abuse signal, but does not punish normal retries.
  return events.length >= 6 || domains.size >= 4;
}

function validateSignup({ email, username, password }) {
  if (typeof email !== 'string' || email.length < 3 || email.length > 254 ||
      /\s/.test(email) || !/^[^@]+@[^@]+\.[^@]+$/.test(email)) return 'Enter a valid email address.';
  // In allowlist mode the allowlist is the whole policy: an approved domain is
  // accepted even if a blocklist also happens to name it.
  if (!isAllowedEmail(email)) return 'Registration is limited to approved email domains.';
  if (!emailDomains.allowlistActive() && isDisposableEmail(email)) {
    return 'Disposable email addresses are not accepted.';
  }
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return 'Username must be 3-32 chars: letters, numbers, . _ -';
  }
  if (typeof password !== 'string' || password.length < 10 || password.length > 256) {
    return 'Password must be between 10 and 256 characters.';
  }
  return null;
}

function clearExpired() {
  const cutoff = Date.now() - WINDOW_MS;
  for (const [key, events] of activity) {
    const fresh = events.filter((e) => e.at > cutoff);
    if (fresh.length) activity.set(key, fresh);
    else activity.delete(key);
  }
}
setInterval(clearExpired, WINDOW_MS).unref();

module.exports = { emailDomain, normalizeEmail, isDisposableEmail, isAllowedEmail, validateSignup, recordSignup, registrationRisk, _activity: activity };
