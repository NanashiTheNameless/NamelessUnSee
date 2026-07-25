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

function recordSignup(req) {
  const now = Date.now();
  const key = keyFor(req);
  const old = activity.get(key) || [];
  const events = old.filter((e) => e.at > now - WINDOW_MS);
  events.push({ at: now });
  activity.set(key, events.slice(-MAX_EVENTS));
}

// Volume from one network only. The mail domain deliberately plays no part:
// a household, office or campus behind one address legitimately registers with
// whatever mix of providers its people use, and counting distinct domains
// throttled exactly that. Individual addresses are still capped by the
// signup-email limiter, and the domain itself is never a bucket.
function registrationRisk(req) {
  const events = (activity.get(keyFor(req)) || []).filter((e) => e.at > Date.now() - WINDOW_MS);
  return events.length >= config.abuse.signupBurstMax;
}

// A short written case for wanting an account. Admins read it when approving,
// and a bot that cannot compose one does not get into the queue.
const REASON_MIN = 20;
const REASON_MAX = 2000;

function validateSignup({ email, username, password, reason }) {
  const stated = String(reason || '').trim();
  if (stated.length < REASON_MIN) {
    return `Tell us why you want an account (at least ${REASON_MIN} characters).`;
  }
  if (stated.length > REASON_MAX) return `Please keep your request under ${REASON_MAX} characters.`;
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
