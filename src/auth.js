'use strict';

const db = require('./db');
const config = require('./config');
const bans = require('./bans');
const { randomToken } = require('./util/crypto');

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const SESSION_COOKIE = 'sid';

const insertSession = db.prepare(
  'INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
);
const getSession = db.prepare('SELECT * FROM sessions WHERE id = ? AND expires_at > ?');
const deleteSession = db.prepare('DELETE FROM sessions WHERE id = ?');
const getUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const purgeExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
const purgeLoginChallenges = db.prepare('DELETE FROM login_challenges WHERE expires_at <= ?');
const purgeRecoveryChallenges = db.prepare('DELETE FROM recovery_challenges WHERE expires_at <= ?');

function createSession(res, userId) {
  const id = randomToken(32);
  const csrf = randomToken(24);
  const now = Date.now();
  insertSession.run(id, userId, csrf, now, now + SESSION_TTL_MS);
  res.cookie(SESSION_COOKIE, id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    signed: true,
    maxAge: SESSION_TTL_MS,
    path: '/',
  });
  return csrf;
}

function destroySession(req, res) {
  const id = req.signedCookies && req.signedCookies[SESSION_COOKIE];
  if (id) deleteSession.run(id);
  res.clearCookie(SESSION_COOKIE, { path: '/' });
}

// Attach req.user / req.session for every request (cheap; no logging side effects).
function attachUser(req, res, next) {
  req.user = null;
  req.session = null;
  const id = req.signedCookies && req.signedCookies[SESSION_COOKIE];
  if (id) {
    const sess = getSession.get(id, Date.now());
    if (sess) {
      const user = getUserById.get(sess.user_id);
      const accountBanned =
        user && (bans.userBan(user.id).account || bans.emailBan(user.email).account);
      if (user && user.status === 'approved' && !accountBanned) {
        req.user = user;
        req.session = sess;
      } else if (accountBanned) {
        // Revoke a banned account's session immediately.
        deleteSession.run(id);
        res.clearCookie(SESSION_COOKIE, { path: '/' });
      }
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  if (req.user.role !== 'admin' && req.user.rank !== 'owner') return res.status(403).render('error', { title: 'Forbidden', message: 'Admin access required.' });
  next();
}

function requireOwner(req, res, next) {
  if (!req.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  if (req.user.rank !== 'owner') return res.status(403).render('error', { title: 'Forbidden', message: 'Owner access required.' });
  next();
}

// CSRF: verify the token in the request body matches the session token.
function verifyCsrf(req, res, next) {
  if (!req.session) return res.status(403).render('error', { title: 'Forbidden', message: 'No active session.' });
  const token = req.body && req.body._csrf;
  if (!token || token !== req.session.csrf_token) {
    return res.status(403).render('error', { title: 'Forbidden', message: 'Invalid CSRF token. Please reload and try again.' });
  }
  next();
}

function sweepSessions() {
  purgeExpired.run(Date.now());
  purgeLoginChallenges.run(Date.now());
  purgeRecoveryChallenges.run(Date.now());
}

module.exports = {
  SESSION_COOKIE,
  createSession,
  destroySession,
  attachUser,
  requireAuth,
  requireAdmin,
  requireOwner,
  verifyCsrf,
  sweepSessions,
};
