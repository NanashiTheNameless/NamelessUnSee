'use strict';

const express = require('express');
const db = require('../db');
const config = require('../config');
const { hashPassword, verifyPassword, randomToken, uuidv7 } = require('../util/crypto');
const { createSession, destroySession, requireAuth, verifyCsrf, SESSION_COOKIE } = require('../auth');
const { gatePage, widgetPage } = require('../middleware');
const { verifySolution } = require('../altcha');
const notify = require('../notify');
const { newEmailCode, newTotpSecret, otpHash, provisioningUri, verifyTotp, matchingTotpCounter } = require('../twofa');
const bans = require('../bans');
const geo = require('../geo');
const { limiters } = require('../ratelimit');

const router = express.Router();

const getByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const getByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const setLastIp = db.prepare('UPDATE users SET last_ip = ? WHERE id = ?');
const countUsers = db.prepare('SELECT COUNT(*) AS n FROM users');
const getUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const insertChallenge = db.prepare(
  `INSERT INTO login_challenges (id, user_id, method, code_hash, csrf_token, next_url, created_at, expires_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
);
const getChallenge = db.prepare('SELECT * FROM login_challenges WHERE id = ? AND expires_at > ?');
const deleteChallenge = db.prepare('DELETE FROM login_challenges WHERE id = ?');
const incrementChallengeAttempts = db.prepare('UPDATE login_challenges SET attempts = attempts + 1 WHERE id = ?');
const updateChallengeEmail = db.prepare('UPDATE login_challenges SET code_hash = ?, created_at = ?, expires_at = ?, resend_count = resend_count + 1, last_sent_at = ? WHERE id = ?');
const updateTotpPending = db.prepare('UPDATE users SET totp_pending_secret = ? WHERE id = ?');
const enableTotp = db.prepare('UPDATE users SET totp_secret = ?, totp_pending_secret = NULL, totp_enabled = 1, totp_last_counter = NULL, twofa_mode = \'email\' WHERE id = ?');
const disableTotp = db.prepare('UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled = 0, totp_last_counter = NULL, twofa_mode = \'email\' WHERE id = ?');
const updateTotpCounter = db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?');
const updateTwofaMode = db.prepare("UPDATE users SET twofa_mode = ? WHERE id = ? AND totp_enabled = 1");
const insertRecovery = db.prepare(
  `INSERT INTO recovery_challenges (id, user_id, kind, target, code_hash, csrf_token, created_at, expires_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
);
const getRecovery = db.prepare('SELECT * FROM recovery_challenges WHERE id = ? AND expires_at > ?');
const deleteRecovery = db.prepare('DELETE FROM recovery_challenges WHERE id = ?');
const deleteUserRecovery = db.prepare('DELETE FROM recovery_challenges WHERE user_id = ? AND kind = ?');
const incrementRecoveryAttempts = db.prepare('UPDATE recovery_challenges SET attempts = attempts + 1 WHERE id = ?');
const updateEmail = db.prepare('UPDATE users SET email = ? WHERE id = ?');
const updatePassword = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
const deleteUserSessions = db.prepare('DELETE FROM sessions WHERE user_id = ?');
const deleteOtherUserSessions = db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?');
const updateDefaults = db.prepare(
  'UPDATE users SET default_ttl = ?, default_timer_start = ?, default_max_views = ? WHERE id = ?'
);
const insertUser = db.prepare(
  `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
   VALUES (@id, @email, @username, @password_hash, @role, @status, @created_at, @approved_at)`
);
const RESEND_DELAYS = [60, 120, 180, 240];
const RESEND_LOCK_MS = 5 * 60 * 1000;

function validUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(u);
}
function validEmail(e) {
  return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
}

function safeNext(next) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//')) return '/dashboard';
  return next;
}

function clearTwofaCookie(res) {
  res.clearCookie('twofa', { path: '/' });
}

function clearTwofaBlockCookie(res) {
  res.clearCookie('twofa_block', { path: '/' });
}

function clearRecoveryCookie(res) {
  res.clearCookie('recovery', { path: '/' });
}

function recoveryFromRequest(req) {
  const id = req.signedCookies && req.signedCookies.recovery;
  return id ? getRecovery.get(id, Date.now()) : null;
}

async function beginRecovery(res, user, kind, target = null) {
  deleteUserRecovery.run(user.id, kind);
  const id = randomToken(24);
  const csrf = randomToken(24);
  const code = newEmailCode();
  const now = Date.now();
  insertRecovery.run(id, user.id, kind, target, otpHash(code), csrf, now, now + config.twofa.challengeTtlMs);
  res.cookie('recovery', id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    signed: true,
    maxAge: config.twofa.challengeTtlMs,
    path: '/',
  });
  const purpose = kind === 'password' ? 'password reset' : kind === 'email' ? 'email change' : 'password change';
  if (!(await notify.sendRecoveryCode(user, code, purpose))) {
    deleteRecovery.run(id);
    clearRecoveryCookie(res);
    return null;
  }
  return { csrf, csrf_token: csrf, kind, email: user.email, target };
}

function recoveryError(res, message, kind, extra = {}) {
  return res.status(400).render('recovery', { error: message, kind, email: extra.email || '', csrf: extra.csrf || '', next: extra.next || '/login' });
}

function twofaBlockUntil(req) {
  const value = req.signedCookies && req.signedCookies.twofa_block;
  const until = Number(value);
  return Number.isFinite(until) && until > Date.now() ? until : 0;
}

function renderLoginBlocked(req, res, nextUrl) {
  const until = twofaBlockUntil(req);
  return res.status(429).render('login', {
    error: `Too many email requests. Start again in ${Math.ceil((until - Date.now()) / 1000)} seconds.`,
    next: nextUrl,
    values: {},
  });
}

async function beginTwofa(res, user, nextUrl, method) {
  const id = randomToken(24);
  const csrf = randomToken(24);
  const now = Date.now();
  const code = method === 'email' ? newEmailCode() : null;
  insertChallenge.run(id, user.id, method, code ? otpHash(code) : null, csrf, nextUrl, now, now + config.twofa.challengeTtlMs);
  res.cookie('twofa', id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.secureCookies,
    signed: true,
    maxAge: config.twofa.challengeTtlMs,
    path: '/',
  });
  const link = `${config.baseUrl}/login/2fa/email?token=${encodeURIComponent(code || '')}`;
  if (method === 'email' && !(await notify.sendLoginCode(user, code, link))) {
    deleteChallenge.run(id);
    clearTwofaCookie(res);
    return null;
  }
  return { csrf, method, next: nextUrl, email: user.email, error: null, resendWaitSeconds: method === 'email' ? RESEND_DELAYS[0] : 0 };
}

// --- Sign up --------------------------------------------------------------
router.get('/signup', gatePage, widgetPage, (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.render('signup', { error: null, values: {} });
});

router.post('/signup', limiters.signup, gatePage, widgetPage, (req, res, next) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  const values = { email, username };

  if (!verifySolution(req.body.altcha))
    return res.status(400).render('signup', { error: 'Bot check failed. Please try again.', values });
  if (bans.emailBan(email).account || bans.isAccountBannedIp(geo.clientIp(req)))
    return res.status(403).render('signup', { error: 'Sign-ups are not permitted from this email or network.', values });
  if (!validEmail(email)) return res.status(400).render('signup', { error: 'Enter a valid email address.', values });
  if (!validUsername(username))
    return res.status(400).render('signup', { error: 'Username must be 3-32 chars: letters, numbers, . _ -', values });
  if (password.length < 10)
    return res.status(400).render('signup', { error: 'Password must be at least 10 characters.', values });
  if (getByEmail.get(email)) return res.status(409).render('signup', { error: 'That email is already registered.', values });
  if (getByUsername.get(username)) return res.status(409).render('signup', { error: 'That username is taken.', values });

  // The very first account is auto-approved so the system is usable out of the
  // box, but it is a regular user- admins are only ever created via the CLI
  // (`yarn create-admin`). Every subsequent signup is pending until approved.
  const isFirst = countUsers.get().n === 0;
  const now = Date.now();
  const userId = uuidv7(now);
  const info = insertUser.run({
    id: userId,
    email,
    username,
    password_hash: hashPassword(password),
    role: 'user',
    status: isFirst ? 'approved' : 'pending',
    created_at: now,
    approved_at: isFirst ? now : null,
  });

  if (isFirst) {
    setLastIp.run(geo.clientIp(req) || null, userId);
    createSession(res, userId);
    return res.redirect('/dashboard');
  }

  // Notify admins (async, best-effort).
  const user = { id: userId, username, email };
  notify.notifyPendingSignup(user).catch(() => {});
  notify.sendSignupStatus(user, 'pending').catch(() => {});
  res.render('signup-pending', {});
});

// --- Account recovery -----------------------------------------------------
function renderForgot(res, kind, error = null, notice = null, value = '') {
  res.render('forgot', { kind, error, notice, value });
}

router.get('/forgot-password', widgetPage, (req, res) => renderForgot(res, 'password'));
router.get('/forgot-email', widgetPage, (req, res) => renderForgot(res, 'email'));
router.get('/forgot-username', widgetPage, (req, res) => renderForgot(res, 'username'));

router.post('/forgot-password', limiters.login, widgetPage, async (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  if (!verifySolution(req.body.altcha)) return renderForgot(res, 'password', 'Bot check failed. Please try again.', null, identifier);
  const user = getByEmail.get(identifier.toLowerCase()) || getByUsername.get(identifier);
  if (!user) return renderForgot(res, 'password', null, 'If that account exists, a reset code has been sent to its email address.');
  const recovery = await beginRecovery(res, user, 'password');
  if (!recovery) return renderForgot(res, 'password', 'Recovery email is temporarily unavailable. Please try again later.');
  res.render('recovery', { ...recovery, error: null, next: '/login' });
});

router.post('/forgot-email', limiters.login, widgetPage, async (req, res) => {
  const username = String(req.body.username || '').trim();
  if (!verifySolution(req.body.altcha)) return renderForgot(res, 'email', 'Bot check failed. Please try again.', null, username);
  const user = getByUsername.get(username);
  if (user) await notify.sendForgottenValue(user, 'email address', user.email);
  renderForgot(res, 'email', null, 'If that username exists, a reminder is on its way to the account\'s email address. Check the inboxes you might have signed up with.');
});

router.post('/forgot-username', limiters.login, widgetPage, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!verifySolution(req.body.altcha)) return renderForgot(res, 'username', 'Bot check failed. Please try again.', null, email);
  const user = getByEmail.get(email);
  if (user) await notify.sendForgottenValue(user, 'username', user.username);
  renderForgot(res, 'username', null, 'If that email address is registered, your username is on its way to it.');
});

router.post('/forgot-password/verify', limiters.login, widgetPage, (req, res) => {
  const challenge = recoveryFromRequest(req);
  const user = challenge && getUserById.get(challenge.user_id);
  const code = String(req.body.code || '').trim();
  const password = req.body.password || '';
  if (!challenge || challenge.kind !== 'password' || challenge.attempts >= 5 || req.body._csrf !== challenge.csrf_token) {
    clearRecoveryCookie(res);
    return res.status(403).render('login', { error: 'Recovery expired. Please start again.', next: '/login', values: {} });
  }
  if (otpHash(code) !== challenge.code_hash) {
    incrementRecoveryAttempts.run(challenge.id);
    return recoveryError(res, 'Invalid recovery code.', 'password', { csrf: challenge.csrf_token, email: user ? user.email : '' });
  }
  if (password.length < 10) return recoveryError(res, 'Password must be at least 10 characters.', 'password', { csrf: challenge.csrf_token, email: user.email });
  updatePassword.run(hashPassword(password), user.id);
  deleteUserSessions.run(user.id);
  deleteRecovery.run(challenge.id);
  clearRecoveryCookie(res);
  res.redirect('/login?reset=1');
});

// --- Log in ---------------------------------------------------------------
router.get('/login', widgetPage, (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.render('login', { error: req.query.reset === '1' ? 'Password reset. Please log in with your new password.' : null, next: safeNext(req.query.next), values: {} });
});

router.post('/login', limiters.login, widgetPage, async (req, res) => {
  const identifier = (req.body.identifier || '').trim().toLowerCase();
  const password = req.body.password || '';
  const nextUrl = safeNext(req.body.next);
  const values = { identifier: req.body.identifier || '' };

  if (!verifySolution(req.body.altcha))
    return res.status(400).render('login', { error: 'Bot check failed. Please try again.', next: nextUrl, values });
  const user = getByEmail.get(identifier) || getByUsername.get(req.body.identifier || '');
  const fail = () => res.status(401).render('login', { error: 'Invalid credentials.', next: nextUrl, values });

  if (!user) return fail();
  if (!verifyPassword(password, user.password_hash)) return fail();
  if (user.status === 'pending')
    return res.status(403).render('login', { error: 'Your account is awaiting admin approval.', next: nextUrl, values });
  if (user.status === 'rejected')
    return res.status(403).render('login', { error: 'Your account request was declined.', next: nextUrl, values });

  const ip = geo.clientIp(req);
  if (bans.userBan(user.id).account || bans.emailBan(user.email).account || bans.isAccountBannedIp(ip))
    return res.status(403).render('login', { error: 'This account has been suspended.', next: nextUrl, values });

  if (!config.twofa.enabled) {
    clearTwofaBlockCookie(res);
    setLastIp.run(ip || null, user.id);
    createSession(res, user.id);
    return res.redirect(nextUrl);
  }

  if (twofaBlockUntil(req)) return renderLoginBlocked(req, res, nextUrl);

  const method = user.totp_enabled && user.twofa_mode === 'totp' ? 'totp' : 'email';
  if (method === 'totp' && !user.totp_enabled) {
    return res.status(400).render('login', {
      error: 'TOTP is not enabled for this account. Use email verification or enroll an authenticator first.',
      next: nextUrl,
      values,
    });
  }
  const challenge = await beginTwofa(res, user, nextUrl, method);
  if (!challenge) {
    return res.status(503).render('login', {
      error: 'Email verification is temporarily unavailable. Please contact the administrator.',
      next: nextUrl,
      values,
    });
  }
  res.render('login-2fa', challenge);
});

router.get('/login/2fa/email', (req, res) => {
  const challengeId = req.signedCookies && req.signedCookies.twofa;
  const challenge = challengeId && getChallenge.get(challengeId, Date.now());
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  const user = challenge && getUserById.get(challenge.user_id);
  const valid = challenge && user && challenge.method === 'email' && challenge.attempts < 5 && otpHash(token) === challenge.code_hash;
  if (!valid) return res.status(403).render('login', { error: 'This verification link is invalid, expired, or belongs to another browser.', next: '/dashboard', values: {} });
  deleteChallenge.run(challenge.id);
  clearTwofaCookie(res);
  clearTwofaBlockCookie(res);
  setLastIp.run(geo.clientIp(req) || null, user.id);
  createSession(res, user.id);
  res.redirect(safeNext(challenge.next_url));
});

router.post('/login/2fa/resend', limiters.login, widgetPage, async (req, res) => {
  const challengeId = req.signedCookies && req.signedCookies.twofa;
  const challenge = challengeId && getChallenge.get(challengeId, Date.now());
  const nextUrl = safeNext(req.body.next);
  if (!challenge || challenge.method !== 'email' || req.body._csrf !== challenge.csrf_token) {
    clearTwofaCookie(res);
    return res.status(403).render('login', { error: 'Verification expired. Please log in again.', next: nextUrl, values: {} });
  }
  const user = getUserById.get(challenge.user_id);
  if (!user) return res.status(403).render('login', { error: 'Verification expired. Please log in again.', next: nextUrl, values: {} });

  const now = Date.now();
  const count = Number(challenge.resend_count || 0);
  const delay = RESEND_DELAYS[count];
  const availableAt = (challenge.last_sent_at || challenge.created_at) + (delay || 0) * 1000;
  if (now < availableAt) {
    return res.status(429).render('login-2fa', {
      error: `Please wait ${Math.ceil((availableAt - now) / 1000)} seconds before requesting another email.`,
      csrf: challenge.csrf_token,
      method: 'email',
      next: nextUrl,
      email: user.email,
      resendWaitSeconds: Math.ceil((availableAt - now) / 1000),
    });
  }
  if (count >= RESEND_DELAYS.length) {
    const blockedUntil = now + RESEND_LOCK_MS;
    deleteChallenge.run(challenge.id);
    clearTwofaCookie(res);
    res.cookie('twofa_block', String(blockedUntil), {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.secureCookies,
      signed: true,
      maxAge: RESEND_LOCK_MS,
      path: '/',
    });
    return res.status(429).render('login', {
      error: 'Too many email requests. Start again in 300 seconds.',
      next: nextUrl,
      values: {},
    });
  }

  const code = newEmailCode();
  const link = `${config.baseUrl}/login/2fa/email?token=${encodeURIComponent(code)}`;
  if (!(await notify.sendLoginCode(user, code, link))) {
    return res.status(503).render('login-2fa', {
      error: 'Email verification is temporarily unavailable. Please try again later.',
      csrf: challenge.csrf_token,
      method: 'email',
      next: nextUrl,
      email: user.email,
      resendWaitSeconds: 0,
    });
  }
  updateChallengeEmail.run(otpHash(code), now, now + config.twofa.challengeTtlMs, now, challenge.id);
  return res.render('login-2fa', {
    csrf: challenge.csrf_token,
    method: 'email',
    next: nextUrl,
    email: user.email,
    error: 'A new verification email was sent.',
    resendWaitSeconds: RESEND_DELAYS[count + 1] || 0,
  });
});

router.post('/login/2fa', limiters.login, widgetPage, (req, res) => {
  const challengeId = req.signedCookies && req.signedCookies.twofa;
  const challenge = challengeId && getChallenge.get(challengeId, Date.now());
  const nextUrl = safeNext(req.body.next);
  if (!challenge || challenge.attempts >= 5 || req.body._csrf !== challenge.csrf_token) {
    clearTwofaCookie(res);
    return res.status(403).render('login', { error: 'Verification expired. Please log in again.', next: nextUrl, values: {} });
  }

  const user = getUserById.get(challenge.user_id);
  let valid = false;
  let totpCounter = null;
  if (user && challenge.method === 'email') valid = otpHash(req.body.code || '') === challenge.code_hash;
  if (user && challenge.method === 'totp' && user.totp_enabled) {
    totpCounter = matchingTotpCounter(user.totp_secret, req.body.code);
    valid = totpCounter !== null && (user.totp_last_counter === null || totpCounter > user.totp_last_counter);
  }
  if (!valid) {
    incrementChallengeAttempts.run(challenge.id);
    const delay = challenge.method === 'email' ? (RESEND_DELAYS[Number(challenge.resend_count || 0)] || 0) : 0;
    const availableAt = (challenge.last_sent_at || challenge.created_at) + delay * 1000;
    return res.status(401).render('login-2fa', {
      error: 'Invalid verification code.',
      csrf: challenge.csrf_token,
      method: challenge.method,
      next: nextUrl,
      email: user ? user.email : '',
      resendWaitSeconds: Math.max(0, Math.ceil((availableAt - Date.now()) / 1000)),
    });
  }

  deleteChallenge.run(challenge.id);
  if (challenge.method === 'totp') updateTotpCounter.run(totpCounter, user.id);
  clearTwofaCookie(res);
  clearTwofaBlockCookie(res);
  setLastIp.run(geo.clientIp(req) || null, user.id);
  createSession(res, user.id);
  res.redirect(nextUrl);
});

const DEFAULT_TTLS = new Set(['1h', '6h', '24h', '3d', '7d', '30d', 'never']);

function renderAccount(res, user, extra = {}) {
  const current = { ...getUserById.get(user.id), ...user };
  const setupSecret = extra.setupSecret || current.totp_pending_secret || null;
  res.render('account', {
    me: current,
    tab: extra.tab || 'defaults',
    totpEnabled: !!current.totp_enabled,
    setupSecret,
    setupUri: setupSecret ? provisioningUri(setupSecret, current.email) : null,
    error: extra.error || null,
    notice: extra.notice || null,
    recovery: extra.recovery || null,
  });
}

function accountRecovery(req, kind) {
  const challenge = recoveryFromRequest(req);
  return challenge && challenge.user_id === req.user.id && challenge.kind === kind ? challenge : null;
}

router.get('/account', requireAuth, (req, res) => {
  const tab = req.query.tab === 'security' ? 'security' : 'defaults';
  const challenge = tab === 'security' ? (accountRecovery(req, 'email') || accountRecovery(req, 'account_password')) : null;
  renderAccount(res, req.user, { tab, recovery: challenge });
});

router.get('/account/security', requireAuth, (req, res) => {
  const challenge = accountRecovery(req, 'email') || accountRecovery(req, 'account_password');
  renderAccount(res, req.user, { tab: 'security', recovery: challenge });
});

router.post('/account/defaults', requireAuth, verifyCsrf, (req, res) => {
  const ttl = DEFAULT_TTLS.has(req.body.default_ttl) ? req.body.default_ttl : null;
  const timer = req.body.default_timer_start === 'upload' ? 'upload' : 'first_view';
  const rawMax = String(req.body.default_max_views || '').trim();
  const maxViews = rawMax ? parseInt(rawMax, 10) : null;
  if (!ttl || (maxViews !== null && (!Number.isInteger(maxViews) || maxViews < 1))) {
    return renderAccount(res, req.user, { tab: 'defaults', error: 'Choose valid upload defaults.' });
  }
  updateDefaults.run(ttl, timer, maxViews, req.user.id);
  renderAccount(res, { ...req.user, default_ttl: ttl, default_timer_start: timer, default_max_views: maxViews }, {
    tab: 'defaults',
    notice: 'New-image defaults saved.',
  });
});

router.post('/account/security/totp/start', requireAuth, verifyCsrf, (req, res) => {
  const secret = newTotpSecret();
  updateTotpPending.run(secret, req.user.id);
  renderAccount(res, { ...req.user, totp_pending_secret: secret }, { tab: 'security', setupSecret: secret });
});

router.post('/account/security/totp/method', requireAuth, verifyCsrf, (req, res) => {
  const method = req.body.twofa_mode === 'totp' ? 'totp' : 'email';
  updateTwofaMode.run(method, req.user.id);
  const message = method === 'totp' ? 'TOTP selected as the preferred login method.' : 'Email selected as the preferred login method.';
  renderAccount(res, { ...req.user, twofa_mode: method }, { tab: 'security', notice: message });
});

router.post('/account/security/totp/confirm', requireAuth, verifyCsrf, (req, res) => {
  const user = getUserById.get(req.user.id);
  if (!user.totp_pending_secret || !verifyTotp(user.totp_pending_secret, req.body.code)) {
    return renderAccount(res, user, { tab: 'security', error: 'Invalid authenticator code. Check the device time and try again.' });
  }
  enableTotp.run(user.totp_pending_secret, user.id);
  renderAccount(res, { ...user, totp_enabled: 1, totp_pending_secret: null }, { tab: 'security', notice: 'TOTP enabled. Email remains the default login method; choose TOTP on the login form to use it instead.' });
});

router.post('/account/security/totp/disable', requireAuth, verifyCsrf, (req, res) => {
  if (!verifyPassword(req.body.password || '', req.user.password_hash)) {
    return renderAccount(res, req.user, { tab: 'security', error: 'Current password is incorrect.' });
  }
  disableTotp.run(req.user.id);
  renderAccount(res, { ...req.user, totp_enabled: 0, totp_secret: null, totp_pending_secret: null }, { tab: 'security', notice: 'TOTP disabled. Email verification remains required at login.' });
});

router.post('/account/security/email/start', requireAuth, verifyCsrf, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!validEmail(email)) return renderAccount(res, req.user, { tab: 'security', error: 'Enter a valid new email address.' });
  if (email === req.user.email.toLowerCase()) return renderAccount(res, req.user, { tab: 'security', error: 'Enter a different email address.' });
  if (getByEmail.get(email)) return renderAccount(res, req.user, { tab: 'security', error: 'That email address is already in use.' });
  const recovery = await beginRecovery(res, req.user, 'email', email);
  if (!recovery) return renderAccount(res, req.user, { tab: 'security', error: 'Verification email is temporarily unavailable.' });
  renderAccount(res, req.user, { tab: 'security', recovery, notice: 'A verification code was sent to your current email address.' });
});

router.post('/account/security/email/confirm', requireAuth, verifyCsrf, (req, res) => {
  const challenge = accountRecovery(req, 'email');
  const email = challenge && challenge.target;
  if (!challenge || req.body._recovery_csrf !== challenge.csrf_token || challenge.attempts >= 5) {
    clearRecoveryCookie(res);
    return renderAccount(res, req.user, { tab: 'security', error: 'Email verification expired. Start again.' });
  }
  if (otpHash(String(req.body.code || '').trim()) !== challenge.code_hash) {
    incrementRecoveryAttempts.run(challenge.id);
    return renderAccount(res, req.user, { tab: 'security', recovery: challenge, error: 'Invalid verification code.' });
  }
  if (!validEmail(email) || (getByEmail.get(email) && getByEmail.get(email).id !== req.user.id)) {
    deleteRecovery.run(challenge.id);
    clearRecoveryCookie(res);
    return renderAccount(res, req.user, { tab: 'security', error: 'That email address is no longer available.' });
  }
  updateEmail.run(email, req.user.id);
  deleteRecovery.run(challenge.id);
  clearRecoveryCookie(res);
  renderAccount(res, { ...req.user, email }, { tab: 'security', notice: 'Email address updated.' });
});

router.post('/account/security/password/start', requireAuth, verifyCsrf, async (req, res) => {
  const recovery = await beginRecovery(res, req.user, 'account_password');
  if (!recovery) return renderAccount(res, req.user, { tab: 'security', error: 'Verification email is temporarily unavailable.' });
  renderAccount(res, req.user, { tab: 'security', recovery, notice: 'A verification code was sent to your current email address.' });
});

router.post('/account/security/password/confirm', requireAuth, verifyCsrf, (req, res) => {
  const challenge = accountRecovery(req, 'account_password');
  const password = req.body.new_password || '';
  if (!challenge || req.body._recovery_csrf !== challenge.csrf_token || challenge.attempts >= 5) {
    clearRecoveryCookie(res);
    return renderAccount(res, req.user, { tab: 'security', error: 'Password verification expired. Start again.' });
  }
  if (otpHash(String(req.body.code || '').trim()) !== challenge.code_hash) {
    incrementRecoveryAttempts.run(challenge.id);
    return renderAccount(res, req.user, { tab: 'security', recovery: challenge, error: 'Invalid verification code.' });
  }
  if (password.length < 10) return renderAccount(res, req.user, { tab: 'security', recovery: challenge, error: 'Password must be at least 10 characters.' });
  updatePassword.run(hashPassword(password), req.user.id);
  deleteOtherUserSessions.run(req.user.id, req.signedCookies && req.signedCookies[SESSION_COOKIE]);
  deleteRecovery.run(challenge.id);
  clearRecoveryCookie(res);
  renderAccount(res, req.user, { tab: 'security', notice: 'Password updated.' });
});

// --- Log out --------------------------------------------------------------
router.post('/logout', verifyCsrf, (req, res) => {
  destroySession(req, res);
  res.redirect('/');
});

module.exports = router;
