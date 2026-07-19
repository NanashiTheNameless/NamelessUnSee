'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');

const config = require('./config');
const db = require('./db');
const bans = require('./bans');
const { attachUser, sweepSessions } = require('./auth');

const countReviewPending = db.prepare(
  "SELECT COUNT(*) AS n FROM images WHERE deleted_at IS NULL AND moderation_status IN ('review', 'quarantined')"
);
const countLeakReports = db.prepare("SELECT COUNT(*) AS n FROM leak_reports WHERE status = 'open'");
const { baseSecurity, enforceViewBan } = require('./middleware');
const storage = require('./storage');

const app = express();

// Behind Cloudflare Tunnel / reverse proxy: trust proxy so req.ip and the
// forwarded headers resolve correctly.
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.disable('x-powered-by');

app.use(baseSecurity);

// Static, same-origin assets only: the self-hosted 0xProto font and the ALTCHA
// widget. No third-party CDNs anywhere in the app.
app.use(
  express.static(path.join(__dirname, '..', 'public'), {
    index: false,
    dotfiles: 'ignore',
    maxAge: '30d',
    setHeaders: (res, p) => {
      if (p.endsWith('.woff2')) res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    },
  })
);

app.use(cookieParser(config.cookieSecret));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(express.json({ limit: '32kb' }));

// Same-origin guard for state-changing requests (defence in depth alongside
// SameSite cookies + per-session CSRF tokens). Note: our `Referrer-Policy:
// no-referrer` makes browsers send `Origin: null` (and no Referer) on same-origin
// form posts, so a null/absent origin is treated as "unknown", not "cross-origin"
//- a real cross-origin Origin is still blocked, and authenticated routes are
// additionally protected by the per-session CSRF token + SameSite cookies.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  const host = req.headers.host;
  const ok = (u) => {
    try {
      return new URL(u).host === host;
    } catch {
      return false;
    }
  };
  const originKnown = origin && origin !== 'null';
  if (originKnown && !ok(origin)) return res.status(403).send('Cross-origin request blocked.');
  if (!originKnown && referer && !ok(referer)) return res.status(403).send('Cross-origin request blocked.');
  next();
});

app.use(attachUser);

// Block banned viewers from the entire service (after attachUser so logged-in
// user bans are visible; before routes so nothing is served to them).
app.use(enforceViewBan);

// Expose helpers to all templates.
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.csrf = req.session ? req.session.csrf_token : '';
  res.locals.baseUrl = config.baseUrl;
  res.locals.sourceUrl = config.sourceUrl;
  res.locals.altcha = config.altcha;
  res.locals.reviewPending = req.user && req.user.role === 'admin' ? countReviewPending.get().n : 0;
  res.locals.reportPending = req.user && req.user.role === 'admin' ? countLeakReports.get().n : 0;
  next();
});

// Landing page.
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

app.get('/healthz', (req, res) => res.type('text').send('ok'));

// Routes.
app.use(require('./routes/altcha'));
app.use(require('./routes/pages'));
app.use(require('./routes/account'));
app.use(require('./routes/admin'));
app.use(require('./routes/review'));
app.use(require('./routes/upload'));
app.use(require('./routes/galleries'));
app.use(require('./routes/view'));
app.use(require('./routes/reports'));

// 404.
app.use((req, res) => {
  res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.' });
});

// Error handler.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[NamelessUnSee] error:', err);
  if (res.headersSent) return;
  res.status(500).render('error', { title: 'Server error', message: 'Something went wrong.' });
});

// --- Background maintenance -----------------------------------------------
const purgeExpiredImages = db.prepare(
  'SELECT * FROM images WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?'
);
const markPurged = db.prepare('UPDATE images SET deleted_at = ? WHERE id = ?');

function runMaintenance() {
  try {
    const now = Date.now();
    const expired = purgeExpiredImages.all(now);
    for (const img of expired) {
      storage.remove(img).catch(() => {});
      markPurged.run(now, img.id);
    }
    if (expired.length) console.log(`[NamelessUnSee] purged ${expired.length} expired image(s)`);
    sweepSessions();
    bans.sweepExpired();
  } catch (e) {
    console.error('[NamelessUnSee] maintenance error:', e.message);
  }
}

// Start background work and listen. Called only when run directly (not when the
// app is imported by the test suite).
function start() {
  setInterval(runMaintenance, 10 * 60 * 1000).unref();
  runMaintenance();

  // Load and auto-update the local IP-intelligence datasets (MaxMind GeoLite2,
  // Tor exit list, VPN/datacenter ranges). All per-viewer detection is local.
  require('./ipintel').init().catch((e) => console.warn('[NamelessUnSee] ipintel init failed:', e.message));

  return app.listen(config.port, () => {
    console.log(`[NamelessUnSee] listening on port ${config.port}- base URL ${config.baseUrl}`);
  });
}

if (require.main === module) start();

module.exports = app;
module.exports.start = start;
