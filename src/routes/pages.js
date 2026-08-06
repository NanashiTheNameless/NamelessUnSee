'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const config = require('../config');
const { legalPage, gatePage, grantConsent, hasConsent } = require('../middleware');
const { verifySolution, obfuscate } = require('../altcha');
const { limiters } = require('../ratelimit');
const { renderMarkdown } = require('../util/markdown');

const router = express.Router();
router.use(limiters.public);

const LICENSE_PATH = path.join(__dirname, '..', '..', 'LICENSE.md');

// Only allow same-origin relative paths as a post-consent redirect target.
function safeNext(next) {
  if (typeof next !== 'string') return '/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
  return next;
}

// --- Consent warning ------------------------------------------------------
// This gate uses the self-hosted ALTCHA proof-of-work widget to keep bots and
// scrapers out. It loads only same-origin assets and performs NO server-side
// logging or geolocation. /tos and /privacy load nothing but text + the font.
router.get('/welcome', gatePage, (req, res) => {
  const next = safeNext(req.query.next);
  // If they already consented this session, don't show it again.
  if (hasConsent(req) && next !== '/welcome') return res.redirect(next);
  res.render('welcome', { next, error: req.query.error || null });
});

router.post('/welcome', gatePage, (req, res) => {
  const next = safeNext(req.body.next);
  const agreed = req.body.agree === 'on' || req.body.agree === 'true';
  if (!agreed) {
    return res.redirect('/welcome?error=agree&next=' + encodeURIComponent(next));
  }
  if (!verifySolution(req.body.altcha)) {
    return res.redirect('/welcome?error=altcha&next=' + encodeURIComponent(next));
  }
  grantConsent(res);
  res.redirect(next);
});

// The operator contact address is never sent in clear text: it is obfuscated
// with ALTCHA's Obfuscation module and revealed in-browser by a small offline
// proof-of-work (deters scrapers; involves no network requests or logging).
function contactObfuscated() {
  return config.operator.contact ? obfuscate(config.operator.contact) : null;
}

router.get('/tos', legalPage, (req, res) => {
  res.render('tos', {
    operator: config.operator,
    imageTtlHours: config.imageTtlHours,
    logRetentionHours: config.logRetentionAfterDeleteHours,
    contactObfuscated: contactObfuscated(),
  });
});

router.get('/privacy', legalPage, (req, res) => {
  res.render('privacy', {
    operator: config.operator,
    imageTtlHours: config.imageTtlHours,
    logRetentionHours: config.logRetentionAfterDeleteHours,
    contactObfuscated: contactObfuscated(),
  });
});

// Open-source acknowledgements, code-license explainer, and the rendered licence text.
router.get('/acknowledgements', (req, res) => {
  res.render('acknowledgements', {});
});

router.get('/license', (req, res) => {
  res.render('license', {});
});

router.get('/license.md', (req, res) => {
  try {
    const source = fs.readFileSync(LICENSE_PATH, 'utf8');
    if (req.query.raw === 'true') return res.type('text/markdown').send(source);
    res.render('license-markdown', { licenseHtml: renderMarkdown(source) });
  } catch {
    res.status(404).render('error', { title: 'Not found', message: 'LICENSE.md not found' });
  }
});

module.exports = router;
