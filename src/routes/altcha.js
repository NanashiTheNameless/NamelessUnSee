'use strict';

const express = require('express');
const { createChallenge } = require('../altcha');
const { limiters } = require('../ratelimit');

const router = express.Router();

// The ALTCHA widget fetches a fresh proof-of-work challenge from here.
// Same-origin only, no logging, no visitor data collected.
router.get('/altcha/challenge', limiters.altcha, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(createChallenge());
});

module.exports = router;
