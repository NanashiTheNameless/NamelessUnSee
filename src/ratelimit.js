'use strict';

const config = require('./config');
const geo = require('./geo');

// Fixed-window rate limiter, keyed by client IP (or user id). Two stores:
//   - memory (default): per-process Map, fine for a single instance.
//   - redis: shared counters for multi-instance deployments. Enable with
//     RATELIMIT_STORE=redis + REDIS_URL, and `yarn add redis` (the client is
//     loaded dynamically, like the NSFW classifier). If Redis is missing or
//     unreachable, the limiter falls back to the in-memory store and keeps
//     serving- a broken Redis must never take the site down.

const buckets = new Map(); // key -> { count, resetAt }

function sweep() {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.resetAt <= now) buckets.delete(k);
}
setInterval(sweep, 5 * 60 * 1000).unref();

function memoryHit(key, windowMs) {
  const now = Date.now();
  let e = buckets.get(key);
  if (!e || e.resetAt <= now) {
    e = { count: 0, resetAt: now + windowMs };
    buckets.set(key, e);
  }
  e.count += 1;
  return { count: e.count, resetMs: e.resetAt - now };
}

// --- optional Redis store ---------------------------------------------------
let redisClient = null;
let redisState = 'off'; // 'off' | 'connecting' | 'ready' | 'failed'

function initRedis() {
  if (config.rateLimit.store !== 'redis') return;
  redisState = 'connecting';
  let createClient;
  try {
    ({ createClient } = require('redis'));
  } catch {
    redisState = 'failed';
    console.warn('[NamelessUnSee] RATELIMIT_STORE=redis but the redis package is not installed (yarn add redis). Using the in-memory store.');
    return;
  }
  const client = createClient({ url: config.rateLimit.redisUrl || undefined });
  client.on('error', () => {}); // reconnects internally; hits fall back meanwhile
  client
    .connect()
    .then(() => {
      redisClient = client;
      redisState = 'ready';
      console.log('[NamelessUnSee] rate limiter using Redis store');
    })
    .catch((e) => {
      redisState = 'failed';
      console.warn('[NamelessUnSee] Redis unavailable, rate limiter using in-memory store:', e.message);
    });
}
initRedis();

async function redisHit(key, windowMs) {
  const k = 'nus:rl:' + key;
  const count = await redisClient.incr(k);
  if (count === 1) await redisClient.pExpire(k, windowMs);
  let ttl = await redisClient.pTTL(k);
  if (ttl < 0) {
    // Expiry was lost (e.g. the pExpire raced a crash); restore it.
    await redisClient.pExpire(k, windowMs);
    ttl = windowMs;
  }
  return { count, resetMs: ttl };
}

async function hit(key, windowMs) {
  if (redisState === 'ready' && redisClient && redisClient.isReady) {
    try {
      return await redisHit(key, windowMs);
    } catch { /* fall through to memory */ }
  }
  return memoryHit(key, windowMs);
}

/**
 * @param {object} opts { name, windowMs, max, by: 'ip'|'user', html: bool }
 */
function createLimiter(opts) {
  const { name, windowMs, max, by = 'ip', html = false } = opts;

  return function rateLimit(req, res, next) {
    if (!config.rateLimit.enabled) return next();

    const who =
      by === 'user' && req.user ? 'u:' + req.user.id : 'ip:' + (geo.clientIp(req) || 'unknown');
    const key = who + '|' + name;

    hit(key, windowMs)
      .then(({ count, resetMs }) => {
        const retryAfter = Math.max(1, Math.ceil(resetMs / 1000));
        res.setHeader('RateLimit-Limit', String(max));
        res.setHeader('RateLimit-Remaining', String(Math.max(0, max - count)));
        res.setHeader('RateLimit-Reset', String(retryAfter));

        if (count > max) {
          res.setHeader('Retry-After', String(retryAfter));
          if (html) {
            return res.status(429).render('ratelimited', { retryAfter });
          }
          return res.status(429).type('text').send('Too many requests. Please try again later.');
        }
        next();
      })
      .catch(() => next()); // a broken limiter must never block traffic
  };
}

// Pre-built limiters from config.
const rl = config.rateLimit;
const limiters = {
  login: createLimiter({ name: 'login', windowMs: rl.login.windowMs, max: rl.login.max, by: 'ip', html: true }),
  signup: createLimiter({ name: 'signup', windowMs: rl.signup.windowMs, max: rl.signup.max, by: 'ip', html: true }),
  upload: createLimiter({ name: 'upload', windowMs: rl.upload.windowMs, max: rl.upload.max, by: 'user', html: true }),
  view: createLimiter({ name: 'view', windowMs: rl.view.windowMs, max: rl.view.max, by: 'ip', html: true }),
  render: createLimiter({ name: 'view', windowMs: rl.view.windowMs, max: rl.view.max, by: 'ip', html: false }),
  telemetry: createLimiter({ name: 'telemetry', windowMs: rl.telemetry.windowMs, max: rl.telemetry.max, by: 'ip', html: false }),
  report: createLimiter({ name: 'report', windowMs: rl.report.windowMs, max: rl.report.max, by: 'user', html: true }),
};

module.exports = { createLimiter, limiters, _buckets: buckets };
