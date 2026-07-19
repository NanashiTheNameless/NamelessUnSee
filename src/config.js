'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

// Load .env if present (tiny parser, no dependency).
(function loadDotEnv() {
  const envPath = path.resolve(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
})();

function bool(v, fallback = false) {
  if (v === undefined || v === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(v));
}

function int(v, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function float(v, fallback) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}

function urlList(v, fallback) {
  const raw = (v === undefined || v === '') ? fallback : v;
  return String(raw).split(',').map((s) => s.trim()).filter(Boolean);
}

const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const REPORT_DIR = path.join(DATA_DIR, 'reports');
// Staging and rendered files are ephemeral; keep them outside persistent media
// storage so R2 deployments never write user media to the data volume.
const TEMP_DIR = path.resolve(process.env.TEMP_DIR || path.join(os.tmpdir(), `namelessunsee-${process.pid}`));

const config = {
  baseUrl: (process.env.BASE_URL || 'http://localhost:3000').replace(/\/+$/, ''),
  port: int(process.env.PORT, 3000),
  cookieSecret: process.env.COOKIE_SECRET || 'insecure-dev-secret-change-me',
  secureCookies: bool(process.env.SECURE_COOKIES, false),
  dataDir: DATA_DIR,
  uploadDir: UPLOAD_DIR,
  reportDir: REPORT_DIR,
  tempDir: TEMP_DIR,
  maxReportBytes: int(process.env.MAX_REPORT_MB, 10) * 1024 * 1024,
  dbPath: path.join(DATA_DIR, 'namelessunsee.sqlite'),
  sourceUrl: (process.env.SOURCE_URL || 'https://github.com/NanashiTheNameless/NamelessUnSee').replace(/\/+$/, ''),
  imageTtlHours: int(process.env.IMAGE_TTL_HOURS, 24),
  maxUploadBytes: int(process.env.MAX_UPLOAD_MB, 500) * 1024 * 1024,
  maxUploadBytesHard: int(process.env.MAX_UPLOAD_HARD_MB, 4096) * 1024 * 1024,
  maxStorageBytes: int(process.env.MAX_STORAGE_MB, 1024) * 1024 * 1024,
  storage: {
    // 'local', Cloudflare R2, or another S3-compatible object store.
    backend: String(process.env.STORAGE_BACKEND || 'local').split('#')[0].trim().toLowerCase(),
    encryptionKey: process.env.STORAGE_ENCRYPTION_KEY || '',
    s3: {
      // R2_* is canonical for Cloudflare R2; S3_* configures generic stores.
      endpoint: process.env.R2_ENDPOINT ||
        (process.env.R2_ACCOUNT_ID ? `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : '') ||
        process.env.S3_ENDPOINT || '',
      bucket: process.env.R2_BUCKET || process.env.S3_BUCKET || '',
      accessKeyId: process.env.R2_ACCESS_KEY_ID || process.env.S3_ACCESS_KEY_ID || '',
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || process.env.S3_SECRET_ACCESS_KEY || '',
      region: process.env.R2_REGION || process.env.S3_REGION || 'auto',
      forcePathStyle: bool(process.env.R2_FORCE_PATH_STYLE, bool(process.env.S3_FORCE_PATH_STYLE, false)),
    },
  },
  ipIntel: {
    blockProxies: bool(process.env.BLOCK_PROXIES, true),
    blockOnUnknown: bool(process.env.BLOCK_ON_UNKNOWN, true),
    allowPrivateIps: bool(process.env.ALLOW_PRIVATE_IPS, false),
    // All detection is local; these datasets are downloaded and auto-refreshed.
    cacheDir: path.join(DATA_DIR, 'intel'),
    tor: {
      enabled: bool(process.env.TOR_LIST_ENABLED, true),
      url: process.env.TOR_LIST_URL || 'https://check.torproject.org/torbulkexitlist',
      refreshHours: int(process.env.TOR_REFRESH_HOURS, 6),
    },
    vpnLists: {
      enabled: bool(process.env.VPN_LISTS_ENABLED, true),
      // Comma-separated URL lists. Each source may contain IPv4 and/or IPv6
      // CIDRs; both families are parsed and matched. The X4BNet defaults are
      // IPv4-only- append your own IPv6 sources to close that gap.
      vpnUrls: urlList(process.env.VPN_LIST_URL, 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'),
      datacenterUrls: urlList(
        process.env.DATACENTER_LIST_URL,
        'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt'
      ),
      refreshHours: int(process.env.VPN_REFRESH_HOURS, 24),
      blockDatacenter: bool(process.env.BLOCK_DATACENTER, true),
    },
    maxmind: {
      // GeoLite2 requires a free MaxMind licence key to auto-download. If a
      // .mmdb already exists at the paths below (e.g. mounted in), it is used
      // even without a key. https://www.maxmind.com/en/geolite2/signup
      licenseKey: (process.env.MAXMIND_LICENSE_KEY || '').trim(),
      asnPath: process.env.MAXMIND_ASN_DB || path.join(DATA_DIR, 'intel', 'GeoLite2-ASN.mmdb'),
      cityPath: process.env.MAXMIND_CITY_DB || path.join(DATA_DIR, 'intel', 'GeoLite2-City.mmdb'),
      refreshHours: int(process.env.MAXMIND_REFRESH_HOURS, 72),
    },
  },
  altcha: {
    // HMAC key for signing ALTCHA challenges. Falls back to a value derived
    // from COOKIE_SECRET so it works out of the box.
    hmacKey: process.env.ALTCHA_HMAC_KEY || null,
    // Proof-of-work search ceiling. Higher values increase client CPU cost.
    maxNumber: int(process.env.ALTCHA_MAX_NUMBER, 200000),
    widget: {
      type: process.env.ALTCHA_WIDGET_TYPE || 'checkbox',
      display: process.env.ALTCHA_WIDGET_DISPLAY || 'standard',
      codeChallengeDisplay: process.env.ALTCHA_CODE_CHALLENGE_DISPLAY || 'standard',
      auto: process.env.ALTCHA_AUTO || 'onsubmit',
      lang: process.env.ALTCHA_LANG || 'en',
      theme: process.env.ALTCHA_THEME || 'business',
      hideFooter: bool(process.env.ALTCHA_HIDE_FOOTER, false),
      hideLogo: bool(process.env.ALTCHA_HIDE_LOGO, true),
    },
  },
  // Rate limits (per client IP, or per user for uploads). The default store is
  // in-memory (single instance). Set RATELIMIT_STORE=redis + REDIS_URL to share
  // counters across instances; requires `yarn add redis`.
  rateLimit: {
    enabled: bool(process.env.RATELIMIT_ENABLED, true),
    store: String(process.env.RATELIMIT_STORE || 'memory').trim().toLowerCase(),
    redisUrl: process.env.REDIS_URL || '',
    login: { windowMs: int(process.env.RL_LOGIN_WINDOW_MIN, 15) * 60000, max: int(process.env.RL_LOGIN_MAX, 10) },
    signup: { windowMs: int(process.env.RL_SIGNUP_WINDOW_MIN, 60) * 60000, max: int(process.env.RL_SIGNUP_MAX, 5) },
    upload: { windowMs: int(process.env.RL_UPLOAD_WINDOW_MIN, 60) * 60000, max: int(process.env.RL_UPLOAD_MAX, 30) },
    view: { windowMs: int(process.env.RL_VIEW_WINDOW_SEC, 60) * 1000, max: int(process.env.RL_VIEW_MAX, 120) },
    telemetry: { windowMs: int(process.env.RL_TELEMETRY_WINDOW_SEC, 60) * 1000, max: int(process.env.RL_TELEMETRY_MAX, 60) },
    report: { windowMs: int(process.env.RL_REPORT_WINDOW_MIN, 1440) * 60000, max: int(process.env.RL_REPORT_MAX, 3) },
  },
  resend: {
    apiKey: process.env.RESEND_API_KEY || '',
    from: process.env.ADMIN_NOTIFY_FROM || '',
    to: process.env.ADMIN_NOTIFY_TO || '',
  },
  twofa: {
    enabled: bool(process.env.TWOFA_ENABLED, true),
    consoleFallback: bool(process.env.TWOFA_CONSOLE_FALLBACK, false),
    challengeTtlMs: int(process.env.TWOFA_CHALLENGE_MIN, 5) * 60000,
  },
  // Content moderation. Scanning runs on upload using the original image or
  // sampled frames for videos.
  //   - perceptual-hash blocklist (self-managed): auto-quarantine on match.
  //   - NSFW classifier (optional, self-hosted): routes to human review only.
  //   - provider hooks (Cloudflare/PhotoDNA/Arachnid): scaffolding, disabled.
  // Nothing here ever auto-bans a user; account actions require a human.
  moderation: {
    enabled: bool(process.env.MODERATION_ENABLED, true),
    // Hold review-flagged images (unviewable) until an admin decides. When
    // false, flagged images stay viewable but are still queued for review.
    holdOnReview: bool(process.env.MODERATION_HOLD_ON_REVIEW, true),
    // Max Hamming distance to count as a blocklist match: 64-bit
    // entries use MODERATION_PHASH_THRESHOLD, 256-bit PDQ entries use
    // MODERATION_PDQ_THRESHOLD (PDQ convention: 31).
    phashThreshold: int(process.env.MODERATION_PHASH_THRESHOLD, 10),
    pdqThreshold: int(process.env.MODERATION_PDQ_THRESHOLD, 31),
    nsfw: {
      // The classifier runs in the optional moderation sidecar.
      enabled: bool(process.env.NSFW_CLASSIFIER_ENABLED, true),
      model: process.env.NSFW_MODEL || 'onnx-community/nsfw-classifier-ONNX',
      threshold: float(process.env.NSFW_THRESHOLD, 0.80),
      failClosed: bool(process.env.NSFW_FAIL_CLOSED, true),
      serviceUrl: (process.env.NSFW_SERVICE_URL || '').replace(/\/+$/, ''),
      timeoutMs: int(process.env.NSFW_SERVICE_TIMEOUT_MS, 15000),
    },
    // Future known-CSAM hash-matching providers- all disabled by default.
    providers: {
      cloudflare: { enabled: bool(process.env.MOD_CLOUDFLARE_ENABLED, false) },
      photodna: {
        enabled: bool(process.env.MOD_PHOTODNA_ENABLED, false),
        endpoint: process.env.PHOTODNA_ENDPOINT || '',
        apiKey: process.env.PHOTODNA_API_KEY || '',
      },
      arachnid: {
        enabled: bool(process.env.MOD_ARACHNID_ENABLED, false),
        endpoint: process.env.ARACHNID_ENDPOINT || '',
        apiKey: process.env.ARACHNID_API_KEY || '',
      },
    },
  },
  // Operator identity rendered into the ToS and Privacy Policy. Set these for
  // any public deployment- they are the legal point of contact.
  operator: {
    name: (process.env.OPERATOR_NAME || '').trim() || 'the operator of this instance',
    contact: (process.env.OPERATOR_CONTACT || '').trim(),
    jurisdiction: (process.env.OPERATOR_JURISDICTION || '').trim(),
  },
};

// Derive a stable ALTCHA HMAC key from the cookie secret if not set explicitly.
if (!config.altcha.hmacKey) {
  config.altcha.hmacKey = require('crypto')
    .createHash('sha256')
    .update('altcha:' + config.cookieSecret)
    .digest('hex');
}

if (process.env.NODE_ENV === 'production' && !process.env.ALTCHA_HMAC_KEY) {
  console.warn(
    '[NamelessUnSee] WARNING: ALTCHA_HMAC_KEY is unset. Using a key derived from COOKIE_SECRET. ' +
      'Set a separate persistent ALTCHA_HMAC_KEY in production.'
  );
}

// Ensure data directories exist.
fs.mkdirSync(config.uploadDir, { recursive: true });
fs.mkdirSync(config.reportDir, { recursive: true });
fs.mkdirSync(config.tempDir, { recursive: true });
fs.mkdirSync(config.ipIntel.cacheDir, { recursive: true });

if (config.cookieSecret === 'insecure-dev-secret-change-me') {
  console.warn(
    '[NamelessUnSee] WARNING: COOKIE_SECRET is unset. Using an insecure default. ' +
      'Set COOKIE_SECRET in your environment for production.'
  );
}

module.exports = config;
