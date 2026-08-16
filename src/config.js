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
  database: {
    backend: String(process.env.DB_BACKEND || 'sqlite').trim().toLowerCase(),
    d1: {
      accountId: process.env.CLOUDFLARE_ACCOUNT_ID || '',
      databaseId: process.env.CLOUDFLARE_D1_DATABASE_ID || '',
      apiToken: process.env.CLOUDFLARE_API_TOKEN || '',
    },
  },
  sourceUrl: (process.env.SOURCE_URL || 'https://github.com/NanashiTheNameless/NamelessUnSee').replace(/\/+$/, ''),
  imageTtlHours: int(process.env.IMAGE_TTL_HOURS, 24),
  // How long an image's access log outlives the image itself. The forensic
  // value of a log outlasts the media, but not indefinitely: after this window
  // the rows are deleted for good.
  logRetentionAfterDeleteHours: int(process.env.LOG_RETENTION_AFTER_DELETE_HOURS, 48),
  maxUploadBytes: int(process.env.MAX_UPLOAD_MB, 500) * 1024 * 1024,
  maxUploadBytesHard: int(process.env.MAX_UPLOAD_HARD_MB, 4096) * 1024 * 1024,
  // Chunked uploads. A reverse proxy caps how large a single request body may
  // be- Cloudflare's limit is 100 MB on most plans- which would otherwise cap
  // uploads far below MAX_UPLOAD_MB. The browser slices the file so no single
  // request approaches that ceiling, and the server reassembles it. Chunking
  // also keeps each request short enough to stay under proxy read timeouts.
  chunkedUpload: {
    enabled: bool(process.env.CHUNKED_UPLOAD_ENABLED, true),
    // Two separate numbers, deliberately:
    //   thresholdBytes - the proxy's request-body limit. Files at or under it
    //     go as one ordinary post, exactly as before.
    //   chunkBytes - the slice size once chunking kicks in. Smaller than the
    //     threshold so several slices can be in flight at once without their
    //     buffered bodies multiplying peak memory.
    thresholdBytes: int(process.env.UPLOAD_CHUNK_THRESHOLD_MB, 95) * 1024 * 1024,
    chunkBytes: int(process.env.UPLOAD_CHUNK_MB, 24) * 1024 * 1024,
    // Each in-flight chunk is buffered whole in memory, so peak usage per
    // uploader is roughly chunkBytes x parallel. 24 MB x 4 costs about what a
    // single 95 MB chunk did, with four times the data in flight.
    parallel: Math.max(1, int(process.env.UPLOAD_PARALLEL_CHUNKS, 4)),
    // How long a partially uploaded file may sit before its chunks are swept.
    sessionTtlMs: int(process.env.UPLOAD_SESSION_TTL_MIN, 60) * 60 * 1000,
  },
  maxStorageBytes: int(process.env.MAX_STORAGE_MB, 1024) * 1024 * 1024,
  // ffmpeg is by far the largest CPU consumer here: every video view burns a
  // per-viewer watermark into the frames, which means a full re-encode. Left to
  // its defaults ffmpeg takes every core it can see, so a couple of concurrent
  // viewers saturate the host. Cap both the threads per process and how many
  // encodes run at once.
  ffmpeg: {
    threads: int(process.env.FFMPEG_THREADS, 2),
    maxConcurrent: int(process.env.FFMPEG_MAX_CONCURRENT, 2),
    preset: String(process.env.FFMPEG_PRESET || 'veryfast').trim(),
    // Re-encode uploaded video once, at upload, into a canonical H.264/AAC mp4.
    // Per-view renders can then copy the audio untouched and skip format
    // guesswork, instead of redoing that work for every single viewer.
    normalizeOnUpload: bool(process.env.VIDEO_NORMALIZE_ON_UPLOAD, true),
    // Hardware encoding takes the per-view re-encode largely off the CPU, which
    // is the only thing that removes the CPU floor rather than merely capping
    // it. 'auto' uses it when the render device and encoder are both present
    // and silently falls back to libx264 otherwise; 'off' never tries.
    hwaccel: String(process.env.FFMPEG_HWACCEL || 'auto').trim().toLowerCase(),
    vaapiDevice: String(process.env.FFMPEG_VAAPI_DEVICE || '/dev/dri/renderD128').trim(),
  },
  // Quality ceiling for stored video. Uploads are capped once, at upload, so
  // neither storage nor the per-view re-encode ever pays for 4K60 source
  // material. CRF is the quality knob: lower is better and bigger (23 is
  // ffmpeg's default). At CRF 20, 1080p30 lands around 7 Mbps on high-motion
  // material, so VIDEO_MAX_BITRATE is a genuine ceiling rather than a formality.
  video: {
    maxHeight: int(process.env.VIDEO_MAX_HEIGHT, 1080),
    maxFps: int(process.env.VIDEO_MAX_FPS, 30),
    crf: int(process.env.VIDEO_CRF, 20),
    // Quality of the per-view watermarked render. Separate from the stored
    // copy: that one is the master and is kept pristine, while this is a
    // transient delivery re-encoded on every single view. Raising it is the
    // cheapest way to cut view-time CPU and bandwidth.
    viewCrf: int(process.env.VIDEO_VIEW_CRF, int(process.env.VIDEO_CRF, 20)),
    maxrate: String(process.env.VIDEO_MAX_BITRATE || '6000k').trim(),
    audioBitrate: String(process.env.VIDEO_AUDIO_BITRATE || '128k').trim(),
  },
  // Watermark tile spacing. The identity mark repeats across the image on a
  // grid; this scales the gap between repetitions. 1.0 packs them flush, higher
  // spreads them out. Tighter means denser coverage but more of each mark
  // clipped at the tile edge, since the rotated text is wider than its slot.
  watermark: {
    tileSpacing: float(process.env.WATERMARK_TILE_SPACING, 1.02),
    tilePadding: int(process.env.WATERMARK_TILE_PADDING, 20),
    // Every other column is dropped by this fraction of the vertical step. The
    // mark is tilted, so neighbours collide along that diagonal; offsetting
    // down the columns breaks up the line where one mark's tail meets the next
    // one's head. 0 disables the offset.
    stagger: float(process.env.WATERMARK_STAGGER, 0.5),
  },
  // Short-lived cache of rendered video, so a viewer seeking or reloading does
  // not trigger a fresh re-encode of the whole file for each request. Entries
  // are bound to the viewer they were rendered for- see src/render-cache.js.
  renderCache: {
    enabled: bool(process.env.RENDER_CACHE_ENABLED, true),
    ttlMs: int(process.env.RENDER_CACHE_TTL_SEC, 300) * 1000,
    maxEntryBytes: int(process.env.RENDER_CACHE_MAX_ENTRY_MB, 512) * 1024 * 1024,
    maxTotalBytes: int(process.env.RENDER_CACHE_MAX_TOTAL_MB, 2048) * 1024 * 1024,
  },
  // Client-side image shrinking before upload. Purely an optimisation: the
  // server re-probes, moderates and watermarks whatever arrives regardless, so
  // a client that ignores or subverts this gains nothing.
  //
  // The default caps the longest edge at 1920, matching the 1080p ceiling the
  // server applies to video, so nothing above 1080p-class resolution is ever
  // sent. Sources already smaller are never upscaled.
  clientImage: {
    maxEdge: int(process.env.CLIENT_IMAGE_MAX_EDGE, 1920),
    quality: Number(process.env.CLIENT_IMAGE_QUALITY || 0.82),
    // An image already within the size cap is only re-encoded when it is also
    // bulky enough for the re-encode to be worth it.
    reencodeAboveBytes: int(process.env.CLIENT_IMAGE_REENCODE_ABOVE_KB, 2048) * 1024,
  },
  // Client-side video compression before upload, using WebCodecs. Same standing
  // as the image path: an optimisation the server never trusts. It downscales
  // to the same ceiling the server would apply anyway, so the bytes are shrunk
  // before they cross the network instead of after. Audio is remuxed untouched;
  // anything the browser cannot handle is uploaded as-is and normalised
  // server-side exactly as before.
  clientVideo: {
    enabled: bool(process.env.CLIENT_VIDEO_COMPRESS, true),
    maxHeight: int(process.env.CLIENT_VIDEO_MAX_HEIGHT, int(process.env.VIDEO_MAX_HEIGHT, 1080)),
    maxFps: int(process.env.CLIENT_VIDEO_MAX_FPS, int(process.env.VIDEO_MAX_FPS, 30)),
    bitrate: int(process.env.CLIENT_VIDEO_BITRATE_KBPS, 6000) * 1000,
  },
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
    maxNumber: int(process.env.ALTCHA_MAX_NUMBER, 400000),
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
  abuse: {
    // Comma-separated domain suffixes, matched against the address domain and
    // any parent of it. Operators can replace/extend this list without shipping
    // a new build. This is the offline seed: it covers well-known throwaway
    // services plus the alias/relay providers that the community blocklist
    // deliberately leaves out, and it still applies when the downloaded list
    // below is disabled or unavailable.
    disposableEmailDomains: new Set(String(process.env.DISPOSABLE_EMAIL_DOMAINS || [
      // Classic throwaway inboxes.
      '10minutemail.com', '10minutemail.net', 'guerrillamail.com', 'guerrillamail.info',
      'sharklasers.com', 'mailinator.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com',
      'throwaway.email', 'dispostable.com', 'fakeinbox.com', 'getnada.com', 'maildrop.cc',
      'mailnesia.com', 'mohmal.com', 'trashmail.com', 'tempmailo.com', 'moakt.com',
      'emailondeck.com', 'mailsac.com', 'spamgourmet.com', 'inboxkitten.com', 'linshiyouxiang.net',
      // Alias / relay providers: real inboxes, but disposable by design.
      'mozmail.com', 'relay.firefox.com',            // Firefox Relay
      'passmail.net', 'passmail.com', 'passinbox.com', 'passfwd.com', // Proton Pass
      'simplelogin.com', 'simplelogin.co', 'simplelogin.fr', 'slmail.me', 'aleeas.com',
      'anonaddy.com', 'anonaddy.me', 'addy.io', 'addymail.com',
      'duck.com',                                    // DuckDuckGo Email Protection
      'privaterelay.appleid.com',                    // Apple Hide My Email
      '33mail.com', 'burnermail.io', 'forwardemail.net', 'spamex.com',
    ].join(',')).split(',').map((d) => d.trim().toLowerCase()).filter(Boolean)),
    // Allowlist mode. When enabled, ONLY these domains (and their subdomains)
    // may register and every other domain is refused, regardless of the
    // blocklists. The mode is a separate switch from the list so that shipping
    // defaults here cannot silently lock an existing instance down: the list is
    // pre-filled with the mainstream providers, and the operator decides when it
    // becomes the policy.
    emailAllowlistEnabled: bool(process.env.EMAIL_DOMAIN_ALLOWLIST_ENABLED, false),
    allowedEmailDomains: new Set(String(process.env.EMAIL_DOMAIN_ALLOWLIST || [
      'namelessnanashi.dev',
      // Google / Microsoft / Apple / Yahoo.
      'gmail.com', 'googlemail.com',
      'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'passport.com',
      'icloud.com', 'me.com', 'mac.com',
      'yahoo.com', 'ymail.com', 'rocketmail.com', 'yahoo.co.uk', 'yahoo.co.jp',
      'yahoo.ca', 'yahoo.com.au', 'yahoo.com.br', 'yahoo.de', 'yahoo.fr', 'yahoo.es', 'yahoo.in',
      // Privacy-focused mailboxes.
      'proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me',
      'tuta.com', 'tutanota.com', 'tutamail.com', 'keemail.me',
      'fastmail.com', 'fastmail.fm', 'mailbox.org', 'posteo.de', 'runbox.com',
      'startmail.com', 'hushmail.com', 'disroot.org', 'riseup.net',
      // Other large consumer providers.
      'aol.com', 'mail.com', 'gmx.com', 'gmx.net', 'gmx.de', 'gmx.at', 'gmx.ch',
      'web.de', 'zoho.com', 'zohomail.com', 'yandex.com', 'yandex.ru',
      'mail.ru', 'bk.ru', 'inbox.ru', 'list.ru', 'rambler.ru',
      'qq.com', '163.com', '126.com', 'sina.com', 'sina.cn', 'foxmail.com',
      'naver.com', 'daum.net', 'hanmail.net', 'seznam.cz', 'wp.pl', 'o2.pl',
      'orange.fr', 'wanadoo.fr', 'free.fr', 'laposte.net', 'libero.it', 'virgilio.it',
      't-online.de', 'bluewin.ch', 'telenet.be', 'ziggo.nl', 'xs4all.nl',
      'btinternet.com', 'sky.com', 'virginmedia.com', 'bigpond.com', 'optusnet.com.au',
      // Large US ISP mailboxes.
      'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'cox.net',
      'charter.net', 'bellsouth.net', 'earthlink.net', 'shaw.ca', 'rogers.com',
    ].join(',')).split(',').map((d) => d.trim().toLowerCase().replace(/^@/, '')).filter(Boolean)),
    // Community blocklist, downloaded and refreshed like the IP datasets. It is
    // merged with the seed list above; matching stays entirely local.
    disposableList: {
      enabled: bool(process.env.DISPOSABLE_LIST_ENABLED, true),
      url: process.env.DISPOSABLE_LIST_URL ||
        'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf',
      refreshHours: int(process.env.DISPOSABLE_REFRESH_HOURS, 24),
      cacheDir: path.join(DATA_DIR, 'intel'),
    },
    newAccountTrustDelayMs: int(process.env.NEW_ACCOUNT_TRUST_DELAY_HOURS, 24) * 3600000,
    signupEmailWindowMs: int(process.env.RL_SIGNUP_EMAIL_WINDOW_MIN, 1440) * 60000,
    signupEmailMax: int(process.env.RL_SIGNUP_EMAIL_MAX, 3),
    // Signups from one network within 15 minutes before registration is
    // throttled. Counts volume only- never the mail domain, so a shared address
    // is not penalised for the mix of providers behind it.
    signupBurstMax: int(process.env.RL_SIGNUP_BURST_MAX, 15),
  },
  // Rate limits (per client IP, or per user for uploads). The default store is
  // in-memory (single instance). Set RATELIMIT_STORE=redis + REDIS_URL to share
  // counters across instances; requires `yarn add redis`.
  rateLimit: {
    enabled: bool(process.env.RATELIMIT_ENABLED, true),
    // Admins and owners bypass every limiter (they are trusted operators whose
    // moderation work looks like burst traffic). Unauthenticated endpoints such
    // as login are unaffected: there is no user to exempt yet.
    exemptStaff: bool(process.env.RATELIMIT_EXEMPT_STAFF, true),
    store: String(process.env.RATELIMIT_STORE || 'memory').trim().toLowerCase(),
    redisUrl: process.env.REDIS_URL || '',
    // Sized so that ordinary use never sees a 429: the limits exist to blunt
    // scripted abuse, not to ration normal browsing. Viewers behind shared NAT
    // (offices, campuses, mobile carriers) all share one IP bucket, so the
    // per-IP view limits in particular carry a lot of legitimate traffic.
    login: { windowMs: int(process.env.RL_LOGIN_WINDOW_MIN, 15) * 60000, max: int(process.env.RL_LOGIN_MAX, 30) },
    signup: { windowMs: int(process.env.RL_SIGNUP_WINDOW_MIN, 60) * 60000, max: int(process.env.RL_SIGNUP_MAX, 10) },
    upload: { windowMs: int(process.env.RL_UPLOAD_WINDOW_MIN, 60) * 60000, max: int(process.env.RL_UPLOAD_MAX, 120) },
    // Per-chunk budget, sized for whole files rather than requests: the hard
    // ceiling is 4 GB, which is ~44 chunks, and RL_UPLOAD_MAX uploads of that
    // size would be far more chunks than anyone sends in an hour.
    uploadChunk: { windowMs: int(process.env.RL_UPLOAD_CHUNK_WINDOW_MIN, 60) * 60000, max: int(process.env.RL_UPLOAD_CHUNK_MAX, 5000) },
    view: { windowMs: int(process.env.RL_VIEW_WINDOW_SEC, 60) * 1000, max: int(process.env.RL_VIEW_MAX, 600) },
    telemetry: { windowMs: int(process.env.RL_TELEMETRY_WINDOW_SEC, 60) * 1000, max: int(process.env.RL_TELEMETRY_MAX, 600) },
    report: { windowMs: int(process.env.RL_REPORT_WINDOW_MIN, 1440) * 60000, max: int(process.env.RL_REPORT_MAX, 10) },
    // Fixed ceilings for the routers and support endpoints (no env knobs: these
    // are ordinary page traffic, and a single page can issue several requests).
    altchaMax: int(process.env.RL_ALTCHA_MAX, 600),
    adminMax: int(process.env.RL_ADMIN_MAX, 900),
    authMax: int(process.env.RL_AUTH_MAX, 600),
    publicMax: int(process.env.RL_PUBLIC_MAX, 1200),
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
  emailVerificationRequired: bool(process.env.EMAIL_VERIFICATION_REQUIRED, process.env.NODE_ENV === 'production'),
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
