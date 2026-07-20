# NamelessUnSee

**NamelessUnSee** (the "unsee" service) is a transparent-source, consent-gated,
temporary image and video host that **watermarks every view with the viewer's own
IP, geolocation and device** so that leaks are traceable. It is a spiritual
successor to the defunct [unsee.cc](https://unsee.cc).

> **Honest note on "you can't get the image without the watermark."**
> No system can stop someone from photographing their screen or screenshotting a
> page. What unsee guarantees is that **the server never emits un-watermarked
> bytes**: the pristine original is stored server-side and never served, and
> every delivered image is rendered fresh and watermarked uniquely for the
> current viewer. This is exactly how forensic / leak-tracing watermarking works
> in practice.

---

## What it does

- **Consent gate first.** The first time in a browsing session that a visitor
  opens a share link, they must agree to the Terms and Privacy Policy (a checkbox
  plus a Continue button) before anything is loaded or logged. The agreement is
  stored in a **session cookie**, so the warning is shown **once per session**.
- **Per-viewer forensic watermark.** When an allowed viewer opens an image, the
  server bakes their **IP address, IP-based geolocation, network/ISP, and device
  (browser / OS / device type)** into the image as both a tiled, hard-to-crop
  overlay and a legible footer banner- unique to that viewer, never cached.
- **Logs everything it can- and says so.** On the image view (and only there),
  unsee records IP, geolocation, proxy/VPN status, User-Agent, request headers,
  and browser-exposed details (screen/viewport size, timezone, languages,
  platform, CPU/memory hints, touch support, User-Agent Client Hints, WebGL
  renderer, battery state, media capabilities, and limited font feature checks).
  The warning and Privacy Policy disclose this in plain language; the project
  does not hide that it logs.
- **The warning, ToS and Privacy pages perform no application collection.** They
  perform no application logging or geolocation and use only their own text,
  the site font, a self-hosted proof-of-work bot check where applicable, and a
  small self-hosted contact-reveal script. Cloudflare Insights may be injected
  by the edge if enabled by the deployment.
- **Scraper-proof contact address.** The operator email (`OPERATOR_CONTACT` in
  `.env`) is never sent as clear text: it ships encrypted using **ALTCHA's
  Obfuscation module** and is decrypted in-browser by a small, invisible,
  fully offline proof-of-work- no widget UI, no network requests, nothing for
  address-harvesting bots to scrape.
- **Blocks anonymised access- fully locally.** VPNs, proxies, datacenter
  egress and Tor are refused, and if the viewer's network cannot be identified,
  the image is not shown. Detection uses only **local datasets** (MaxMind
  GeoLite2, the Tor exit list, and X4BNet VPN/datacenter ranges) that the app
  **auto-downloads and keeps up to date**- a viewer's IP is never sent to any
  third party.
- **Bot / scraper protection.** The consent gate, signup, login, the image view
  page itself, and leak-report forms use [ALTCHA](https://altcha.org)
  proof-of-work, self-hosted (no third-party service, no tracking). The view
  page only renders the watermarked media after the check passes (a short-lived,
  per-image signed cookie records that it did).
- **Video support.** Uploads may be images (PNG, JPEG, WebP, GIF, AVIF) or
  videos (MP4, WebM, MOV, Ogg). Videos are re-encoded per view with the same
  forensic overlay burned into every frame. Needs `ffmpeg`/`ffprobe`- the
  Docker image ships them; install them yourself for local development.
- **Encrypted at rest.** Originals are encrypted with AES-256-GCM before hitting
  disk, with an optional S3-compatible backend (`STORAGE_BACKEND=s3` or `r2`-
  Cloudflare R2, MinIO, AWS S3, Backblaze B2...) that only ever receives
  encrypted bytes.
- **Per-recipient links.** Hand each person their own separate `/r/<token>` link
  to the same upload; the recipient URL does not reveal the upload's primary
  share token;
  the access log and the watermark itself show which link every view came
  through. Links can carry a view limit or be one-time, and can be revoked at
  any moment.
- **Galleries.** Combine multiple uploads into a single **gallery share link**
  (`/g/<token>`). Viewers see a list of items; each item is still served through
  the normal per-image view flow and is watermarked/logged per view.
- **Accounts with admin approval.** Uploading requires an account. The first
  account is auto-approved (a regular user); every later signup stays **pending**
  until an administrator approves it. **Admins are created only via the CLI.**
- **Two-factor login + recovery.** Every login requires a second factor: an
  emailed code (via Resend) by default, or an authenticator app (TOTP) once
  enrolled. Password, email, and username recovery flows work via emailed codes.
- **Leak reports.** Uploaders can report unauthorised redistribution- from an
  image page or against a specific logged view- with screenshot evidence;
  admins get a review queue.
- **Upload moderation.** Uploads are scanned at upload time: a
  perceptual-hash blocklist (admin-managed) auto-quarantines matches, and an
  optional self-hosted NSFW classifier sidecar routes suspect uploads to a human
  review queue. The sidecar is internal-only; trusted users skip scanning.
- **Admin panel.** Approve/deny account requests, promote/demote admins, and
  **ban by IP/CIDR, email, or user**- independently for *account access*
  (signup/login) and/or *viewing the service at all*.
- **Per-image retention, uploader's choice.** Pick how long an image is kept
  and/or a **maximum number of views** before instant deletion. By default the
  retention **timer starts on first view** (not at upload)- or start it
  immediately.
- **Save deterrence.** The view page serves the image as a CSS background (no
  `<img>` to "save as"), with a transparent overlay and disabled
  context-menu/drag/select/save-keys. (Screenshots can never be prevented- the
  per-viewer watermark is the real protection.)
- **Temporary storage.** Originals auto-delete when their timer or view cap is hit.

## Screens & flow

```
share link  ─►  /welcome (agree + ALTCHA)  ─►  consent cookie (session)
                                              │
                              /i/:token  ◄────┘   assess viewer
                              /r/:token  ─────────┘   recipient link (opaque)
                                   │             (block VPN/proxy/unknown)
                                   ▼
                       /i/:token/render.png   ── watermarked, per-viewer, no-store
                       /i/:token/telemetry    ── client-side beacon (logged)
```

## Tech

- **Node.js + Express** (server-rendered EJS- the legal pages are trivially
  auditable to prove they load nothing extra).
- **better-sqlite3** for storage, **sharp** for watermark compositing, and
  **ffmpeg/ffprobe** (system binaries) for probing and watermarking video
  uploads.
- **[0xProto](https://github.com/0xType/0xProto)** as the font everywhere-
  self-hosted `woff2` for the web UI, and installed in the container so watermark
  text uses it too.
- **[ALTCHA](https://github.com/altcha-org/altcha)** for anti-bot proof-of-work,
  verified server-side with no external calls.
- **Local, self-updating IP intelligence**- MaxMind GeoLite2 (ASN + City) via
  the `maxmind` reader, plus the Tor exit list and X4BNet VPN/datacenter ranges,
  all auto-downloaded and refreshed; per-viewer detection never leaves the box.
- Designed to run **in Docker behind a Cloudflare Tunnel**, which supplies the
  `CF-Connecting-IP` and `CF-IPCountry` headers unsee relies on.

## Quick start (local)

This project uses **Yarn Berry (v4.17.1)**, pinned by the `packageManager` field
and installed by Corepack.

```bash
cp .env.example .env
# edit .env: set COOKIE_SECRET at minimum
corepack enable
corepack install
corepack yarn install
# For local testing without a real public IP, allow private IPs so rendering works:
ALLOW_PRIVATE_IPS=true corepack yarn start
```

Open http://localhost:3000. The **first account you create is auto-approved**
(so the system is usable immediately) but is a **regular user**- every later
signup is pending until an admin approves it. **Owners/admins are only ever
created via the CLI:**

```bash
corepack yarn create-admin you@example.invalid yourname "your-strong-password"
```

This creates an approved Owner with admin access. Existing accounts can be made
Owners with `corepack yarn set-owner <email|username|uuid>`.

With Docker Compose, run these inside the app container so they use the live
SQLite database mounted at `/app/data`:

```bash
docker compose exec app corepack yarn create-admin you@example.invalid yourname "your-strong-password"
docker compose exec app corepack yarn set-owner you@example.invalid
```

## Deploy with Docker + Cloudflare Tunnel

1. In the Cloudflare **Zero Trust** dashboard → **Networks → Tunnels**, create a
   tunnel with the *Cloudflared* connector and copy its **token**.
2. Add a **Public Hostname** to that tunnel pointing your domain
   (e.g. `unsee.example.invalid`) at the service URL `http://app:3000`.
   Do not use `http://localhost:3000`: inside cloudflared, `localhost` refers
   to the cloudflared container, not the app container.
3. Configure and launch:

   ```bash
   cp .env.example .env
   # set COOKIE_SECRET, BASE_URL=https://unsee.example.invalid,
   #     SECURE_COOKIES=true, and TUNNEL_TOKEN=<your tunnel token>
   docker compose pull
   docker compose up -d
   ```

   The default Compose file pulls the app image and the internal moderation
   sidecar image from GHCR. Set `GHCR_IMAGE` or `MODERATION_IMAGE` to use
   another tag or digest. For a local source build, use
   `docker compose -f docker-compose.dev.yml up -d --build`.

The app is never exposed to the host directly- all inbound traffic arrives
through the Cloudflare Tunnel. SQLite is embedded in the app container; the
database (`namelessunsee.sqlite`), reports, and downloaded datasets persist in
the `unsee-data` volume mounted at `/app/data`. Encrypted media is stored there
only with `STORAGE_BACKEND=local`; R2 deployments stage media in ephemeral
container storage and upload it directly to R2.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BASE_URL` | `http://localhost:3000` | Public URL, used to build share links |
| `PORT` | `3000` | Port the Node server listens on |
| `COOKIE_SECRET` | *(required)* | Signs session & consent cookies- set a long random value |
| `ALTCHA_HMAC_KEY` | derived from `COOKIE_SECRET` | Dedicated persistent HMAC key for ALTCHA challenges; set separately in production |
| `ALTCHA_MAX_NUMBER` | `400000` | ALTCHA proof-of-work search ceiling; higher values increase anti-bot friction and client CPU time |
| `SECURE_COOKIES` | `false` | `true` in production (behind HTTPS/Cloudflare) |
| `SOURCE_URL` | this repo | Source-code link shown in the footer and on info pages |
| `DATA_DIR` | `./data` | Where the SQLite DB and uploaded originals live |
| `IMAGE_TTL_HOURS` | `24` | Retention before an upload is auto-purged (`0` = never) |
| `MAX_UPLOAD_MB` | `500` | Default max upload size per file |
| `MAX_REPORT_MB` | `10` | Max size per leak-report screenshot |
| `MAX_UPLOAD_HARD_MB` | `4096` | Absolute ceiling for admin per-user upload overrides |
| `MAX_STORAGE_MB` | `1024` | Default active storage quota per user |
| User ranks | `User`, `Trusted User`, `Owner` | Trusted users get 2x default limits and skip NSFW scanning; owners have no upload/storage limits and always have admin access |
| `STORAGE_BACKEND` | `local` | Encrypted media backend: `local`, or `s3`/`r2` for any S3-compatible store |
| `STORAGE_ENCRYPTION_KEY` | derived | AES-256-GCM key; set a 64-character hex key in production |
| `S3_ENDPOINT` / `S3_BUCKET` | | Generic S3-compatible endpoint and bucket when `STORAGE_BACKEND=s3` |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | | Object-store credentials |
| `S3_REGION` / `S3_FORCE_PATH_STYLE` | `auto` / `false` | Region and path-style addressing (MinIO wants `true`) |
| `BLOCK_PROXIES` | `true` | Refuse VPN/proxy/Tor viewers |
| `BLOCK_DATACENTER` | `true` | Also refuse datacenter/hosting egress |
| `BLOCK_ON_UNKNOWN` | `true` | Refuse when the viewer can't be assessed (datasets not yet loaded) |
| `ALLOW_PRIVATE_IPS` | `false` | Allow loopback/LAN IPs (enable for local dev) |
| `MAXMIND_LICENSE_KEY` | *(empty)* | Free [GeoLite2](https://www.maxmind.com/en/geolite2/signup) key; app auto-downloads GeoLite2-ASN + City and keeps them current |
| `MAXMIND_ASN_DB` / `MAXMIND_CITY_DB` | `./data/intel/…` | Paths to `.mmdb` files (mount your own instead of using a key) |
| `MAXMIND_REFRESH_HOURS` | `72` | GeoLite2 auto-update interval |
| `TOR_LIST_ENABLED` / `TOR_REFRESH_HOURS` | `true` / `6` | Tor exit-list detection + refresh interval |
| `VPN_LISTS_ENABLED` / `VPN_REFRESH_HOURS` | `true` / `24` | X4BNet VPN + datacenter ranges + refresh interval |
| `RESEND_API_KEY` | *(empty)* | Resend API key for signup notices and required email 2FA |
| `ADMIN_NOTIFY_FROM` / `ADMIN_NOTIFY_TO` | | Sender for 2FA and admin notices; admin recipient for signup, moderation, and report notices |
| `TWOFA_ENABLED` | `true` | Require second factor after password login |
| `TWOFA_CONSOLE_FALLBACK` | `false` | Development-only console OTP fallback; keep disabled in production |
| `TWOFA_CHALLENGE_MIN` | `5` | Email/TOTP challenge lifetime in minutes |
| `RL_REPORT_WINDOW_MIN` / `RL_REPORT_MAX` | `1440` / `3` | Leak-report rate limit per account |
| `RATELIMIT_STORE` / `REDIS_URL` | `memory` | Set `redis` + a URL to share rate-limit counters across instances (`yarn add redis`) |
| `MODERATION_ENABLED` | `true` | Upload-time scanning (perceptual-hash blocklist + optional classifier) |
| `MODERATION_HOLD_ON_REVIEW` | `true` | Hold review-flagged uploads (unviewable) until an admin decides |
| `MODERATION_PHASH_THRESHOLD` | `10` | Max Hamming distance for 64-bit blocklist entries |
| `MODERATION_PDQ_THRESHOLD` | `31` | Max Hamming distance for 256-bit PDQ blocklist entries |
| `NSFW_CLASSIFIER_ENABLED` / `NSFW_MODEL` / `NSFW_SAFETY_MODEL` / `NSFW_BINARY_MODEL` / `NSFW_THRESHOLD` / `NSFW_FAIL_CLOSED` | `true` / `onnx-community/nsfw-classifier-ONNX` / `OwenElliott/image-safety-classifier-m` / `onnx-community/nsfw_image_detection-ONNX` / `0.80` / `true` | Three-model moderation ensemble; reports subtype, NSFW/NSFL, and binary labels for review |
| `NSFW_SERVICE_URL` / `NSFW_SERVICE_TIMEOUT_MS` | `http://moderation:8787` / `15000` | Internal moderation sidecar endpoint and request timeout |
| `TUNNEL_TOKEN` | | Cloudflare Tunnel token (used by docker-compose) |

> **All proxy/VPN/Tor detection is local and self-updating.** On startup the app
> loads any cached datasets, then downloads the latest MaxMind GeoLite2 (if a
> licence key is set), the Tor exit list, and the X4BNet VPN/datacenter ranges,
> refreshing each on its own schedule. **Viewer IPs are never sent to a third
> party.** Until the datasets finish loading the first time, `BLOCK_ON_UNKNOWN`
> decides whether viewers are allowed through.
>
> Trade-off: local lists catch Tor, commercial VPNs and datacenter/cloud egress,
> but not residential proxies (those need a paid commercial dataset). Country is
> always available for free from Cloudflare's `CF-IPCountry` header even with no
> MaxMind key.

## Security & privacy model

- **Consent cookie** is a signed **session cookie** (cleared on browser close) →
  the warning shows once per session.
- **Content-Security-Policy** is locked down per route:
  - ToS / Privacy: `default-src 'none'` plus same-origin scripts and the
    explicitly allowlisted Cloudflare Insights endpoints. The application does
    not collect or log those requests itself.
  - App pages allow only the self-hosted assets plus the explicitly allowlisted
    Cloudflare Insights script and beacon endpoints.
  - Inline application scripts use a per-response **nonce**; `unsafe-inline` is
    not enabled for scripts. Cloudflare's injected external script is permitted
    by its exact origin because it cannot know the app-generated nonce.
- **Third-party requests in the request path** are limited to Cloudflare
  Insights when enabled by the deployment; the font and ALTCHA widget remain
  self-hosted, and there are **no per-viewer IP lookups**. The app also
  periodically fetches public intel datasets (MaxMind/Tor/X4BNet) to update
  itself.
- **CSRF** protection on all authenticated state-changing actions (per-session
  token) plus a same-origin check and `SameSite` cookies.
- **Passwords** hashed with per-password random salts using scrypt (Node stdlib,
  OWASP baseline parameters); verification uses constant-time comparison.
- The **original image is never served**- there is no route that returns it.

## Attribution & licensing

unsee is licensed under the **Nameless Nanashi Code License (NNCL) v1.4**- see
[`LICENSE.md`](./LICENSE.md) for the full text. In summary it permits
non-commercial use, study, sharing and adaptation under firm ethical conditions,
and requires that adaptations carry the same license and policy forward.
Project: **unsee** by [NamelessNanashi](https://git.NamelessNanashi.dev/).

Bundled third-party components keep their own licenses:

- **0xProto** font- SIL Open Font License 1.1
  (`public/fonts/0xProto-OFL-LICENSE.txt`, `assets/fonts/OFL.txt`).
- **ALTCHA** widget- MIT (`public/altcha-LICENSE.txt`).

Intel datasets are downloaded at runtime (not bundled) and remain under their
own terms- review them before deploying:

- **MaxMind GeoLite2** (ASN + City)- GeoLite2 End User License Agreement;
  requires a free MaxMind account/licence key. This product includes GeoLite2
  data created by MaxMind, available from <https://www.maxmind.com>.
- **Tor exit list**- from the Tor Project.
- **VPN / datacenter ranges**- [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn).

If you deploy a modified version, per NNCL §3 keep attribution, note your changes
and their date, make corresponding source available, and reproduce the license
(including its Policy) in full.
