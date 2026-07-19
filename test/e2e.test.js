'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// Configure a throwaway instance before requiring the app.
process.env.COOKIE_SECRET = 'test-' + 'x'.repeat(40);
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nus-e2e-'));
process.env.ALLOW_PRIVATE_IPS = 'true';
process.env.STORAGE_BACKEND = 'local';
process.env.TOR_LIST_ENABLED = 'false';
process.env.VPN_LISTS_ENABLED = 'false';
process.env.MAXMIND_LICENSE_KEY = '';
process.env.ALTCHA_MAX_NUMBER = '4000';
process.env.RATELIMIT_ENABLED = 'false';
process.env.SECURE_COOKIES = 'false';
process.env.NSFW_CLASSIFIER_ENABLED = 'false'; // no external model in CI
process.env.TWOFA_ENABLED = 'false'; // dedicated 2FA coverage lives in test/twofa.test.js
process.env.OPERATOR_CONTACT = 'operator@test.example'; // exercises the obfuscated-contact path
process.env.RESEND_API_KEY = ''; // never send real email from tests (a real key may sit in local .env)
process.env.ADMIN_NOTIFY_FROM = '';
process.env.ADMIN_NOTIFY_TO = '';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const sharp = require('sharp');

const app = require('../src/server');
const db = require('../src/db');
const config = require('../src/config');
const bans = require('../src/bans');
const { hashPassword, uuidv7 } = require('../src/util/crypto');
const { newJar, makeReq, form, solveAltcha, consent, csrfFrom } = require('./helpers');

async function pngBuffer(w, h) {
  return sharp({ create: { width: w, height: h, channels: 3, background: { r: 10, g: 80, b: 140 } } })
    .png()
    .toBuffer();
}

test('public + legal pages', async () => {
  const req = makeReq(app, newJar());
  for (const p of ['/', '/welcome', '/tos', '/privacy', '/login', '/signup', '/acknowledgements', '/license', '/license.md']) {
    assert.equal((await req(p)).status, 200, `GET ${p}`);
  }
  const loginHtml = await (await req('/login')).text();
  assert.ok(loginHtml.includes('<altcha-widget'), 'login page includes ALTCHA');
  const csp = (await req('/tos')).headers.get('content-security-policy') || '';
  assert.ok(
    csp.includes("default-src 'none'") && csp.includes("'self'") && csp.includes('script-src'),
    'legal CSP allows nonce-protected same-origin scripts (offline contact reveal)'
  );
  assert.ok(csp.includes('https://static.cloudflareinsights.com'), 'legal CSP allows Cloudflare Insights');
  assert.ok(csp.includes('https://cloudflareinsights.com'), 'legal CSP allows Insights beacon connections');
  assert.match(csp, /script-src 'nonce-[^']+'/i, 'legal CSP includes a per-response script nonce');

  const appCsp = (await req('/login')).headers.get('content-security-policy') || '';
  assert.ok(appCsp.includes('https://static.cloudflareinsights.com'), 'app CSP allows Cloudflare Insights');
  assert.ok(appCsp.includes('https://cloudflareinsights.com'), 'app CSP allows Insights beacon connections');
  assert.ok(appCsp.includes("media-src 'self'"), 'app CSP allows same-origin video previews');
  assert.match(appCsp, /script-src 'nonce-[^']+'/i, 'app CSP includes a per-response script nonce');
});

test('operator contact is obfuscated, never sent as clear text', async () => {
  const req = makeReq(app, newJar());
  const contact = config.operator.contact;
  for (const p of ['/tos', '/privacy']) {
    const html = await (await req(p)).text();
    if (contact) {
      assert.ok(!html.includes(contact), `${p} does not leak the contact address`);
      assert.ok(html.includes('data-obfuscated-email='), `${p} carries the obfuscated payload`);
      assert.ok(html.includes('/altcha-obfuscation.min.js'), `${p} loads the obfuscation module`);
      // The payload decodes to the ALTCHA Obfuscation format, not the address.
      const payload = html.match(/data-obfuscated-email="([^"]+)"/)[1];
      const parsed = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
      assert.ok(parsed.parameters && parsed.cipher, 'payload has parameters + cipher');
      assert.ok(!JSON.stringify(parsed).includes(contact), 'payload does not embed the address');
    } else {
      assert.ok(!html.includes('data-obfuscated-email='), `${p} omits the reveal when no contact is set`);
    }
  }
  for (const asset of ['/altcha-obfuscation.min.js', '/email-reveal.js']) {
    assert.equal((await req(asset)).status, 200, `GET ${asset}`);
  }
});

test('same-origin guard: null origin (no-referrer browsers) allowed, real cross-origin blocked', async () => {
  const jar = newJar();
  const req = makeReq(app, jar);
  const sol = await solveAltcha(req);
  // Browsers under Referrer-Policy: no-referrer send Origin: null on same-origin
  // form posts- this must be accepted.
  let r = await req('/welcome', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'null' },
    body: new URLSearchParams({ agree: 'on', altcha: sol, next: '/' }).toString(),
  });
  assert.equal(r.status, 302, 'null-origin form post accepted');
  assert.ok(jar.has('consent'));
  // A genuine cross-origin Origin is still blocked.
  r = await req('/welcome', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'http://evil.example' },
    body: new URLSearchParams({ agree: 'on', next: '/' }).toString(),
  });
  assert.equal(r.status, 403, 'cross-origin form post blocked');
});

test('consent gate, first-user signup (auto-approved user), upload, watermark, telemetry, logs', async () => {
  const jar = newJar();
  const req = makeReq(app, jar);

  // Gate: no consent -> redirect to /welcome
  let r = await req('/i/doesnotexist');
  assert.equal(r.status, 302);
  assert.ok((r.headers.get('location') || '').includes('/welcome'));

  // Bad ALTCHA rejected
  r = await req('/welcome', form({ agree: 'on', altcha: 'bad', next: '/' }));
  assert.ok((r.headers.get('location') || '').includes('error=altcha'));

  // Consent granted
  await consent(req, '/');
  assert.ok(jar.has('consent'));

  // First signup -> auto-approved regular user, logged in
  const sol = await solveAltcha(req);
  r = await req('/signup', form({ email: 'first@example.invalid', username: 'firstuser', password: 'password1234', altcha: sol }));
  assert.equal(r.status, 302, 'first signup redirects');
  assert.ok(jar.has('sid'), 'first user logged in');
  // ...and is NOT an admin
  const firstRole = db.prepare('SELECT role, status FROM users WHERE username = ?').get('firstuser');
  assert.equal(firstRole.role, 'user');
  assert.equal(firstRole.status, 'approved');

  // Account settings control defaults shown for future uploads.
  const accountHtml = await (await req('/account')).text();
  const accountCsrf = csrfFrom(accountHtml);
  assert.ok(accountHtml.includes('Image Defaults') && accountHtml.includes('Security'));
  r = await req('/account/defaults', form({
    _csrf: accountCsrf,
    default_ttl: '1h',
    default_timer_start: 'upload',
    default_max_views: '2',
  }));
  assert.equal(r.status, 200);
  const savedDefaults = db.prepare('SELECT default_ttl, default_timer_start, default_max_views FROM users WHERE username = ?').get('firstuser');
  assert.deepEqual(savedDefaults, { default_ttl: '1h', default_timer_start: 'upload', default_max_views: 2 });
  const dashboardWithDefaults = await (await req('/dashboard')).text();
  assert.match(dashboardWithDefaults, /option value="1h" selected/);
  assert.match(dashboardWithDefaults, /name="max_views"[^>]+min="1" value="2"/);

  // Upload
  const dash = await (await req('/dashboard')).text();
  const csrf = csrfFrom(dash);
  assert.ok(csrf, 'csrf on dashboard');
  const fd = new FormData();
  fd.set('_csrf', csrf);
  fd.set('title', 'e2e');
  fd.set('ttl', '1h');
  fd.set('timer_start', 'first_view');
  fd.set('image', new Blob([await pngBuffer(300, 180)], { type: 'image/png' }), 't.png');
  r = await req('/upload', { method: 'POST', body: fd });
  assert.equal(r.status, 302, 'upload ok');
  const storedImage = db.prepare('SELECT storage_name, storage_encrypted FROM images WHERE title = ? ORDER BY id DESC').get('e2e');
  assert.equal(storedImage.storage_encrypted, 1, 'new originals are encrypted');
  assert.ok(fs.existsSync(path.join(config.uploadDir, storedImage.storage_name + '.enc')), 'encrypted local object exists');
  assert.equal(fs.existsSync(path.join(config.uploadDir, storedImage.storage_name)), false, 'plaintext original is removed');

  // Multiple files are accepted together and automatically grouped.
  const batch = new FormData();
  batch.set('_csrf', csrf);
  batch.set('title', 'batch gallery');
  batch.set('ttl', '1h');
  batch.append('image', new Blob([await pngBuffer(80, 60)], { type: 'image/png' }), 'batch-a.png');
  batch.append('image', new Blob([await pngBuffer(90, 70)], { type: 'image/png' }), 'batch-b.png');
  r = await req('/upload', { method: 'POST', body: batch });
  assert.equal(r.status, 302, 'batch upload ok');
  const batchGalleryToken = new URL(r.headers.get('location'), config.baseUrl).searchParams.get('gallery');
  assert.ok(batchGalleryToken, 'batch upload redirects with gallery token');
  const batchGallery = db.prepare('SELECT id FROM galleries WHERE token = ?').get(batchGalleryToken);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM gallery_items WHERE gallery_id = ?').get(batchGallery.id).n, 2, 'both files grouped into gallery');
  assert.equal((await req('/g/' + batchGalleryToken)).status, 200, 'generated gallery opens');

  const token = db.prepare("SELECT token FROM images WHERE title = 'e2e' ORDER BY id DESC").get().token;
  assert.ok(token, 'share token present');

  // View page
  assert.equal((await req('/i/' + token)).status, 200);

  // Watermarked render
  await req('/i/' + token + '/view-check', form({ altcha: await solveAltcha(req) }));
  const viewId = crypto.randomBytes(16).toString('hex');
  r = await req('/i/' + token + '/render.png?v=' + viewId);
  assert.equal(r.status, 200);
  assert.ok((r.headers.get('content-type') || '').includes('image/png'));
  assert.ok(r.headers.get('cache-control').includes('no-store'));
  const meta = await sharp(Buffer.from(await r.arrayBuffer())).metadata();
  assert.equal(meta.width, 300);
  assert.equal(meta.height, 180);

  // First-view timer started (expires_at now set)
  const img = db.prepare('SELECT expires_at, first_viewed_at FROM images WHERE token = ?').get(token);
  assert.ok(img.first_viewed_at && img.expires_at, 'first-view timer started');

  // Telemetry
  r = await req('/i/' + token + '/telemetry', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ viewId, client: { screenW: 1920, screenH: 1080, platform: 'Linux x86_64' } }),
  });
  assert.equal(r.status, 204);

  // Logs page shows the client telemetry + search works
  const logs = await (await req('/dashboard/i/' + token + '/logs')).text();
  assert.ok(/1920/.test(logs) && /Linux/.test(logs), 'logs show telemetry');
  const searched = await (await req('/dashboard/i/' + token + '/logs?q=Linux')).text();
  assert.ok(/1 match/.test(searched), 'log search finds the entry');
  const searchedMiss = await (await req('/dashboard/i/' + token + '/logs?q=NoSuchThing')).text();
  assert.ok(/0 matches/.test(searchedMiss), 'log search reports no matches');

  // Owner can report a specific access-log entry; it becomes non-repeatable.
  const logHtml = await (await req('/dashboard/i/' + token + '/logs')).text();
  const logId = (logHtml.match(new RegExp('/dashboard/i/' + token + '/logs/(\\d+)/report')) || [])[1];
  assert.ok(logId, 'access log offers report action');
  const ownerReportFd = new FormData();
  ownerReportFd.set('_csrf', csrf);
  ownerReportFd.set('details', 'Owner proof report.');
  ownerReportFd.set('altcha', await solveAltcha(req));
  ownerReportFd.append('proofs', new Blob([await pngBuffer(140, 90)], { type: 'image/png' }), 'owner-proof.png');
  ownerReportFd.append('proofs', new Blob([await pngBuffer(150, 95)], { type: 'image/png' }), 'owner-proof-2.png');
  r = await req('/dashboard/i/' + token + '/logs/' + logId + '/report', { method: 'POST', body: ownerReportFd });
  assert.equal(r.status, 302, 'owner report submitted');
  const afterReportLogs = await (await req('/dashboard/i/' + token + '/logs')).text();
  assert.ok(afterReportLogs.includes('Already Reported'), 'reported entry is disabled');

  // Authenticated viewer can submit screenshot proof for a view.
  const reportFd = new FormData();
  reportFd.set('_csrf', csrf);
  reportFd.set('reason', 'unauthorized_redistribution');
  reportFd.set('details', 'Screenshot shows the traceable copy being redistributed.');
  reportFd.set('view_ref', `${token}/12345678`);
  reportFd.set('altcha', await solveAltcha(req));
  reportFd.append('proofs', new Blob([await pngBuffer(160, 100)], { type: 'image/png' }), 'proof.png');
  r = await req('/i/' + token + '/report', { method: 'POST', body: reportFd });
  assert.equal(r.status, 302, 'report submitted');
  const report = db.prepare('SELECT * FROM leak_reports WHERE image_id = (SELECT id FROM images WHERE token = ?)').get(token);
  assert.equal(report.reason, 'unauthorized_redistribution');
  assert.equal(report.status, 'open');
  assert.ok(fs.existsSync(path.join(process.env.DATA_DIR, 'reports', report.proof_storage_name)), 'proof stored privately');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM leak_report_proofs WHERE report_id = ?').get(report.id).count, 2);
});

test('retention: max_views deletes after the cap', async () => {
  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');
  // log in as firstuser
  const loginAltcha = await solveAltcha(req);
  await req('/login', form({ identifier: 'firstuser', password: 'password1234', altcha: loginAltcha, next: '/dashboard' }));
  const csrf = csrfFrom(await (await req('/dashboard')).text());

  const fd = new FormData();
  fd.set('_csrf', csrf);
  fd.set('title', 'oneshot');
  fd.set('ttl', 'never');
  fd.set('max_views', '1');
  fd.set('image', new Blob([await pngBuffer(120, 90)], { type: 'image/png' }), 'o.png');
  await req('/upload', { method: 'POST', body: fd });

  // find the newest token owned by firstuser
  const token = db
    .prepare("SELECT token FROM images WHERE title = 'oneshot' AND deleted_at IS NULL ORDER BY created_at DESC")
    .get().token;

  await req('/i/' + token + '/view-check', form({ altcha: await solveAltcha(req) }));
  assert.equal((await req('/i/' + token + '/render.png?v=' + crypto.randomBytes(16).toString('hex'))).status, 200);
  const second = await req('/i/' + token + '/render.png?v=' + crypto.randomBytes(16).toString('hex'));
  assert.ok(second.status === 404 || second.status === 410, 'deleted after max_views');
});

test('admin: seed via DB, ban (view) blocks service-wide, audit recorded', async () => {
  const now = Date.now();
  db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, 'admin', 'approved', ?, ?)`
  ).run(uuidv7(now), 'admin@example.invalid', 'adminx', hashPassword('adminpass1234'), now, now);

  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');
  const adminAltcha = await solveAltcha(req);
  await req('/login', form({ identifier: 'adminx', password: 'adminpass1234', altcha: adminAltcha, next: '/dashboard' }));

  const adminHtml = await (await req('/admin')).text();
  const csrf = csrfFrom(adminHtml);
  assert.ok(csrf, 'admin page + csrf');
  assert.ok(/Leak reports/.test(adminHtml), 'admin sees leak reports');

  const targetUser = db.prepare("SELECT id FROM users WHERE username = 'firstuser'").get();
  const targetImage = db.prepare('SELECT token FROM images WHERE owner_id = ? AND deleted_at IS NULL ORDER BY id DESC').get(targetUser.id);
  const accessLogCount = db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = (SELECT id FROM images WHERE token = ?)').get(targetImage.token).n;
  const original = await req('/admin/users/' + targetUser.id + '/files/' + targetImage.token);
  assert.equal(original.status, 200, 'admin can retrieve original from user files');
  assert.ok((original.headers.get('content-type') || '').includes('image/png'));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM access_logs WHERE image_id = (SELECT id FROM images WHERE token = ?)').get(targetImage.token).n, accessLogCount, 'admin retrieval does not create viewer log');

  assert.equal((await req('/admin/users/' + targetUser.id + '/limits', form({ _csrf: csrf, upload_max_mb: '2', storage_limit_mb: '20' }))).status, 302);
  const limits = db.prepare('SELECT upload_max_bytes, storage_limit_bytes FROM users WHERE id = ?').get(targetUser.id);
  assert.deepEqual(limits, { upload_max_bytes: 2 * 1048576, storage_limit_bytes: 20 * 1048576 });

  const report = db.prepare("SELECT id FROM leak_reports WHERE status = 'open' ORDER BY id DESC LIMIT 1").get();
  if (report) {
    const proof = await req('/admin/reports/' + report.id + '/proof');
    assert.equal(proof.status, 200, 'admin can view private proof');
    assert.ok((proof.headers.get('content-type') || '').includes('image/png'));
    assert.equal((await req('/admin/reports/' + report.id + '/status', form({ _csrf: csrf, status: 'reviewed', admin_note: 'Evidence reviewed.' }))).status, 302);
    assert.equal(db.prepare('SELECT status FROM leak_reports WHERE id = ?').get(report.id).status, 'reviewed');
  }

  // Add a view-ban with an expiry
  let r = await req('/admin/bans', form({ _csrf: csrf, kind: 'ip', value: '198.51.100.5', block_view: '1', expires: '1h', reason: 'test' }));
  assert.equal(r.status, 302);

  // The banned IP is blocked from the whole service
  r = await req('/', { headers: { 'cf-connecting-ip': '198.51.100.5' } });
  assert.equal(r.status, 403);
  // A different IP is fine
  assert.equal((await req('/', { headers: { 'cf-connecting-ip': '198.51.100.9' } })).status, 200);

  // Audit + expiry surfaced on the admin page
  const adm2 = await (await req('/admin')).text();
  assert.ok(/add_ban/.test(adm2), 'audit shows add_ban');
  assert.ok(/198\.51\.100\.5/.test(adm2), 'ban listed');
});

test('bans: expired ban is not enforced and gets swept', () => {
  const past = Date.now() - 1000;
  db.prepare(
    `INSERT INTO bans (kind, value, block_account, block_view, reason, created_at, expires_at)
     VALUES ('ip', '203.0.113.200', 0, 1, 'expired', ?, ?)`
  ).run(past, past);
  bans.reload();
  assert.ok(!bans.isViewBannedIp('203.0.113.200'), 'expired ban not enforced');
  const removed = bans.sweepExpired();
  assert.ok(removed >= 1, 'sweep removed the expired ban');
});

test('recipient links: labelled, one-time with replay-safe counting, revocable', async () => {
  const jar = newJar();
  const req = makeReq(app, jar);
  await consent(req, '/');
  let r = await req('/login', form({ identifier: 'firstuser', password: 'password1234', altcha: await solveAltcha(req), next: '/dashboard' }));
  assert.equal(r.status, 302, 'login ok');

  // Upload without a view cap so link accounting is isolated from max_views.
  const dash = await (await req('/dashboard')).text();
  const fd = new FormData();
  fd.set('_csrf', csrfFrom(dash));
  fd.set('title', 'linktest');
  fd.set('ttl', '1h');
  fd.set('timer_start', 'first_view');
  fd.set('max_views', '0');
  fd.set('image', new Blob([await pngBuffer(120, 90)], { type: 'image/png' }), 'l.png');
  r = await req('/upload', { method: 'POST', body: fd });
  assert.equal(r.status, 302, 'upload ok');
  const img = db.prepare('SELECT id, token FROM images WHERE title = ?').get('linktest');
  assert.ok(img, 'image stored');

  // Create a labelled one-time link.
  const linksHtml = await (await req(`/dashboard/i/${img.token}/links`)).text();
  r = await req(`/dashboard/i/${img.token}/links`, form({ _csrf: csrfFrom(linksHtml), label: 'Alex', one_time: 'on' }));
  assert.equal(r.status, 302, 'link created');
  const link = db.prepare('SELECT * FROM view_links WHERE image_id = ?').get(img.id);
  assert.equal(link.max_uses, 1);
  assert.equal(link.label, 'Alex');
  const recipientUrl = `/r/${link.token}`;
  assert.ok(!recipientUrl.includes(img.token), 'recipient URL does not expose the primary image token');

  // View + render through the link.
  r = await req(recipientUrl);
  assert.equal(r.status, 200);
  const recipientHtml = await r.text();
  assert.ok(recipientHtml.includes(`/r/${link.token}`));
  assert.ok(!recipientHtml.includes(img.token), 'recipient page does not expose the primary image token');
  assert.ok(!recipientHtml.includes(`/i/${img.token}?r=${link.token}`), 'recipient page does not publish the primary link');
  await req(`${recipientUrl}/view-check`, form({ altcha: await solveAltcha(req) }));
  const viewId = crypto.randomBytes(16).toString('hex');
  r = await req(`${recipientUrl}/render.png?v=${viewId}`);
  assert.equal(r.status, 200, 'link render ok');
  assert.equal(
    db.prepare('SELECT link_label FROM access_logs WHERE image_id = ? AND view_id = ?').get(img.id, viewId).link_label,
    'Alex',
    'link label on the access log'
  );
  assert.equal(db.prepare('SELECT use_count FROM view_links WHERE id = ?').get(link.id).use_count, 1);

  // Replaying the same view id (video seek / replay) is free.
  const viewsBefore = db.prepare('SELECT view_count FROM images WHERE id = ?').get(img.id).view_count;
  r = await req(`${recipientUrl}/render.png?v=${viewId}`);
  assert.equal(r.status, 200, 'replay allowed');
  assert.equal(db.prepare('SELECT use_count FROM view_links WHERE id = ?').get(link.id).use_count, 1, 'replay does not consume the link');
  assert.equal(db.prepare('SELECT view_count FROM images WHERE id = ?').get(img.id).view_count, viewsBefore, 'replay does not count a view');

  // A fresh view through the used-up one-time link is refused; the plain link still works.
  assert.equal((await req(`${recipientUrl}/render.png?v=${crypto.randomBytes(16).toString('hex')}`)).status, 410, 'one-time link used up');
  assert.equal((await req(`/i/${img.token}/render.png?v=${crypto.randomBytes(16).toString('hex')}`)).status, 200, 'plain share link unaffected');

  // Revoked links stop working immediately.
  const lh = await (await req(`/dashboard/i/${img.token}/links`)).text();
  await req(`/dashboard/i/${img.token}/links`, form({ _csrf: csrfFrom(lh), label: 'Sam' }));
  const sam = db.prepare("SELECT * FROM view_links WHERE image_id = ? AND label = 'Sam'").get(img.id);
  await req(`/dashboard/i/${img.token}/links/${sam.id}/revoke`, form({ _csrf: csrfFrom(lh) }));
  assert.equal((await req(`/r/${sam.token}`)).status, 410, 'revoked link rejected');
});

test('admin: delete user (admins delete non-admins, owner deletes admins, owner/self protected)', async () => {
  const now = Date.now();
  const seed = db.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, rank, status, created_at, approved_at)
     VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?)`
  );
  const victimId = uuidv7(now);
  const admin2Id = uuidv7(now);
  const ownerId = uuidv7(now);
  seed.run(victimId, 'victim@example.invalid', 'victim', hashPassword('victimpass1234'), 'user', 'user', now, now);
  seed.run(admin2Id, 'admin2@example.invalid', 'admin2', hashPassword('adminpass1234'), 'admin', 'user', now, now);
  seed.run(ownerId, 'boss@example.invalid', 'bigboss', hashPassword('ownerpass1234'), 'admin', 'owner', now, now);

  const adminxId = db.prepare("SELECT id FROM users WHERE username = 'adminx'").get().id;

  const login = async (identifier, password) => {
    const jar = newJar();
    const req = makeReq(app, jar);
    await consent(req, '/');
    const altcha = await solveAltcha(req);
    await req('/login', form({ identifier, password, altcha, next: '/dashboard' }));
    return req;
  };

  // Plain admin: may delete a normal user...
  const adminReq = await login('adminx', 'adminpass1234');
  const csrf = csrfFrom(await (await adminReq('/admin/users')).text());
  assert.equal((await adminReq('/admin/users/' + victimId + '/delete', form({ _csrf: csrf }))).status, 302);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE id = ?').get(victimId).n, 0, 'victim removed');

  // ...but not another admin, themselves, or the owner.
  assert.equal((await adminReq('/admin/users/' + admin2Id + '/delete', form({ _csrf: csrf }))).status, 403, 'admin cannot delete admin');
  assert.equal((await adminReq('/admin/users/' + adminxId + '/delete', form({ _csrf: csrf }))).status, 403, 'cannot delete self');
  assert.equal((await adminReq('/admin/users/' + ownerId + '/delete', form({ _csrf: csrf }))).status, 403, 'cannot delete owner');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE id IN (?, ?, ?)').get(admin2Id, adminxId, ownerId).n, 3);

  // Owner: may delete an admin, even one with audit-log entries and bans
  // pointing at them (adminx recorded audit rows and created bans earlier).
  const ownerReq = await login('bigboss', 'ownerpass1234');
  const ocsrf = csrfFrom(await (await ownerReq('/admin/users')).text());
  assert.equal((await ownerReq('/admin/users/' + adminxId + '/delete', form({ _csrf: ocsrf }))).status, 302);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE id = ?').get(adminxId).n, 0, 'admin removed by owner');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?').get(adminxId).n, 0, 'sessions cascade');
  assert.ok(db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'delete_user'").get().n >= 2, 'deletions audited');
});
