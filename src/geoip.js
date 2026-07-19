'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const maxmind = require('maxmind');
const config = require('./config');

const CFG = config.ipIntel.maxmind;

let asnReader = null;
let cityReader = null;

async function openReaders() {
  try {
    if (fs.existsSync(CFG.asnPath)) asnReader = await maxmind.open(CFG.asnPath);
  } catch (e) {
    console.warn('[NamelessUnSee] failed to open ASN db:', e.message);
  }
  try {
    if (fs.existsSync(CFG.cityPath)) cityReader = await maxmind.open(CFG.cityPath);
  } catch (e) {
    console.warn('[NamelessUnSee] failed to open City db:', e.message);
  }
}

function findMmdb(dir, editionId) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findMmdb(full, editionId);
      if (found) return found;
    } else if (entry.name === `${editionId}.mmdb`) {
      return full;
    }
  }
  return null;
}

// Download a GeoLite2 edition using the licence key, verifying the published
// SHA-256 and only replacing the local copy when it actually changed.
// MaxMind serves the actual database from an R2 presigned URL via a redirect
// from download.maxmind.com. Node's fetch follows redirects by default; we set
// it explicitly and add a timeout + User-Agent. If a firewall is in play, allow
// HTTPS to `download.maxmind.com` AND
// `*.r2.cloudflarestorage.com` (specifically
// mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com).
async function mmFetch(url) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 60000);
  try {
    return await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'NamelessUnSee/1.0 (+geoip-update)' },
    });
  } finally {
    clearTimeout(t);
  }
}

async function downloadEdition(editionId, destPath) {
  const key = CFG.licenseKey;
  if (!key) return false;
  const base = `https://download.maxmind.com/app/geoip_download?edition_id=${encodeURIComponent(
    editionId
  )}&license_key=${encodeURIComponent(key)}`;

  let shaRes;
  try {
    shaRes = await mmFetch(base + '&suffix=tar.gz.sha256');
  } catch (e) {
    console.warn(`[NamelessUnSee] MaxMind ${editionId} checksum request error:`, e.message);
    return false;
  }
  if (!shaRes.ok) {
    console.warn(`[NamelessUnSee] MaxMind ${editionId} checksum fetch failed:`, shaRes.status);
    return false;
  }
  const remoteSha = (await shaRes.text()).trim().split(/\s+/)[0];
  const shaFile = destPath + '.sha256';
  const localSha = fs.existsSync(shaFile) ? fs.readFileSync(shaFile, 'utf8').trim() : '';
  if (remoteSha && remoteSha === localSha && fs.existsSync(destPath)) return false; // up to date

  let tgzRes;
  try {
    tgzRes = await mmFetch(base + '&suffix=tar.gz');
  } catch (e) {
    console.warn(`[NamelessUnSee] MaxMind ${editionId} download error:`, e.message);
    return false;
  }
  if (!tgzRes.ok) {
    console.warn(`[NamelessUnSee] MaxMind ${editionId} download failed:`, tgzRes.status);
    return false;
  }
  const buf = Buffer.from(await tgzRes.arrayBuffer());
  const gotSha = crypto.createHash('sha256').update(buf).digest('hex');
  if (remoteSha && gotSha !== remoteSha) {
    console.warn(`[NamelessUnSee] MaxMind ${editionId} checksum mismatch- discarding download`);
    return false;
  }

  const tmpDir = fs.mkdtempSync(path.join(config.ipIntel.cacheDir, 'mm-'));
  const tgzPath = path.join(tmpDir, `${editionId}.tar.gz`);
  try {
    fs.writeFileSync(tgzPath, buf);
    execFileSync('tar', ['-xzf', tgzPath, '-C', tmpDir]);
    const mmdb = findMmdb(tmpDir, editionId);
    if (!mmdb) {
      console.warn(`[NamelessUnSee] MaxMind ${editionId}: .mmdb not found in archive`);
      return false;
    }
    fs.copyFileSync(mmdb, destPath);
    fs.writeFileSync(shaFile, gotSha);
    console.log(`[NamelessUnSee] MaxMind ${editionId} updated`);
    return true;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function refresh() {
  if (!CFG.licenseKey) return; // nothing to auto-download; use mounted files if present
  try {
    const a = await downloadEdition('GeoLite2-ASN', CFG.asnPath);
    const c = await downloadEdition('GeoLite2-City', CFG.cityPath);
    if (a || c || !asnReader || !cityReader) await openReaders();
  } catch (e) {
    console.warn('[NamelessUnSee] MaxMind refresh error:', e.message);
  }
}

function lookup(ip) {
  const out = { geo: null, asn: null, org: null };
  try {
    if (asnReader) {
      const a = asnReader.get(ip);
      if (a) {
        out.asn = a.autonomous_system_number || null;
        out.org = a.autonomous_system_organization || null;
      }
    }
  } catch { /* ignore */ }
  try {
    if (cityReader) {
      const c = cityReader.get(ip);
      if (c) {
        out.geo = {
          city: c.city && c.city.names && c.city.names.en,
          region: c.subdivisions && c.subdivisions[0] && c.subdivisions[0].names && c.subdivisions[0].names.en,
          country: c.country && c.country.names && c.country.names.en,
          countryCode: c.country && c.country.iso_code,
          latitude: c.location && c.location.latitude,
          longitude: c.location && c.location.longitude,
        };
      }
    }
  } catch { /* ignore */ }
  return out;
}

function status() {
  return { asn: !!asnReader, city: !!cityReader };
}

module.exports = { openReaders, refresh, lookup, status };
