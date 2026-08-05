'use strict';

const { getDatabase } = require('./db-runtime');
const { parseUserAgent, summarize } = require('./util/device');

const REDACT_HEADERS = new Set(['cookie', 'authorization', 'proxy-authorization']);
const BLOCKED_DEDUPE_MS = 10 * 60 * 1000;
const BLOCKED_LOG_KEEP = 200;

function captureHeaders(req) {
  const out = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (!REDACT_HEADERS.has(key.toLowerCase())) out[key] = value;
  }
  return out;
}

async function logRender(req, imageId, viewId, assessment, linkLabel = null) {
  const ua = req.headers['user-agent'] || '';
  const device = parseUserAgent(ua);
  const geoBlob = {
    ...(assessment.geo || {}),
    country: assessment.country || (assessment.geo && assessment.geo.country) || null,
    proxy: assessment.proxy || null,
  };
  await (await getDatabase()).run(
    `INSERT INTO access_logs
      (image_id, view_id, viewed_at, ip, ip_country, geo_json, user_agent, device_json, headers_json, client_json, link_label)
     VALUES (@image_id, @view_id, @viewed_at, @ip, @ip_country, @geo_json, @user_agent, @device_json, @headers_json, @client_json, @link_label)
     ON CONFLICT(image_id, view_id) DO UPDATE SET
       ip = COALESCE(excluded.ip, ip), ip_country = COALESCE(excluded.ip_country, ip_country),
       geo_json = COALESCE(excluded.geo_json, geo_json), user_agent = COALESCE(excluded.user_agent, user_agent),
       device_json = COALESCE(excluded.device_json, device_json), headers_json = COALESCE(excluded.headers_json, headers_json),
       client_json = COALESCE(excluded.client_json, client_json), link_label = COALESCE(excluded.link_label, link_label)`,
    { image_id: imageId, view_id: viewId || null, viewed_at: Date.now(), ip: assessment.ip || null,
      ip_country: assessment.country || (assessment.geo && assessment.geo.countryCode) || null,
      geo_json: JSON.stringify(geoBlob), user_agent: ua || null, device_json: JSON.stringify(device),
      headers_json: JSON.stringify(captureHeaders(req)), client_json: null, link_label: linkLabel || null }
  );
  return { ip: assessment.ip || 'unknown', country: assessment.country, geoSummary: assessment.geoSummary,
    org: assessment.org, proxy: assessment.proxy, device, deviceSummary: summarize(device) };
}

async function logBlocked(req, imageId, assessment, linkLabel = null, { withHeaders = true, client = null } = {}) {
  const ua = req.headers['user-agent'] || '';
  const device = parseUserAgent(ua);
  const geoBlob = { ...(assessment.geo || {}), country: assessment.country || (assessment.geo && assessment.geo.country) || null, proxy: assessment.proxy || null };
  const row = { image_id: imageId, viewed_at: Date.now(), ip: assessment.ip || null,
    ip_country: assessment.country || (assessment.geo && assessment.geo.countryCode) || null,
    geo_json: JSON.stringify(geoBlob), user_agent: ua || null, device_json: JSON.stringify(device),
    headers_json: withHeaders ? JSON.stringify(captureHeaders(req)) : null,
    client_json: client ? JSON.stringify(client) : null, link_label: linkLabel || null,
    blocked_reason: assessment.reason || 'blocked' };
  const db = await getDatabase();
  const existing = await db.get(
    `SELECT id FROM access_logs WHERE image_id = @image_id AND blocked_reason = @blocked_reason
     AND ip IS @ip AND viewed_at >= @since ORDER BY viewed_at DESC LIMIT 1`,
    { ...row, since: row.viewed_at - BLOCKED_DEDUPE_MS }
  );
  if (existing) {
    await db.run(`UPDATE access_logs SET viewed_at=@viewed_at, ip_country=@ip_country, geo_json=@geo_json,
      user_agent=@user_agent, device_json=COALESCE(@device_json, device_json), headers_json=COALESCE(@headers_json, headers_json),
      client_json=COALESCE(@client_json, client_json), attempts=attempts+@attempt_delta,
      link_label=COALESCE(@link_label, link_label) WHERE id=@id`, { ...row, id: existing.id, attempt_delta: client ? 0 : 1 });
    return existing.id;
  }
  const result = await db.get(`INSERT INTO access_logs
    (image_id, view_id, viewed_at, ip, ip_country, geo_json, user_agent, device_json, headers_json, client_json, link_label, blocked_reason, attempts)
    VALUES (@image_id, NULL, @viewed_at, @ip, @ip_country, @geo_json, @user_agent, @device_json, @headers_json, @client_json, @link_label, @blocked_reason, 1)
    RETURNING id`, row);
  return result && result.id;
}

async function pruneBlockedLogs(keep = BLOCKED_LOG_KEEP) {
  const db = await getDatabase();
  let removed = 0;
  for (const row of await db.all(`SELECT image_id, COUNT(*) AS n FROM access_logs WHERE blocked_reason IS NOT NULL GROUP BY image_id HAVING n > ?`, [keep])) {
    removed += (await db.run(`DELETE FROM access_logs WHERE blocked_reason IS NOT NULL AND image_id=@image_id AND id NOT IN
      (SELECT id FROM access_logs WHERE blocked_reason IS NOT NULL AND image_id=@image_id ORDER BY viewed_at DESC, id DESC LIMIT @keep)`, { image_id: row.image_id, keep })).changes;
  }
  return removed;
}

async function logClient(imageId, viewId, clientData) {
  await (await getDatabase()).run(`INSERT INTO access_logs
    (image_id, view_id, viewed_at, ip, ip_country, geo_json, user_agent, device_json, headers_json, client_json, link_label)
    VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL)
    ON CONFLICT(image_id, view_id) DO UPDATE SET client_json=COALESCE(excluded.client_json, client_json)`,
    [imageId, viewId || null, Date.now(), clientData ? JSON.stringify(clientData) : null]);
}

module.exports = { logRender, logBlocked, logClient, pruneBlockedLogs, captureHeaders, BLOCKED_LOG_KEEP };
