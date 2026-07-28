'use strict';

const db = require('./db');
const { parseUserAgent, summarize } = require('./util/device');

// Headers we never store (sensitive / not useful as forensic signal).
const REDACT_HEADERS = new Set(['cookie', 'authorization', 'proxy-authorization']);

function captureHeaders(req) {
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (REDACT_HEADERS.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

const upsert = db.prepare(`
INSERT INTO access_logs
  (image_id, view_id, viewed_at, ip, ip_country, geo_json, user_agent, device_json, headers_json, client_json, link_label)
VALUES
  (@image_id, @view_id, @viewed_at, @ip, @ip_country, @geo_json, @user_agent, @device_json, @headers_json, @client_json, @link_label)
ON CONFLICT(image_id, view_id) DO UPDATE SET
  ip           = COALESCE(excluded.ip, ip),
  ip_country   = COALESCE(excluded.ip_country, ip_country),
  geo_json     = COALESCE(excluded.geo_json, geo_json),
  user_agent   = COALESCE(excluded.user_agent, user_agent),
  device_json  = COALESCE(excluded.device_json, device_json),
  headers_json = COALESCE(excluded.headers_json, headers_json),
  client_json  = COALESCE(excluded.client_json, client_json),
  link_label   = COALESCE(excluded.link_label, link_label)
`);

/**
 * Record the server-side view (render). Takes the viewer assessment produced by
 * ipintel.assess() and bakes/stores IP, geo, proxy status, device and headers.
 * Returns the identity used so the caller can render it into the watermark.
 */
function logRender(req, imageId, viewId, assessment, linkLabel = null) {
  const ua = req.headers['user-agent'] || '';
  const device = parseUserAgent(ua);
  const geoBlob = {
    ...(assessment.geo || {}),
    country: assessment.country || (assessment.geo && assessment.geo.country) || null,
    proxy: assessment.proxy || null,
  };

  upsert.run({
    image_id: imageId,
    view_id: viewId || null,
    viewed_at: Date.now(),
    ip: assessment.ip || null,
    ip_country: assessment.country || (assessment.geo && assessment.geo.countryCode) || null,
    geo_json: JSON.stringify(geoBlob),
    user_agent: ua || null,
    device_json: JSON.stringify(device),
    headers_json: JSON.stringify(captureHeaders(req)),
    client_json: null,
    link_label: linkLabel || null,
  });

  return {
    ip: assessment.ip || 'unknown',
    country: assessment.country,
    geoSummary: assessment.geoSummary,
    org: assessment.org,
    proxy: assessment.proxy,
    device,
    deviceSummary: summarize(device),
  };
}

// Refused viewers (VPN/proxy/Tor, unidentifiable connection) never get image
// bytes, so they are recorded as separate attempt rows: view_id stays NULL so
// they can never be mistaken for a served view, and blocked_reason carries the
// refusal. Repeat attempts from the same IP for the same reason within this
// window refresh the existing row instead of piling up on every refresh.
const BLOCKED_DEDUPE_MS = 10 * 60 * 1000;

const insertBlocked = db.prepare(`
INSERT INTO access_logs
  (image_id, view_id, viewed_at, ip, ip_country, geo_json, user_agent, device_json, headers_json, client_json, link_label, blocked_reason)
VALUES
  (@image_id, NULL, @viewed_at, @ip, @ip_country, @geo_json, @user_agent, @device_json, @headers_json, NULL, @link_label, @blocked_reason)
`);

const touchBlocked = db.prepare(`
UPDATE access_logs SET
  viewed_at    = @viewed_at,
  ip_country   = @ip_country,
  geo_json     = @geo_json,
  user_agent   = @user_agent,
  device_json  = @device_json,
  headers_json = @headers_json,
  link_label   = COALESCE(@link_label, link_label)
WHERE id = (
  SELECT id FROM access_logs
  WHERE image_id = @image_id AND blocked_reason = @blocked_reason
    AND ip IS @ip AND viewed_at >= @since
  ORDER BY viewed_at DESC LIMIT 1
)
`);

/**
 * Record a refused access attempt. Same shape as logRender, but the row is
 * flagged with the block reason and never counts as a delivered view.
 */
function logBlocked(req, imageId, assessment, linkLabel = null) {
  const ua = req.headers['user-agent'] || '';
  const device = parseUserAgent(ua);
  const geoBlob = {
    ...(assessment.geo || {}),
    country: assessment.country || (assessment.geo && assessment.geo.country) || null,
    proxy: assessment.proxy || null,
  };
  const row = {
    image_id: imageId,
    viewed_at: Date.now(),
    ip: assessment.ip || null,
    ip_country: assessment.country || (assessment.geo && assessment.geo.countryCode) || null,
    geo_json: JSON.stringify(geoBlob),
    user_agent: ua || null,
    device_json: JSON.stringify(device),
    headers_json: JSON.stringify(captureHeaders(req)),
    link_label: linkLabel || null,
    blocked_reason: assessment.reason || 'blocked',
  };

  if (touchBlocked.run({ ...row, since: row.viewed_at - BLOCKED_DEDUPE_MS }).changes === 0) {
    insertBlocked.run(row);
  }
}

/** Record the client-side telemetry beacon for a given view. */
function logClient(imageId, viewId, clientData) {
  upsert.run({
    image_id: imageId,
    view_id: viewId || null,
    viewed_at: Date.now(),
    ip: null,
    ip_country: null,
    geo_json: null,
    user_agent: null,
    device_json: null,
    headers_json: null,
    client_json: clientData ? JSON.stringify(clientData) : null,
    link_label: null,
  });
}

module.exports = { logRender, logBlocked, logClient, captureHeaders };
