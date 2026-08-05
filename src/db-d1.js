'use strict';

// Cloudflare D1 REST API client.
//
// D1 is exposed through Cloudflare's API when this application runs outside
// Workers. This module deliberately has no dependency on the Workers runtime;
// Node's native fetch is sufficient.

const API_ROOT = 'https://api.cloudflare.com/client/v4';

function required(name, value) {
  if (!value) throw new Error(`[D1] missing ${name}`);
  return value;
}

function rowsFromResult(result) {
  const first = Array.isArray(result) ? result[0] : result;
  if (!first || first.success === false) {
    const message = first && first.error ? first.error : 'D1 query failed';
    throw new Error(`[D1] ${message}`);
  }
  return first;
}

function positional(sql, params) {
  if (Array.isArray(params) || params == null || typeof params !== 'object') {
    return { sql, params: params == null ? [] : params };
  }
  const values = [];
  const rewritten = sql.replace(/([:@$])([A-Za-z_][A-Za-z0-9_]*)/g, (token, prefix, name) => {
    if (!Object.prototype.hasOwnProperty.call(params, name) &&
        !Object.prototype.hasOwnProperty.call(params, token)) return token;
    values.push(Object.prototype.hasOwnProperty.call(params, name) ? params[name] : params[token]);
    return '?';
  });
  return { sql: rewritten, params: values };
}

class D1Client {
  constructor({ accountId, databaseId, apiToken, fetchImpl = fetch }) {
    if (!accountId || !databaseId || !apiToken) {
      throw new Error('Cloudflare D1 requires CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_D1_DATABASE_ID, and CLOUDFLARE_API_TOKEN');
    }
    this.accountId = required('CLOUDFLARE_ACCOUNT_ID', accountId);
    this.databaseId = required('CLOUDFLARE_D1_DATABASE_ID', databaseId);
    this.apiToken = required('CLOUDFLARE_API_TOKEN', apiToken);
    this.fetch = fetchImpl;
    this.url = `${API_ROOT}/accounts/${encodeURIComponent(this.accountId)}/d1/database/${encodeURIComponent(this.databaseId)}/query`;
  }

  async request(body) {
    const response = await this.fetch(this.url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.apiToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error(`[D1] Cloudflare returned HTTP ${response.status} with invalid JSON`);
    }
    if (!response.ok || payload.success === false) {
      const error = payload.errors && payload.errors[0];
      throw new Error(`[D1] ${error ? error.message : `Cloudflare returned HTTP ${response.status}`}`);
    }
    return payload.result;
  }

  async execute(sql, params = []) {
    const bound = positional(sql, params);
    const result = rowsFromResult(await this.request(bound));
    return {
      rows: result.results || [],
      changes: Number(result.meta && result.meta.changes || 0),
      lastInsertRowid: result.meta && result.meta.last_row_id != null
        ? Number(result.meta.last_row_id)
        : undefined,
    };
  }

  async batch(statements) {
    if (!Array.isArray(statements) || !statements.length) return [];
    const result = await this.request({
      batch: statements.map(({ sql, params = [] }) => positional(sql, params)),
    });
    return result.map((entry) => ({
      rows: entry.results || [],
      changes: Number(entry.meta && entry.meta.changes || 0),
      lastInsertRowid: entry.meta && entry.meta.last_row_id != null
        ? Number(entry.meta.last_row_id)
        : undefined,
    }));
  }
}

module.exports = { D1Client };
