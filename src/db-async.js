'use strict';

const path = require('path');
const { createClient } = require('@libsql/client');
const config = require('./config');
const { D1Client } = require('./db-d1');
const { bootstrapAsyncDatabase } = require('./db-async-bootstrap');

function normalizeParams(params) {
  if (params.length === 1 && Array.isArray(params[0])) return params[0];
  if (params.length === 1 && params[0] && typeof params[0] === 'object' && !Buffer.isBuffer(params[0])) {
    return params[0];
  }
  return params;
}

function statement(execute, sql) {
  return {
    async get(...params) {
      const result = await execute(sql, normalizeParams(params));
      return result.rows[0];
    },
    async all(...params) {
      const result = await execute(sql, normalizeParams(params));
      return result.rows;
    },
    async run(...params) {
      return execute(sql, normalizeParams(params));
    },
  };
}

function splitSql(sql) {
  return sql.split(';').map((part) => part.trim()).filter(Boolean);
}

function adaptLibsql(client) {
  const mapResult = (result) => ({
    rows: result.rows || [],
    changes: Number(result.rowsAffected || 0),
    lastInsertRowid: result.lastInsertRowid == null ? undefined : Number(result.lastInsertRowid),
  });
  const execute = async (sql, args = []) => {
    const result = await client.execute({ sql, args });
    return mapResult(result);
  };
  return {
    prepare: (sql) => statement(execute, sql),
    execute,
    async all(sql, args = []) { return (await execute(sql, args)).rows; },
    async get(sql, args = []) { return (await execute(sql, args)).rows[0]; },
    async run(sql, args = []) { return execute(sql, args); },
    async exec(sql) {
      if (!sql.trim()) return;
      await client.batch(splitSql(sql).map((part) => ({ sql: part, args: [] })), 'write');
    },
    async batch(statements) {
      const results = await client.batch(statements, 'write');
      return results.map(mapResult);
    },
    async transaction(fn) {
      const tx = await client.transaction('write');
      const txDb = adaptLibsql(tx);
      try {
        const result = await fn(txDb);
        await tx.commit();
        return result;
      } catch (error) {
        await tx.rollback();
        throw error;
      }
    },
    close() { return client.close(); },
  };
}

async function createAsyncDatabase({ backend = config.database.backend, dbPath = config.dbPath, bootstrap = true, fetchImpl, d1Config = config.database.d1 } = {}) {
  let db;
  if (backend === 'd1') {
    const d1 = new D1Client({ ...d1Config, ...(fetchImpl ? { fetchImpl } : {}) });
    db = {
      prepare: (sql) => statement((query, args) => d1.execute(query, args), sql),
      execute: (sql, args = []) => d1.execute(sql, args),
      all: async (sql, args = []) => (await d1.execute(sql, args)).rows,
      get: async (sql, args = []) => (await d1.execute(sql, args)).rows[0],
      run: (sql, args = []) => d1.execute(sql, args),
      async exec(sql) {
        await d1.batch(splitSql(sql).map((part) => ({ sql: part, params: [] })));
      },
      async batch(statements) {
        return d1.batch(statements.map(({ sql, args, params }) => ({
          sql,
          params: params === undefined ? args : params,
        })));
      },
      async transaction() {
        throw new Error('D1 REST backend does not support interactive transactions; use db.batch()');
      },
      close() {},
    };
  } else {
    const url = `file:${path.resolve(dbPath)}`;
    db = adaptLibsql(createClient({ url }));
  }
  return bootstrap ? bootstrapAsyncDatabase(db) : db;
}

module.exports = { createAsyncDatabase };
