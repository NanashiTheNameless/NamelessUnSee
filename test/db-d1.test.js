'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { D1Client } = require('../src/db-d1');
const { createAsyncDatabase } = require('../src/db-async');

test('D1 client sends bound parameters and maps query rows', async () => {
  let request;
  const client = new D1Client({
    accountId: 'account',
    databaseId: 'database',
    apiToken: 'token',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify({
        success: true,
        result: [{ success: true, results: [{ id: 'u1' }], meta: { changes: 0 } }],
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });

  const result = await client.execute('SELECT * FROM users WHERE id = ?', ['u1']);
  assert.deepEqual(result.rows, [{ id: 'u1' }]);
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.authorization, 'Bearer token');
  assert.deepEqual(JSON.parse(request.options.body), {
    sql: 'SELECT * FROM users WHERE id = ?',
    params: ['u1'],
  });
});

test('D1 client maps batch metadata', async () => {
  const client = new D1Client({
    accountId: 'account',
    databaseId: 'database',
    apiToken: 'token',
    fetchImpl: async () => new Response(JSON.stringify({
      success: true,
      result: [{ success: true, results: [], meta: { changes: 1, last_row_id: 7 } }],
    }), { status: 200 }),
  });

  const result = await client.batch([{ sql: 'INSERT INTO users (id) VALUES (?)', params: ['u1'] }]);
  assert.equal(result[0].changes, 1);
  assert.equal(result[0].lastInsertRowid, 7);
});

test('D1 client converts named parameters to positional bindings', async () => {
  let body;
  const client = new D1Client({
    accountId: 'account',
    databaseId: 'database',
    apiToken: 'token',
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return new Response(JSON.stringify({ success: true, result: [{ success: true, results: [] }] }), { status: 200 });
    },
  });

  await client.execute('INSERT INTO users (id, email) VALUES (@id, $email)', {
    id: 'u1',
    email: 'a@example.invalid',
  });
  assert.deepEqual(body, {
    sql: 'INSERT INTO users (id, email) VALUES (?, ?)',
    params: ['u1', 'a@example.invalid'],
  });
});

test('async database facade routes D1 queries through the configured REST client', async () => {
  let body;
  const db = await createAsyncDatabase({
    backend: 'd1',
    bootstrap: false,
    d1Config: { accountId: 'a', databaseId: 'd', apiToken: 't' },
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return new Response(JSON.stringify({ success: true, result: [{ success: true, results: [{ n: 1 }], meta: {} }] }), { status: 200 });
    },
  });
  assert.deepEqual(await db.prepare('SELECT @value AS n').get({ value: 1 }), { n: 1 });
  assert.equal(body.sql, 'SELECT ? AS n');
  assert.deepEqual(body.params, [1]);
});

test('async local backend supports prepared statements and transactions', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'namelessunsee-db-'));
  const db = await createAsyncDatabase({ backend: 'sqlite', dbPath: path.join(dir, 'test.sqlite'), bootstrap: false });
  await db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL)');
  const insert = db.prepare('INSERT INTO users (username) VALUES (?)');
  await insert.run('alice');
  await db.transaction(async (tx) => {
    await tx.prepare('INSERT INTO users (username) VALUES (?)').run('bob');
  });
  assert.deepEqual(await db.prepare('SELECT username FROM users ORDER BY id').all(), [
    { username: 'alice' },
    { username: 'bob' },
  ]);
  await db.close();
  await fs.rm(dir, { recursive: true, force: true });
});

test('async bootstrap creates the application schema', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'namelessunsee-schema-'));
  const db = await createAsyncDatabase({ backend: 'sqlite', dbPath: path.join(dir, 'app.sqlite') });
  assert.deepEqual(await db.get("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'"), { name: 'users' });
  assert.deepEqual(await db.get('PRAGMA table_info(images)', []), { cid: 0, name: 'id', type: 'INTEGER', notnull: 0, dflt_value: null, pk: 1 });
  await db.close();
  await fs.rm(dir, { recursive: true, force: true });
});
