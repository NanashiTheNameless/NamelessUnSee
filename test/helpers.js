'use strict';

// In-process HTTP client for Express tests. No socket listen needed, so this
// works in sandboxed runners that block network binds.
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { Readable } = require('stream');
const signature = require('cookie-signature');
const fs = require('fs');
const path = require('path');
const config = require('../src/config');

function newJar() {
  return new Map();
}

function applyCookies(jar, res) {
  const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of sc) {
    const pair = c.split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

function normalizeHeaders(input) {
  const out = {};
  for (const [k, v] of Object.entries(input || {})) out[k.toLowerCase()] = v;
  return out;
}

async function serializeBody(method, headers, body) {
  if (body === undefined || body === null) return { body: null, headers, parsedBody: undefined };
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const parsedBody = {};
    const fileParts = [];
    for (const [key, value] of body.entries()) {
      if (typeof value === 'string') {
        parsedBody[key] = value;
      } else if (value && typeof value.arrayBuffer === 'function') {
        const buf = Buffer.from(await value.arrayBuffer());
        const filename = crypto.randomBytes(20).toString('hex');
        const mime = value.type || 'application/octet-stream';
        const storageName = filename;
        const destination = key === 'proof' || key === 'proofs' ? config.reportDir : config.uploadDir;
        fs.writeFileSync(path.join(destination, storageName), buf);
        fileParts.push({
          fieldname: key,
          filename: storageName,
          originalname: value.name || storageName,
          mimetype: mime,
          size: buf.length,
          buffer: buf,
        });
      }
    }
    return { body: null, headers: Object.assign({}, headers, { 'content-length': '0' }), parsedBody, fileParts };
  }
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    const buf = Buffer.from(body);
    const ct = String(headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
    if (ct.includes('application/x-www-form-urlencoded')) {
      return {
        body: null,
        headers: Object.assign({}, headers, { 'content-length': '0' }),
        parsedBody: Object.fromEntries(new URLSearchParams(buf.toString('utf8'))),
      };
    }
    if (ct.includes('application/json')) {
      return {
        body: null,
        headers: Object.assign({}, headers, { 'content-length': '0' }),
        parsedBody: JSON.parse(buf.toString('utf8')),
      };
    }
    return { body: buf, headers: Object.assign({}, headers, { 'content-length': String(buf.length) }), parsedBody: undefined };
  }
  const req = new Request('http://example.test/', { method, headers, body });
  const buf = Buffer.from(await req.arrayBuffer());
  const out = normalizeHeaders(Object.fromEntries(req.headers.entries()));
  if (!out['content-length']) out['content-length'] = String(buf.length);
  return { body: buf, headers: out, parsedBody: undefined, filePart: null };
}

class TestRequest extends Readable {
  constructor({ method, url, headers, body }) {
    super();
    this.method = method;
    this.url = url;
    this.originalUrl = url;
    this.headers = headers;
    this.httpVersion = '1.1';
    this.socket = { remoteAddress: '127.0.0.1', encrypted: false };
    this.connection = this.socket;
    this._body = body;
    this._sent = false;
    this.complete = body == null;
    Object.defineProperty(this, 'readableEnded', { value: body == null, writable: true, configurable: true });
  }

  _read() {
    if (this._sent) return;
    this._sent = true;
    if (this._body) this.push(this._body);
    this.push(null);
    this.complete = true;
    this.readableEnded = true;
  }
}

class HeaderBag {
  constructor(store) {
    this.store = store;
  }

  get(name) {
    const v = this.store[name.toLowerCase()];
    if (Array.isArray(v)) return v.join(', ');
    return v ?? null;
  }

  getSetCookie() {
    const v = this.store['set-cookie'];
    if (Array.isArray(v)) return v.slice();
    return v ? [v] : [];
  }

  entries() {
    return Object.entries(this.store);
  }
}

class TestResponse {
  constructor() {
    this._ee = new EventEmitter();
    this.statusCode = 200;
    this.statusMessage = 'OK';
    this._headers = {};
    this.body = [];
    Object.defineProperty(this, 'headersSent', { value: false, writable: true, configurable: true });
    this.finished = false;
    this.locals = {};
    this.on = (event, fn) => {
      this._ee.on(event, fn);
      return this;
    };
    this.once = (event, fn) => {
      this._ee.once(event, fn);
      return this;
    };
    this.emit = (...args) => this._ee.emit(...args);
    this.setHeader = (name, value) => {
      this._headers[name.toLowerCase()] = value;
    };
    this.getHeader = (name) => this._headers[name.toLowerCase()];
    this.getHeaders = () => this._headers;
    this.removeHeader = (name) => {
      delete this._headers[name.toLowerCase()];
    };
    this.set = (name, value) => {
      if (typeof name === 'string') this.setHeader(name, value);
      else if (name && typeof name === 'object') for (const [k, v] of Object.entries(name)) this.setHeader(k, v);
      return this;
    };
    this.append = (name, value) => {
      const key = name.toLowerCase();
      const prev = this._headers[key];
      if (prev === undefined) this._headers[key] = value;
      else if (Array.isArray(prev)) this._headers[key] = prev.concat(value);
      else this._headers[key] = [prev].concat(value);
      return this;
    };
    this.status = (code) => {
      this.statusCode = code;
      return this;
    };
    this.type = (value) => {
      const v = String(value || '');
      if (v.includes('/')) this.setHeader('Content-Type', v);
      else if (v === 'json') this.setHeader('Content-Type', 'application/json; charset=utf-8');
      else if (v === 'text') this.setHeader('Content-Type', 'text/plain; charset=utf-8');
      else if (v === 'html') this.setHeader('Content-Type', 'text/html; charset=utf-8');
      else this.setHeader('Content-Type', v);
      return this;
    };
    this.location = (url) => {
      this.setHeader('Location', url);
      return this;
    };
    this.cookie = (name, value, opts = {}) => {
      const secret = process.env.COOKIE_SECRET || '';
      const rawValue = opts.signed ? `s:${signature.sign(String(value), secret)}` : String(value);
      const parts = [`${name}=${rawValue}`];
      if (opts.maxAge != null) parts.push(`Max-Age=${Math.floor(opts.maxAge / 1000)}`);
      if (opts.domain) parts.push(`Domain=${opts.domain}`);
      if (opts.path !== false) parts.push(`Path=${opts.path || '/'}`);
      if (opts.expires instanceof Date) parts.push(`Expires=${opts.expires.toUTCString()}`);
      if (opts.httpOnly !== false) parts.push('HttpOnly');
      if (opts.secure) parts.push('Secure');
      if (opts.sameSite) parts.push(`SameSite=${String(opts.sameSite).replace(/^[a-z]/, (m) => m.toUpperCase())}`);
      this.append('Set-Cookie', parts.join('; '));
      return this;
    };
    this.send = (body) => {
      if (body === undefined || body === null) return this.end();
      if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
        if (!this.getHeader('content-type')) this.type('application/octet-stream');
        return this.end(Buffer.from(body));
      }
      if (typeof body === 'object') return this.json(body);
      if (!this.getHeader('content-type')) this.type('text/html; charset=utf-8');
      return this.end(String(body));
    };
    this.json = (body) => {
      this.type('application/json; charset=utf-8');
      return this.end(JSON.stringify(body));
    };
    this.redirect = (statusOrUrl, maybeUrl) => {
      const status = typeof maybeUrl === 'string' ? statusOrUrl : 302;
      const url = typeof maybeUrl === 'string' ? maybeUrl : statusOrUrl;
      this.status(status);
      this.location(url);
      return this.end(`Found. Redirecting to ${url}`);
    };
    this.render = (view, locals = {}) => {
      const app = this.app;
      const data = Object.assign({}, this.locals, locals);
      app.render(view, data, (err, html) => {
        if (err) {
          this._ee.emit('error', err);
          return;
        }
        if (!this.getHeader('content-type')) this.type('text/html; charset=utf-8');
        this.end(html);
      });
      return this;
    };
    this.writeHead = (statusCode, headers) => {
      this.statusCode = statusCode;
      this.headersSent = true;
      if (headers) {
        if (Array.isArray(headers)) {
          for (let i = 0; i < headers.length; i += 2) this.setHeader(headers[i], headers[i + 1]);
        } else {
          for (const [k, v] of Object.entries(headers)) this.setHeader(k, v);
        }
      }
      return this;
    };
    this.write = (chunk, enc, cb) => {
      if (chunk) this.body.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc));
      this.headersSent = true;
      if (typeof cb === 'function') cb();
      return true;
    };
    this.end = (chunk, enc, cb) => {
      if (chunk) this.write(chunk, enc);
      this.finished = true;
      this.headersSent = true;
      this.emit('finish');
      if (typeof cb === 'function') cb();
      return this;
    };
  }
}

class TestFetchResponse {
  constructor(res) {
    this.status = res.statusCode;
    this.headers = new HeaderBag(res._headers);
    this._body = Buffer.concat(res.body);
  }

  async text() {
    return this._body.toString('utf8');
  }

  async json() {
    return JSON.parse(await this.text());
  }

  async arrayBuffer() {
    return this._body.buffer.slice(this._body.byteOffset, this._body.byteOffset + this._body.byteLength);
  }
}

function makeReq(app, jar) {
  if (!app || typeof app.handle !== 'function') {
    throw new TypeError('makeReq expects Express app instance');
  }
  return async function req(path, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    const headers = normalizeHeaders(Object.assign({ cookie: cookieHeader(jar), host: 'example.test' }, opts.headers || {}));
    const { body, headers: serializedHeaders, parsedBody, fileParts = [] } = await serializeBody(method, headers, opts.body);
    const finalHeaders = Object.assign(headers, serializedHeaders);
    const request = new TestRequest({ method, url: path, headers: finalHeaders, body });
    if (parsedBody !== undefined) {
      Object.defineProperty(request, 'body', { value: parsedBody, writable: false, enumerable: true, configurable: false });
      request._body = true;
    }
    if (fileParts && fileParts.length) {
      request.files = fileParts;
      request.file = fileParts[0];
    }
    const response = new TestResponse();
    response.req = request;
    response.app = app;
    response.locals = {};

    const done = new Promise((resolve, reject) => {
      request.on('error', reject);
      response.on('error', reject);
      response.on('finish', resolve);
      response.on('close', resolve);
    });

    app.handle(request, response);
    request.resume();
    await done;

    const out = new TestFetchResponse(response);
    applyCookies(jar, out);
    return out;
  };
}

function form(obj) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(obj).toString(),
  };
}

async function solveAltcha(req) {
  const c = await (await req('/altcha/challenge')).json();
  for (let n = 0; n <= c.maxnumber; n++) {
    if (crypto.createHash('sha256').update(c.salt + n).digest('hex') === c.challenge) {
      return Buffer.from(
        JSON.stringify({ algorithm: c.algorithm, challenge: c.challenge, number: n, salt: c.salt, signature: c.signature })
      ).toString('base64');
    }
  }
  throw new Error('altcha unsolved');
}

// Pass the consent gate (solve ALTCHA + agree).
async function consent(req, next = '/') {
  const sol = await solveAltcha(req);
  return req('/welcome', form({ agree: 'on', altcha: sol, next }));
}

function csrfFrom(html) {
  const m = html.match(/name="_csrf" value="([^"]+)"/);
  return m && m[1];
}

module.exports = { newJar, makeReq, form, solveAltcha, consent, csrfFrom };
