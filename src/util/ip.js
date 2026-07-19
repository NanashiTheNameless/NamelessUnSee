'use strict';

// Parse an IPv4/IPv6 string into { version, value (BigInt) } or null.
// IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as IPv4.
function parseIp(ip) {
  if (typeof ip !== 'string') return null;
  ip = ip.trim();
  const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) ip = mapped[1];

  if (ip.indexOf(':') === -1) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let v = 0n;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return null;
      const n = Number(p);
      if (n > 255) return null;
      v = (v << 8n) | BigInt(n);
    }
    return { version: 4, value: v };
  }

  // IPv6
  let head = ip;
  let tailV4 = null;
  const v4tail = ip.match(/(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4tail) {
    const p = parseIp(v4tail[2]);
    if (!p) return null;
    tailV4 = p.value;
    head = v4tail[1].replace(/:$/, '') + '::TAIL'; // placeholder split below
    head = v4tail[1]; // keep the leading part incl trailing ':'
  }

  const dbl = head.split('::');
  if (dbl.length > 2) return null;
  const toGroups = (s) => (s ? s.split(':').filter((x) => x !== '') : []);
  let left = toGroups(dbl[0]);
  let right = dbl.length === 2 ? toGroups(dbl[1]) : null;

  let groups;
  if (right === null) {
    groups = left;
  } else {
    const have = left.length + right.length + (tailV4 !== null ? 2 : 0);
    const missing = 8 - have;
    if (missing < 0) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  }
  // Append the two 16-bit words from an embedded IPv4 tail.
  if (tailV4 !== null) {
    groups.push(((tailV4 >> 16n) & 0xffffn).toString(16));
    groups.push((tailV4 & 0xffffn).toString(16));
  }
  if (groups.length !== 8) return null;

  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return { version: 6, value: v };
}

// Canonical string for set membership (exact-IP lists like Tor).
function normalizeIp(ip) {
  const p = parseIp(ip);
  if (!p) return null;
  if (p.version === 4) {
    const v = p.value;
    return [24n, 16n, 8n, 0n].map((s) => ((v >> s) & 0xffn).toString()).join('.');
  }
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(((p.value >> BigInt(i * 16)) & 0xffffn).toString(16));
  return groups.join(':');
}

// A set of CIDR ranges for one address family, with binary-search lookup.
class RangeSet {
  constructor() {
    this.ranges = []; // [start, end] BigInt, sorted & merged after finalize()
    this._final = false;
  }
  addCidr(cidr) {
    const slash = cidr.indexOf('/');
    if (slash === -1) {
      const p = parseIp(cidr);
      if (p) this.ranges.push([p.value, p.value]);
      return;
    }
    const ipStr = cidr.slice(0, slash);
    const prefix = Number(cidr.slice(slash + 1));
    const p = parseIp(ipStr);
    if (!p || !Number.isInteger(prefix)) return;
    const bits = p.version === 4 ? 32 : 128;
    if (prefix < 0 || prefix > bits) return;
    const hostBits = BigInt(bits - prefix);
    const mask = hostBits === 0n ? 0n : (1n << hostBits) - 1n;
    const start = p.value & ~mask & ((1n << BigInt(bits)) - 1n);
    const end = start | mask;
    this.ranges.push([start, end]);
  }
  finalize() {
    this.ranges.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    // merge overlaps
    const merged = [];
    for (const r of this.ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1n) {
        if (r[1] > last[1]) last[1] = r[1];
      } else merged.push([r[0], r[1]]);
    }
    this.ranges = merged;
    this._final = true;
    return this;
  }
  get size() {
    return this.ranges.length;
  }
  contains(value) {
    const a = this.ranges;
    let lo = 0;
    let hi = a.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (value < a[mid][0]) hi = mid - 1;
      else if (value > a[mid][1]) lo = mid + 1;
      else return true;
    }
    return false;
  }
}

module.exports = { parseIp, normalizeIp, RangeSet };
