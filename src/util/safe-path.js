'use strict';

const path = require('path');

// Resolve a filename only beneath an application-owned directory. Callers must
// pass a relative filename; absolute paths and traversal are rejected.
function beneath(root, name) {
  if (typeof name !== 'string' || !name || path.isAbsolute(name)) throw new Error('invalid storage path');
  const base = path.resolve(root);
  const resolved = path.resolve(base, name);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) throw new Error('invalid storage path');
  return resolved;
}

module.exports = { beneath };
