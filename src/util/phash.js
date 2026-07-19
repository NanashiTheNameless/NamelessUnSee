'use strict';

// Perceptual hashing for the self-managed image blocklist.
//
// Two hashes live behind this interface:
//   - compute():       256-bit PDQ-style hash (64 hex chars). The image is
//                      reduced to a 64x64 luminance buffer, a 16x16 block of
//                      low-frequency DCT coefficients is taken (skipping DC,
//                      as PDQ does), and each coefficient is thresholded on
//                      the median. Near-duplicates land within a small
//                      Hamming distance (PDQ convention: <= 31 of 256).
//   - computeLegacy(): 64-bit DCT pHash (16 hex chars) for compact entries.
//
// hamming() compares any two equal-length hex hashes, so the blocklist can
// hold both formats side by side- callers pick the threshold by hash length.

const sharp = require('sharp');

// --- 256-bit PDQ-style hash -------------------------------------------------
const P = 64; // luminance buffer size
const PLOW = 16; // 16x16 = 256 bits

// DCT-II basis rows 1..16 over 64 samples (PDQ skips the DC row).
const PDQ_COS = [];
for (let i = 0; i < PLOW; i++) {
  PDQ_COS[i] = new Float64Array(P);
  for (let j = 0; j < P; j++) {
    PDQ_COS[i][j] = Math.sqrt(2 / P) * Math.cos((Math.PI / 2 / P) * (i + 1) * (2 * j + 1));
  }
}

async function compute(input) {
  const raw = await sharp(input, { failOn: 'none' })
    .greyscale()
    .resize(P, P, { fit: 'fill', kernel: 'linear' })
    .raw()
    .toBuffer();

  // B = D * A * D^T  (16x64 · 64x64 · 64x16)
  const tmp = []; // 16 x 64
  for (let i = 0; i < PLOW; i++) {
    tmp[i] = new Float64Array(P);
    for (let x = 0; x < P; x++) {
      let s = 0;
      for (let y = 0; y < P; y++) s += PDQ_COS[i][y] * raw[y * P + x];
      tmp[i][x] = s;
    }
  }
  const vals = new Float64Array(PLOW * PLOW);
  for (let i = 0; i < PLOW; i++) {
    for (let j = 0; j < PLOW; j++) {
      let s = 0;
      for (let x = 0; x < P; x++) s += tmp[i][x] * PDQ_COS[j][x];
      vals[i * PLOW + j] = s;
    }
  }

  const median = medianOf(vals);
  let hex = '';
  for (let i = 0; i < vals.length; i += 4) {
    let nib = 0;
    for (let b = 0; b < 4; b++) if (vals[i + b] > median) nib |= 1 << (3 - b);
    hex += nib.toString(16);
  }
  return hex;
}

function medianOf(arr) {
  const sorted = Array.from(arr).sort((a, b) => a - b);
  const mid = sorted.length / 2;
  return (sorted[mid - 1] + sorted[mid]) / 2;
}

// --- 64-bit DCT pHash --------------------------------------------------------
const N = 32; // DCT input size
const LOW = 8; // low-frequency block kept for the hash (8x8 = 64 bits)

const COS = [];
for (let u = 0; u < N; u++) {
  COS[u] = new Float64Array(N);
  const c = u === 0 ? Math.sqrt(1 / N) : Math.sqrt(2 / N);
  for (let x = 0; x < N; x++) COS[u][x] = c * Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N));
}

function dct2d(m) {
  const tmp = [];
  for (let y = 0; y < N; y++) {
    tmp[y] = new Float64Array(N);
    for (let u = 0; u < N; u++) {
      let s = 0;
      for (let x = 0; x < N; x++) s += m[y][x] * COS[u][x];
      tmp[y][u] = s;
    }
  }
  const out = [];
  for (let u = 0; u < N; u++) {
    out[u] = new Float64Array(N);
    for (let v = 0; v < N; v++) {
      let s = 0;
      for (let y = 0; y < N; y++) s += tmp[y][v] * COS[u][y];
      out[u][v] = s;
    }
  }
  return out;
}

async function computeLegacy(input) {
  const raw = await sharp(input, { failOn: 'none' })
    .greyscale()
    .resize(N, N, { fit: 'fill' })
    .raw()
    .toBuffer();

  const m = [];
  for (let y = 0; y < N; y++) {
    m[y] = new Float64Array(N);
    for (let x = 0; x < N; x++) m[y][x] = raw[y * N + x];
  }

  const d = dct2d(m);
  const vals = [];
  for (let u = 0; u < LOW; u++) for (let v = 0; v < LOW; v++) vals.push(d[u][v]);

  // Threshold on the median of the low-frequency coefficients (excluding DC).
  const sorted = vals.slice(1).sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];

  let hex = '';
  for (let i = 0; i < 64; i += 4) {
    let nib = 0;
    for (let b = 0; b < 4; b++) if (vals[i + b] > median) nib |= 1 << (3 - b);
    hex += nib.toString(16);
  }
  return hex;
}

// Hamming distance between two hex hashes of equal length.
function hamming(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return Infinity;
  let dist = 0;
  for (let i = 0; i < a.length; i++) {
    let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (x) {
      dist += x & 1;
      x >>= 1;
    }
  }
  return dist;
}

module.exports = { compute, computeLegacy, hamming };
