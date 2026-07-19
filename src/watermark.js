'use strict';

const sharp = require('sharp');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

function escapeXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Build a full-image SVG overlay: a repeating diagonal tile of the viewer's
// identity across the whole picture, plus a legible footer banner. The tile
// makes the mark hard to crop out; the banner makes it human-readable.
function buildOverlaySvg(width, height, lines, footerLines) {
  const fontSize = Math.max(12, Math.round(Math.min(width, height) / 68));
  const tileLineHeight = Math.round(fontSize * 1.35);
  const longestLine = lines.reduce((max, line) => Math.max(max, String(line).length), 0);
  const markWidth = Math.max(260, Math.round(longestLine * fontSize * 0.52));
  const markXStep = Math.round(markWidth * 1.10);
  const markYStep = Math.max(170, lines.length * tileLineHeight + 48);
  const bannerFont = Math.max(12, Math.round(Math.min(width, height) / 42));
  const lineHeight = bannerFont + 6;
  const bannerPad = 12;
  const bannerHeight = bannerPad * 2 + footerLines.length * lineHeight;
  const bannerTop = Math.max(0, height - bannerHeight);

  const tileLines = lines.map((line, i) =>
    `<tspan x="0" dy="${i === 0 ? 0 : tileLineHeight}" ` +
    `font-size="${fontSize}" font-weight="bold">${escapeXml(line)}</tspan>`
  ).join('');

  const marks = [];
  for (let y = -height; y <= height * 2; y += markYStep) {
    for (let x = -width; x <= width * 2; x += markXStep) {
      marks.push(`<g transform="translate(${x} ${y}) rotate(-30)"><text x="0" y="${Math.round(fontSize * 1.1)}" text-anchor="middle" ` +
        `font-family="'0xProto', monospace" fill="#ffffff" fill-opacity="0.40" ` +
        `stroke="#000000" stroke-opacity="0.58" stroke-width="1.35" ` +
        `paint-order="stroke fill">${tileLines}</text></g>`);
    }
  }

  const bannerLines = footerLines.map((line, i) =>
    `<text x="${Math.round(width / 2)}" y="${bannerTop + bannerPad + (i + 1) * lineHeight - 5}" text-anchor="middle" ` +
    `font-family="'0xProto', monospace" font-size="${bannerFont}" fill="#ffffff" ` +
    `font-weight="bold">${escapeXml(line)}</text>`
  ).join('');

  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  ${marks.join('')}
  <rect x="0" y="${bannerTop}" width="${width}" height="${bannerHeight}"
        fill="#000000" fill-opacity="0.34"/>
  <rect x="0" y="${bannerTop}" width="${width}" height="1"
        fill="#ffffff" fill-opacity="0.10"/>
  ${bannerLines}
</svg>`,
    'utf8'
  );
}

function runFfmpeg(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('ffmpeg', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolve() : reject(new Error(stderr.slice(-1000))));
  });
}

/**
 * Render a watermarked copy of an original image for a specific viewer.
 * The original bytes are never returned- only this composited output is.
 *
 * @param {string} originalPath absolute path to the stored original
 * @param {string[]} lines watermark text lines (viewer identity)
 * @returns {Promise<Buffer>} PNG buffer
 */
async function renderWatermarked(originalPath, lines, footerLines = lines) {
  const base = sharp(originalPath, { failOn: 'none' }).rotate(); // honour EXIF orientation
  const meta = await base.metadata();
  const width = meta.width || 1200;
  const height = meta.height || 800;

  const overlay = buildOverlaySvg(width, height, lines, footerLines);

  return base
    .composite([{ input: overlay, top: 0, left: 0 }])
    .png({ compressionLevel: 9 })
    .toBuffer();
}

async function probe(originalPath) {
  try {
    const meta = await sharp(originalPath, { failOn: 'none' }).metadata();
    return { width: meta.width || null, height: meta.height || null, format: meta.format || null, mediaType: 'image' };
  } catch {
    const output = await new Promise((resolve, reject) => {
      const child = spawn('ffprobe', ['-v', 'error', '-select_streams', 'v:0', '-show_entries', 'stream=width,height,codec_name', '-of', 'json', originalPath], { stdio: ['ignore', 'pipe', 'pipe'] });
      let data = '';
      child.stdout.on('data', (chunk) => { data += chunk.toString(); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve(data) : reject(new Error('not a video')));
    });
    const stream = JSON.parse(output).streams && JSON.parse(output).streams[0];
    if (!stream || !stream.width || !stream.height) throw new Error('invalid video');
    return { width: stream.width, height: stream.height, format: stream.codec_name || 'video', mediaType: 'video' };
  }
}

async function renderWatermarkedVideo(originalPath, outputPath, width, height, lines, footerLines) {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'nus-video-'));
  const overlayPath = path.join(tempDir, 'overlay.png');
  try {
    await sharp(buildOverlaySvg(width, height, lines, footerLines)).png().toFile(overlayPath);
    await runFfmpeg([
      '-y', '-i', originalPath, '-loop', '1', '-i', overlayPath,
      '-filter_complex', '[0:v][1:v]overlay=0:0:shortest=1:format=auto[v]',
      '-map', '[v]', '-map', '0:a?', '-c:v', 'libx264', '-preset', 'veryfast',
      '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-movflags', '+faststart', outputPath,
    ]);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
  return outputPath;
}

async function transcodeVideo(originalPath, outputPath) {
  await runFfmpeg([
    '-y', '-i', originalPath,
    '-map', '0:v:0', '-map', '0:a?',
    '-c:v', 'libx264', '-preset', 'veryfast', '-pix_fmt', 'yuv420p',
    '-c:a', 'aac', '-movflags', '+faststart', outputPath,
  ]);
  return outputPath;
}

module.exports = { renderWatermarked, renderWatermarkedVideo, transcodeVideo, probe, buildOverlaySvg };
