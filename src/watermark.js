'use strict';

const sharp = require('sharp');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const config = require('./config');

// ffmpeg grabs every core it can see and each video view is a full re-encode,
// so concurrent viewers otherwise pin the whole host. Two limits apply: how
// many threads one encode may use, and how many encodes run at once. Work over
// the limit queues rather than competing for the same CPUs.
let activeEncodes = 0;
const encodeQueue = [];

function acquireEncodeSlot() {
  if (activeEncodes < config.ffmpeg.maxConcurrent) {
    activeEncodes += 1;
    return Promise.resolve();
  }
  return new Promise((resolve) => encodeQueue.push(resolve));
}

function releaseEncodeSlot() {
  const next = encodeQueue.shift();
  if (next) {
    next(); // hand the slot straight over; activeEncodes stays as it is
    return;
  }
  activeEncodes -= 1;
}

function escapeXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Geometry shared by the tile and the banner, so both stay in step.
function overlayMetrics(width, height, lines, footerLines) {
  const fontSize = Math.max(12, Math.round(Math.min(width, height) / 68));
  const tileLineHeight = Math.round(fontSize * 1.35);
  const longestLine = lines.reduce((max, line) => Math.max(max, String(line).length), 0);
  const markWidth = Math.max(260, Math.round(longestLine * fontSize * 0.52));
  const bannerFont = Math.max(12, Math.round(Math.min(width, height) / 42));
  const lineHeight = bannerFont + 6;
  const bannerPad = 12;
  const bannerHeight = Math.max(1, Math.min(height, bannerPad * 2 + footerLines.length * lineHeight));
  return {
    fontSize,
    tileLineHeight,
    markWidth,
    // Grid step between repetitions- the original spacing. The mark itself is
    // drawn larger than this and is allowed to overlap its neighbours, which is
    // what keeps the identity text from being trimmed.
    stepX: Math.max(1, Math.round(markWidth * config.watermark.tileSpacing)),
    stepY: Math.max(1, Math.max(
      Math.round(170 * config.watermark.tileSpacing),
      lines.length * tileLineHeight + config.watermark.tilePadding
    )),
    bannerFont,
    lineHeight,
    bannerPad,
    bannerHeight: Math.max(1, Math.min(height, bannerHeight)),
    bannerTop: Math.max(0, height - Math.min(height, bannerHeight)),
  };
}

/**
 * One repetition of the diagonal identity mark, on a canvas large enough to
 * hold it whole.
 *
 * The canvas is sized to the mark's *rotated* bounding box, which is wider than
 * the grid step it will be repeated on. That is deliberate: the original
 * overlay drew every mark as a free-standing element, so neighbours overlapped
 * and nothing was ever cut off. Sizing this to the step instead would clip each
 * copy at its own edge, trimming the identity text mid-string.
 */
function buildMarkSvg(width, height, lines) {
  const m = overlayMetrics(width, height, lines, lines);
  // Generous on purpose. Character-count estimates understate the real advance
  // width of a monospace face, which is what cropped the ends off the longest
  // line ("Ref ..." losing its R and its trailing label). The canvas only needs
  // to be big enough; the exact ink bounds are measured afterwards, so erring
  // high here costs nothing but transparent margin.
  const longestLine = lines.reduce((max, line) => Math.max(max, String(line).length), 0);
  const blockWidth = Math.max(m.markWidth, Math.ceil(longestLine * m.fontSize * 0.9)) + 32;
  const blockHeight = lines.length * m.tileLineHeight + 32;
  const rad = Math.PI / 6; // -30 degrees grows the footprint on both axes
  const boxWidth = Math.ceil(blockWidth * Math.cos(rad) + blockHeight * Math.sin(rad));
  const boxHeight = Math.ceil(blockWidth * Math.sin(rad) + blockHeight * Math.cos(rad));

  const tileLines = lines.map((line, i) =>
    `<tspan x="0" dy="${i === 0 ? 0 : m.tileLineHeight}" ` +
    `font-size="${m.fontSize}" font-weight="bold">${escapeXml(line)}</tspan>`
  ).join('');

  return {
    width: boxWidth,
    height: boxHeight,
    svg: Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${boxWidth}" height="${boxHeight}">` +
      `<g transform="translate(${Math.round(boxWidth / 2)} ${Math.round((boxHeight - blockHeight) / 2)}) rotate(-30)">` +
      `<text x="0" y="${Math.round(m.fontSize * 1.1)}" text-anchor="middle" ` +
      `font-family="'0xProto', monospace" fill="#ffffff" fill-opacity="0.40" ` +
      `stroke="#000000" stroke-opacity="0.58" stroke-width="1.35" ` +
      `paint-order="stroke fill">${tileLines}</text></g></svg>`,
      'utf8'
    ),
  };
}

/**
 * Rasterise one mark and crop to the ink it actually produced.
 *
 * Measuring beats estimating: glyph metrics depend on the font that is really
 * installed, and any shortfall in a predicted width shows up as text sliced off
 * mid-string. Trimming the transparent margin gives the true bounding box, so
 * the stamp is exactly as large as the mark needs and never smaller.
 */
async function buildMarkStamp(width, height, lines) {
  const mark = buildMarkSvg(width, height, lines);
  const rendered = await sharp(mark.svg).png().toBuffer();
  try {
    const { data, info } = await sharp(rendered)
      .trim({ background: { r: 0, g: 0, b: 0, alpha: 0 }, threshold: 0 })
      .png()
      .toBuffer({ resolveWithObject: true });
    return { buffer: data, width: info.width, height: info.height };
  } catch {
    // Nothing to trim (or an all-transparent render): use it as drawn.
    return { buffer: rendered, width: mark.width, height: mark.height };
  }
}

/**
 * The tiled mark layer: the mark rasterised once, then composited at every grid
 * position. Repeating a bitmap costs almost nothing next to laying out text, so
 * this keeps the original overlapping-and-unclipped look at the speed of the
 * tiled one. Marks are laid out on an oversized canvas and the centre cropped
 * out, which is how copies are allowed to hang off the edges as they used to.
 */
async function buildMarkPeriod(width, height, lines) {
  const m = overlayMetrics(width, height, lines, lines);
  const mark = await buildMarkStamp(width, height, lines);

  // One period of the pattern. Alternate columns are offset vertically, so the
  // layout repeats every two columns across and every row step down. Clamped to
  // the image, because sharp refuses a composite larger than its base and a
  // period wider than the picture would never repeat anyway.
  const periodW = Math.max(1, Math.min(width, m.stepX * 2));
  const periodH = Math.max(1, Math.min(height, m.stepY));

  // Draw that period on a canvas padded by a whole mark on each side, then cut
  // the period back out of the middle. Marks that overhang an edge therefore
  // reappear on the opposite side, which makes the result tile seamlessly- no
  // mark is ever cut off, and neighbours still overlap.
  const padX = mark.width;
  const padY = mark.height;
  const canvasWidth = periodW + padX * 2;
  const canvasHeight = periodH + padY * 2;

  const offset = Math.round(m.stepY * config.watermark.stagger);
  const marks = [];
  // Column parity has to follow the absolute grid, not this canvas, or the
  // stagger would flip at every tile boundary.
  const firstColumn = -Math.ceil(padX / m.stepX);
  for (let c = firstColumn; c * m.stepX <= periodW + padX; c += 1) {
    const x = c * m.stepX + padX;
    const shift = Math.abs(c % 2) === 0 ? 0 : offset;
    for (let y = shift - padY; y <= periodH + padY; y += m.stepY) {
      const left = Math.round(x);
      const top = Math.round(y + padY);
      if (left < 0 || top < 0) continue;
      if (left + mark.width > canvasWidth || top + mark.height > canvasHeight) continue;
      marks.push({ input: mark.buffer, top, left });
    }
  }

  // Raw pixels between the passes: encoding this intermediate as PNG and
  // decoding it straight back dominated the whole render.
  const painted = await sharp({ create: { width: canvasWidth, height: canvasHeight, channels: 4, background: { r: 0, g: 0, b: 0, alpha: 0 } } })
    .composite(marks)
    .raw()
    .toBuffer();

  // sharp orders extract before composite inside one pipeline, so the crop has
  // to happen on a fresh instance.
  const period = await sharp(painted, { raw: { width: canvasWidth, height: canvasHeight, channels: 4 } })
    .extract({ left: padX, top: padY, width: Math.min(periodW, canvasWidth - padX * 2), height: Math.min(periodH, canvasHeight - padY * 2) })
    .png()
    .toBuffer();

  // Returned as the small repeating tile. Painting it out to a full-size layer
  // first and compositing that was ~2.8 s of wasted work at 4000x3000: sharp can
  // tile it straight onto the image in one pass.
  return period;
}

/** The legible footer banner, full width, rasterised once. */
function buildBannerSvg(width, height, footerLines) {
  const m = overlayMetrics(width, height, footerLines, footerLines);
  const bannerLines = footerLines.map((line, i) =>
    `<text x="${Math.round(width / 2)}" y="${m.bannerPad + (i + 1) * m.lineHeight - 5}" text-anchor="middle" ` +
    `font-family="'0xProto', monospace" font-size="${m.bannerFont}" fill="#ffffff" ` +
    `font-weight="bold">${escapeXml(line)}</text>`
  ).join('');
  return {
    top: m.bannerTop,
    height: m.bannerHeight,
    svg: Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${m.bannerHeight}">` +
      `<rect x="0" y="0" width="${width}" height="${m.bannerHeight}" fill="#000000" fill-opacity="0.34"/>` +
      `<rect x="0" y="0" width="${width}" height="1" fill="#ffffff" fill-opacity="0.10"/>` +
      `${bannerLines}</svg>`,
      'utf8'
    ),
  };
}

/**
 * Compose the full-size overlay as a bitmap: one rasterised mark tiled across a
 * transparent canvas, with the banner composited over it.
 */
async function buildOverlayBitmap(width, height, lines, footerLines) {
  const period = await buildMarkPeriod(width, height, lines);
  const banner = buildBannerSvg(width, height, footerLines);
  // ffmpeg needs a real file, so this one does encode to PNG.
  return sharp({ create: { width, height, channels: 4, background: { r: 0, g: 0, b: 0, alpha: 0 } } })
    .composite([
      { input: period, tile: true },
      { input: banner.svg, top: banner.top, left: 0 },
    ])
    .png({ compressionLevel: 6 })
    .toBuffer();
}

// Retained for callers that want the whole overlay as a single SVG. This is the
// slow path- see buildMarkSvg for why- and is no longer used for rendering.
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

// --- hardware encoding ------------------------------------------------------
// Moving the H.264 encode onto the GPU is the only thing that removes the CPU
// floor rather than merely capping it. Which API is available depends entirely
// on the host, so nothing here assumes one: a per-platform candidate list is
// probed at startup by actually encoding a throwaway clip. Being listed by
// ffmpeg is not proof an encoder works- drivers are frequently present but
// non-functional- so only a successful encode counts. Anything that fails,
// then or later, drops back to libx264 for the rest of the process, because a
// broken accelerator must never cost anyone their upload or their view.
//
//   macOS    VideoToolbox
//   Windows  NVENC, Quick Sync, AMF
//   Linux    NVENC, VAAPI, Quick Sync
//
// `hwupload` is only needed by VAAPI/QSV, which take frames in GPU memory;
// NVENC, AMF and VideoToolbox accept ordinary software frames.
const HW_ENCODERS = {
  h264_videotoolbox: { platforms: ['darwin'], quality: (q) => ['-q:v', String(Math.max(1, Math.min(100, 120 - q * 3)))] },
  h264_nvenc: { platforms: ['win32', 'linux'], quality: (q) => ['-rc', 'vbr', '-cq', String(q)] },
  h264_qsv: { platforms: ['win32', 'linux'], quality: (q) => ['-global_quality', String(q)], upload: 'format=nv12,hwupload=extra_hw_frames=64' },
  h264_amf: { platforms: ['win32'], quality: (q) => ['-rc', 'cqp', '-qp_i', String(q), '-qp_p', String(q)] },
  h264_vaapi: {
    platforms: ['linux'],
    quality: (q) => ['-qp', String(q)],
    upload: 'format=nv12,hwupload',
    device: () => ['-vaapi_device', config.ffmpeg.vaapiDevice],
    usable: () => { try { fs.accessSync(config.ffmpeg.vaapiDevice, fs.constants.R_OK | fs.constants.W_OK); return true; } catch { return false; } },
  },
};

let hwChoice; // undefined = unprobed, null = software only

function candidateEncoders() {
  const requested = config.ffmpeg.hwaccel;
  if (requested === 'off') return [];
  if (requested !== 'auto') return HW_ENCODERS[requested] ? [requested] : [];
  return Object.keys(HW_ENCODERS).filter((name) => HW_ENCODERS[name].platforms.includes(process.platform));
}

// Encode one throwaway frame. Proves the encoder is not merely listed.
function encoderWorks(name) {
  const spec = HW_ENCODERS[name];
  if (spec.usable && !spec.usable()) return false;
  const filter = spec.upload ? ['-vf', spec.upload] : [];
  const probe = spawnSync('ffmpeg', [
    '-hide_banner', '-loglevel', 'error',
    ...(spec.device ? spec.device() : []),
    '-f', 'lavfi', '-i', 'testsrc=size=320x240:rate=1:duration=1',
    ...filter, '-c:v', name, '-frames:v', '1', '-f', 'null', '-',
  ], { encoding: 'utf8', timeout: 20000 });
  return probe.status === 0;
}

function hardwareEncoder() {
  if (hwChoice !== undefined) return hwChoice;
  hwChoice = null;
  let listed = '';
  try {
    const probe = spawnSync('ffmpeg', ['-hide_banner', '-encoders'], { encoding: 'utf8', timeout: 20000 });
    listed = probe.status === 0 ? (probe.stdout || '') : '';
  } catch {
    listed = '';
  }
  for (const name of candidateEncoders()) {
    if (!listed.includes(name)) continue;
    try {
      if (encoderWorks(name)) {
        hwChoice = name;
        console.log('[NamelessUnSee] hardware video encoding enabled: %s', name);
        break;
      }
    } catch { /* try the next candidate */ }
  }
  if (!hwChoice && config.ffmpeg.hwaccel !== 'off') {
    console.log('[NamelessUnSee] no usable hardware video encoder; using libx264');
  }
  return hwChoice;
}

function disableHardware(reason) {
  if (hwChoice) console.warn('[NamelessUnSee] disabling %s, falling back to libx264: %s', hwChoice, reason);
  hwChoice = null;
}

/** Extra input args (device init) for the chosen encoder. */
function hardwareInputArgs(name) {
  const spec = name && HW_ENCODERS[name];
  return spec && spec.device ? spec.device() : [];
}

/** Append the GPU upload step for encoders that need frames in device memory. */
function withUpload(name, filter) {
  const spec = name && HW_ENCODERS[name];
  if (!spec || !spec.upload) return filter;
  return filter ? `${filter},${spec.upload}` : spec.upload;
}

// Hardware encoders take their own constant-quality flag; CRF is libx264 only.
function videoCodecArgs(quality, name) {
  if (!name) {
    return ['-c:v', 'libx264', '-preset', config.ffmpeg.preset, '-crf', String(quality), '-pix_fmt', 'yuv420p'];
  }
  return ['-c:v', name, ...HW_ENCODERS[name].quality(quality)];
}

/**
 * Run ffmpeg, preferring hardware and retrying in software if that fails.
 * `build(encoder)` receives the encoder name, or null for libx264.
 */
async function runFfmpegAccelerated(build) {
  const name = hardwareEncoder();
  if (name) {
    try {
      return await runFfmpeg(build(name));
    } catch (error) {
      disableHardware(String(error.message).split('\n')[0]);
    }
  }
  return runFfmpeg(build(null));
}

async function runFfmpeg(args) {
  await acquireEncodeSlot();
  try {
    return await new Promise((resolve, reject) => {
      // -threads bounds this process; the queue above bounds how many run.
      const child = spawn('ffmpeg', ['-threads', String(config.ffmpeg.threads), ...args], { stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = '';
      child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve() : reject(new Error(stderr.slice(-1000))));
    });
  } finally {
    releaseEncodeSlot();
  }
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

  const period = await buildMarkPeriod(width, height, lines);
  const banner = buildBannerSvg(width, height, footerLines);

  return base
    .composite([
      { input: period, tile: true },
      { input: banner.svg, top: banner.top, left: 0 },
    ])
    // Level 6, not 9: at 4000x3000 the extra compression cost ~1.8 s per view
    // for roughly 1% off the file. Every view pays it, so it is not worth it.
    .png({ compressionLevel: 6 })
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

/**
 * Burn a viewer-specific watermark into a video. This runs per view- the mark
 * identifies the individual viewer, so it cannot be precomputed and shared-
 * which makes it the single hottest path in the app.
 *
 * @param {boolean} normalized true when the source was already canonicalised at
 *   upload, which lets the audio be copied instead of re-encoded.
 */
async function renderWatermarkedVideo(originalPath, outputPath, width, height, lines, footerLines, normalized = false) {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'nus-video-'));
  const overlayPath = path.join(tempDir, 'overlay.png');
  try {
    await fs.promises.writeFile(overlayPath, await buildOverlayBitmap(width, height, lines, footerLines));
    await runFfmpegAccelerated((encoder) => [
      ...hardwareInputArgs(encoder),
      '-y', '-i', originalPath, '-loop', '1', '-i', overlayPath,
      // The composite happens in software either way; only the encode moves to
      // the GPU, so any upload to it comes last in the chain.
      '-filter_complex', `[0:v][1:v]${withUpload(encoder, 'overlay=0:0:shortest=1:format=auto')}[v]`,
      '-map', '[v]', '-map', '0:a?',
      ...videoCodecArgs(config.video.viewCrf, encoder),
      // The overlay only touches video. When the upload was normalised the
      // audio is already AAC, so it can be remuxed untouched- re-encoding it
      // for every viewer is pure waste.
      '-c:a', normalized ? 'copy' : 'aac',
      '-movflags', '+faststart', outputPath,
    ]);
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }
  return outputPath;
}

/**
 * Canonicalise a video to H.264/AAC/yuv420p with a faststart header. Run once,
 * at upload, so per-view renders start from a known format.
 */
/**
 * Downscale/framerate filter enforcing the configured quality ceiling. Both
 * axes are rounded down to an even number because libx264 rejects odd
 * dimensions, and `min` means a source already under the cap is never upscaled.
 */
function qualityFilter() {
  const h = config.video.maxHeight;
  return `scale='trunc(iw*min(1\\,${h}/ih)/2)*2':'trunc(min(ih\\,${h})/2)*2':flags=bicubic`
    + `,fps='min(source_fps,${config.video.maxFps})'`;
}

/**
 * Canonicalise a video to H.264/AAC/yuv420p with a faststart header, capped at
 * the configured resolution, framerate and bitrate. Run once, at upload, so
 * per-view renders start from a known format at a sane size.
 */
async function transcodeVideo(originalPath, outputPath) {
  await runFfmpegAccelerated((encoder) => [
    ...hardwareInputArgs(encoder),
    '-y', '-i', originalPath,
    '-map', '0:v:0', '-map', '0:a?',
    '-vf', withUpload(encoder, qualityFilter()),
    ...videoCodecArgs(config.video.crf, encoder),
    // bufsize equal to maxrate, not double it: a looser buffer let the
    // encoder average ~18% over the ceiling on high-motion material.
    '-maxrate', config.video.maxrate, '-bufsize', config.video.maxrate,
    '-c:a', 'aac', '-b:a', config.video.audioBitrate,
    '-movflags', '+faststart', outputPath,
  ]);
  return outputPath;
}

// Probing spawns ffmpeg synchronously, so callers should warm it at startup
// rather than make the first viewer wait for it.
function warmHardwareProbe() { return hardwareEncoder(); }

module.exports = { warmHardwareProbe, renderWatermarked, renderWatermarkedVideo, transcodeVideo, probe, buildOverlaySvg, buildMarkSvg, buildMarkStamp, buildMarkPeriod, buildBannerSvg, buildOverlayBitmap };
