'use strict';

const sharp = require('sharp');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const config = require('./config');

let testScorer = null; // injected in tests to avoid loading a real model

// Test/DI hook: provide async (imagePath) => number|null
function setScorer(fn) {
  testScorer = fn;
}

const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.ogv', '.ogg']);

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr.slice(-800))));
  });
}

async function videoDuration(videoPath) {
  const output = await runCommand('ffprobe', [
    '-v', 'error', '-show_entries', 'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', videoPath,
  ]);
  const duration = Number.parseFloat(output.trim());
  if (!Number.isFinite(duration) || duration <= 0) throw new Error('video has no usable duration');
  return duration;
}

async function extractVideoFrames(videoPath) {
  const duration = await videoDuration(videoPath);
  // Sample roughly one frame every ten seconds, with a minimum of five and a
  // maximum of fifteen. Frames are evenly distributed across the full video.
  const count = Math.min(15, Math.max(5, Math.ceil(duration / 10)));
  const lastTime = Math.max(0, duration - 0.25);
  const times = Array.from({ length: count }, (_, index) =>
    count === 1 ? 0 : (lastTime * index) / (count - 1)
  );
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'nus-video-moderation-'));
  const frames = [];
  try {
    for (let i = 0; i < times.length; i += 1) {
      const framePath = path.join(dir, `frame-${i}.jpg`);
      await runCommand('ffmpeg', [
        '-hide_banner', '-loglevel', 'error', '-ss', String(times[i]), '-i', videoPath,
        '-frames:v', '1', '-vf', 'scale=1024:1024:force_original_aspect_ratio=decrease',
        '-q:v', '4', '-y', framePath,
      ]);
      frames.push(framePath);
    }
    return { dir, frames, count };
  } catch (error) {
    await fs.rm(dir, { recursive: true, force: true });
    throw error;
  }
}

async function classifyImage(imagePath) {
  if (testScorer) {
    const result = await testScorer(imagePath);
    return typeof result === 'number' ? { score: result, label: 'nsfw' } : result;
  }
  if (!config.moderation.nsfw.serviceUrl) return null;
  try {
    // Downsample before sending so large originals do not cross the internal
    // HTTP boundary unnecessarily.
    const image = await sharp(imagePath)
      .resize(1024, 1024, { fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 85 })
      .toBuffer();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.moderation.nsfw.timeoutMs);
    try {
      const res = await fetch(`${config.moderation.nsfw.serviceUrl}/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'image/jpeg' },
        body: image,
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = (await res.text()).slice(0, 500);
        throw new Error(`sidecar returned HTTP ${res.status}${detail ? `: ${detail}` : ''}`);
      }
      return await res.json();
    } finally {
      clearTimeout(timeout);
    }
  } catch (error) {
    console.warn('[NamelessUnSee] NSFW sidecar error:', error.message);
    return null;
  }
}

/** Returns { score, label, reports }, or null when the moderation sidecar is unavailable. */
async function classify(imagePath) {
  if (!VIDEO_EXTENSIONS.has(path.extname(imagePath).toLowerCase())) return classifyImage(imagePath);
  let extracted;
  try {
    extracted = await extractVideoFrames(imagePath);
    const results = [];
    for (const frame of extracted.frames) {
      const result = await classifyImage(frame);
      if (result) results.push(result);
    }
    if (!results.length) return null;
    const best = results.reduce((winner, result) => result.score > winner.score ? result : winner);
    const reports = [];
    for (const result of results) {
      for (const report of Array.isArray(result.reports) ? result.reports : []) {
        const existing = reports.find((candidate) => candidate.model === report.model);
        if (!existing || (report.flagScore || 0) > (existing.flagScore || 0)) {
          if (existing) reports.splice(reports.indexOf(existing), 1);
          reports.push({ ...report, frame: results.indexOf(result) + 1, frames: extracted.count });
        }
      }
    }
    return { ...best, reports };
  } catch (error) {
    console.warn('[NamelessUnSee] video NSFW scan error:', error.message);
    return null;
  } finally {
    if (extracted) await fs.rm(extracted.dir, { recursive: true, force: true });
  }
}

async function score(imagePath) {
  const result = await classify(imagePath);
  return result ? result.score : null;
}

module.exports = { score, classify, setScorer };
