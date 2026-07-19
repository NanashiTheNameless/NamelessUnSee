'use strict';

const http = require('http');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const sharp = require('sharp');
const ort = require('onnxruntime-node');

const PORT = Number(process.env.PORT || 8787);
const MODELS = [
  {
    name: 'subtype',
    id: process.env.NSFW_MODEL || 'onnx-community/nsfw-classifier-ONNX',
    risky: /porn|sexy|hentai/i,
  },
  {
    name: 'safety',
    id: process.env.NSFW_SAFETY_MODEL || 'OwenElliott/image-safety-classifier-m',
    risky: /nsfw|nsfl/i,
  },
  {
    name: 'binary',
    id: process.env.NSFW_BINARY_MODEL || 'onnx-community/nsfw_image_detection-ONNX',
    risky: /nsfw|porn|sexy|hentai/i,
  },
];
const MAX_BYTES = 20 * 1024 * 1024;
const classifierPromises = new Map();
const MODEL_CACHE_DIR = process.env.MODEL_CACHE_DIR || '/app/models';
const startup = { ready: false, reports: [] };

async function loadSafetyModel() {
  const modelPath = path.join(MODEL_CACHE_DIR, 'image-safety-classifier-m.onnx');
  await fs.mkdir(MODEL_CACHE_DIR, { recursive: true });
  try {
    await fs.access(modelPath);
  } catch {
    const url = 'https://huggingface.co/OwenElliott/image-safety-classifier-m/resolve/main/onnx/image-safety-classifier-m.onnx?download=true';
    console.log('[moderation] downloading safety model:', url);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`safety model download HTTP ${response.status}`);
    const partialPath = `${modelPath}.part`;
    await fs.writeFile(partialPath, Buffer.from(await response.arrayBuffer()));
    await fs.rename(partialPath, modelPath);
  }
  console.log('[moderation] loading safety model:', modelPath);
  const session = await ort.InferenceSession.create(modelPath);
  console.log('[moderation] safety model loaded');
  return async (imagePath) => {
    const { data } = await sharp(imagePath)
      .resize(224, 224, { fit: 'cover' })
      .removeAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const pixels = new Float32Array(1 * 3 * 224 * 224);
    for (let y = 0; y < 224; y += 1) {
      for (let x = 0; x < 224; x += 1) {
        const source = (y * 224 + x) * 3;
        const target = y * 224 + x;
        // The model's ONNX graph contains its own normalization.
        pixels[target] = data[source];
        pixels[224 * 224 + target] = data[source + 1];
        pixels[2 * 224 * 224 + target] = data[source + 2];
      }
    }
    const inputName = session.inputNames[0];
    const result = await session.run({ [inputName]: new ort.Tensor('float32', pixels, [1, 3, 224, 224]) });
    const values = Array.from(result[session.outputNames[0]].data, Number);
    const sum = values.reduce((total, value) => total + value, 0);
    const probabilities = sum > 0.98 && sum < 1.02
      ? values
      : (() => {
        const max = Math.max(...values);
        const exp = values.map((value) => Math.exp(value - max));
        const total = exp.reduce((acc, value) => acc + value, 0);
        return exp.map((value) => value / total);
      })();
    return ['NSFL', 'NSFW', 'SFW']
      .map((label, index) => ({ label, score: probabilities[index] || 0 }))
      .sort((a, b) => b.score - a.score);
  };
}

async function classifier(model) {
  if (!classifierPromises.has(model.id)) {
    const promise = (async () => {
      if (model.name === 'safety') return loadSafetyModel();
      // eslint-disable-next-line no-eval -- dynamic import of the ESM package
      const tf = await import('@huggingface/transformers');
      tf.env.cacheDir = process.env.MODEL_CACHE_DIR || '/app/models';
      tf.env.allowLocalModels = true;
      tf.env.allowRemoteModels = true;
      console.log(`[moderation] loading ${model.name} model:`, model.id);
      const pipe = await tf.pipeline('image-classification', model.id);
      console.log(`[moderation] ${model.name} model loaded:`, model.id);
      return pipe;
    })();
    classifierPromises.set(model.id, promise);
  }
  return classifierPromises.get(model.id);
}

async function initializeAndTest() {
  const testPath = path.join(os.tmpdir(), `nus-moderation-startup-${process.pid}.jpg`);
  await sharp({ create: { width: 224, height: 224, channels: 3, background: { r: 128, g: 128, b: 128 } } })
    .jpeg({ quality: 90 })
    .toFile(testPath);
  try {
    const reports = await Promise.all(MODELS.map(async (model) => {
      try {
        const predict = await classifier(model);
        const output = await predict(testPath, { topk: 5 });
        if (!Array.isArray(output) || !output.length || !output.every((item) => typeof item.score === 'number')) {
          throw new Error('model returned no usable predictions');
        }
        return { model: model.name, label: output[0].label, score: output[0].score, tested: true };
      } catch (error) {
        return { model: model.name, tested: false, error: error.message };
      }
    }));
    startup.reports = reports;
    startup.ready = reports.every((report) => report.tested);
    if (startup.ready) {
      console.log('[moderation] startup checks passed:', JSON.stringify(reports));
    } else {
      console.error('[moderation] startup checks failed:', JSON.stringify(reports));
    }
  } catch (error) {
    startup.reports = [{ tested: false, error: error.message }];
    startup.ready = false;
    console.error('[moderation] startup checks failed:', error.message);
  } finally {
    await fs.rm(testPath, { force: true });
  }
}

function send(res, status, body) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': data.length });
  res.end(data);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    return send(res, startup.ready ? 200 : 503, { ok: startup.ready, models: startup.reports });
  }
  if (!startup.ready) return send(res, 503, { error: 'classifiers not ready', models: startup.reports });
  if (req.method !== 'POST' || req.url !== '/classify' || !String(req.headers['content-type'] || '').startsWith('image/')) {
    return send(res, 404, { error: 'not found' });
  }
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BYTES) return send(res, 413, { error: 'image too large' });
      chunks.push(chunk);
    }
    const tempPath = path.join(os.tmpdir(), `nus-moderation-${process.pid}-${Date.now()}.jpg`);
    await fs.writeFile(tempPath, Buffer.concat(chunks));
    try {
      const reports = await Promise.all(MODELS.map(async (model) => {
        try {
          const output = await (await classifier(model))(tempPath, { topk: 5 });
          const top = output && output[0];
          const hit = (output || []).find((item) => model.risky.test(String(item.label || '')));
          return {
            model: model.name,
            label: top ? top.label : null,
            score: top ? top.score : 0,
            flagged: !!hit,
            flagLabel: hit ? hit.label : null,
            flagScore: hit ? hit.score : 0,
          };
        } catch (error) {
          console.error(`[moderation] ${model.name} failed:`, error.message);
          return { model: model.name, label: null, score: null, error: 'unavailable' };
        }
      }));
      if (reports.some((report) => report.error) || !reports.some((report) => typeof report.score === 'number')) {
        return send(res, 503, { error: 'all classifiers unavailable', reports });
      }
      const available = reports.filter((report) => report.flagged && typeof report.flagScore === 'number');
      if (!available.length) return send(res, 200, { score: 0, label: null, reports });
      const hit = available.reduce((best, report) => report.flagScore > best.flagScore ? report : best);
      send(res, 200, { score: hit.flagScore, label: hit.flagLabel ? `${hit.model}:${hit.flagLabel}` : null, reports });
    } finally {
      await fs.rm(tempPath, { force: true });
    }
  } catch (error) {
    console.error('[moderation] classify failed:', error.message);
    send(res, 503, { error: 'classifier unavailable' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[moderation] listening on ${PORT}`);
  initializeAndTest().catch((error) => {
    startup.reports = [{ tested: false, error: error.message }];
    startup.ready = false;
    console.error('[moderation] startup checks failed:', error.message);
  });
});
