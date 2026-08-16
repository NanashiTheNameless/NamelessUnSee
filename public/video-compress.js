'use strict';

// Client-side video compression, used before upload.
//
// This is an optimisation only. The server still probes, moderates, normalises
// and watermarks whatever arrives, and treats it as untrusted regardless- a
// client that skips, subverts or fakes this gains nothing beyond uploading a
// different file, which it could always do. Nothing that decides access,
// moderation or watermarking runs here.
//
// The pipeline is WebCodecs: MP4Box demuxes the source, VideoDecoder produces
// frames, those are scaled on a canvas, VideoEncoder re-encodes them, and
// mp4-muxer writes a new MP4. Audio is *remuxed untouched* rather than
// re-encoded.
//
// It refuses far more often than it runs. Anything unexpected- an unsupported
// codec, audio it cannot carry through losslessly, a missing API- makes it
// return the original file so the server handles it as before. Silently
// degrading someone's upload is much worse than not compressing it.

(() => {
  const VENDOR = ['/vendor/mp4box.min.js', '/vendor/mp4-muxer.js'];
  const loaded = new Map();

  function loadScript(src) {
    if (loaded.has(src)) return loaded.get(src);
    const promise = new Promise((resolve, reject) => {
      const el = document.createElement('script');
      el.src = src;
      el.async = true;
      el.onload = resolve;
      el.onerror = () => reject(new Error('failed to load ' + src));
      document.head.appendChild(el);
    });
    loaded.set(src, promise);
    return promise;
  }

  function apisPresent() {
    return typeof window.VideoEncoder === 'function'
      && typeof window.VideoDecoder === 'function'
      && typeof window.EncodedVideoChunk === 'function'
      && typeof window.VideoFrame === 'function'
      && typeof window.OffscreenCanvas === 'function';
  }

  // Even dimensions only: H.264 with 4:2:0 chroma cannot represent odd ones,
  // and encoders reject them outright.
  function targetSize(width, height, maxHeight) {
    const scale = Math.min(1, maxHeight / height);
    return {
      width: Math.max(2, Math.round((width * scale) / 2) * 2),
      height: Math.max(2, Math.round((height * scale) / 2) * 2),
      scaled: scale < 1,
    };
  }

  // The codec-private bytes (SPS/PPS for H.264) a decoder needs to start.
  function codecDescription(file, trackId) {
    const trak = file.getTrackById(trackId);
    const entries = trak && trak.mdia && trak.mdia.minf && trak.mdia.minf.stbl && trak.mdia.minf.stbl.stsd
      ? trak.mdia.minf.stbl.stsd.entries
      : [];
    for (const entry of entries) {
      const box = entry.avcC || entry.hvcC || entry.vpcC || entry.av1C;
      if (!box) continue;
      const stream = new window.MP4Box.DataStream(undefined, 0, window.MP4Box.DataStream.BIG_ENDIAN);
      box.write(stream);
      return new Uint8Array(stream.buffer, 8); // strip the 8-byte box header
    }
    return null;
  }

  // AudioSpecificConfig out of the esds descriptor chain, needed to remux AAC
  // without re-encoding it. Returns null when the shape is not what we expect,
  // which aborts the whole compression rather than dropping the audio.
  function audioDescription(file, trackId) {
    try {
      const trak = file.getTrackById(trackId);
      for (const entry of trak.mdia.minf.stbl.stsd.entries) {
        if (!entry.esds) continue;
        const descs = entry.esds.esd && entry.esds.esd.descs;
        const decoderConfig = descs && descs[0] && descs[0].descs && descs[0].descs[0];
        if (decoderConfig && decoderConfig.data && decoderConfig.data.length) {
          return new Uint8Array(decoderConfig.data);
        }
      }
    } catch { /* unexpected layout: treated as "cannot carry the audio" */ }
    return null;
  }

  function demux(file, arrayBuffer) {
    return new Promise((resolve, reject) => {
      const samples = { video: [], audio: [] };
      let info = null;
      file.onError = (err) => reject(new Error(String(err)));
      file.onReady = (movieInfo) => {
        info = movieInfo;
        for (const track of movieInfo.tracks) {
          file.setExtractionOptions(track.id, null, { nbSamples: 1000 });
        }
        file.start();
      };
      file.onSamples = (id, _user, chunk) => {
        const track = info.tracks.find((t) => t.id === id);
        if (!track) return;
        const bucket = track.type === 'video' || info.videoTracks.some((v) => v.id === id) ? 'video' : 'audio';
        for (const sample of chunk) samples[bucket].push(sample);
      };
      const buffer = arrayBuffer;
      buffer.fileStart = 0;
      file.appendBuffer(buffer);
      file.flush();
      if (!info) return reject(new Error('not a parsable mp4'));
      resolve({ info, samples });
    });
  }

  const microseconds = (value, timescale) => Math.round((value / timescale) * 1e6);

  /**
   * @returns {Promise<File>} a smaller file, or the original when compression
   *   is not possible or would not help.
   */
  async function compress(source, options, onProgress) {
    const maxHeight = options.maxHeight;
    if (!apisPresent()) return source;
    // Only MP4/MOV: the demuxer here reads ISO-BMFF. WebM and others go to the
    // server untouched.
    if (!/^video\/(mp4|quicktime)$/.test(source.type)) return source;

    await Promise.all(VENDOR.map(loadScript));
    if (!window.MP4Box || !window.Mp4Muxer) return source;

    const buffer = await source.arrayBuffer();
    const file = window.MP4Box.createFile();
    let demuxed;
    try {
      demuxed = await demux(file, buffer);
    } catch {
      return source;
    }

    const { info, samples } = demuxed;
    const videoTrack = info.videoTracks && info.videoTracks[0];
    if (!videoTrack || !samples.video.length) return source;

    const audioTrack = info.audioTracks && info.audioTracks[0];
    // Audio must be carried through byte-for-byte. If there is audio we cannot
    // describe, bail out entirely- never produce a silent copy of someone's
    // video.
    let audioDesc = null;
    if (audioTrack) {
      if (!/^mp4a/.test(audioTrack.codec) || !samples.audio.length) return source;
      audioDesc = audioDescription(file, audioTrack.id);
      if (!audioDesc) return source;
    }

    const target = targetSize(videoTrack.video.width, videoTrack.video.height, maxHeight);
    // Nothing to gain: already within the cap.
    if (!target.scaled) return source;

    const description = codecDescription(file, videoTrack.id);
    if (!description) return source;

    const encoderConfig = {
      codec: 'avc1.4d0028', // H.264 Main@4.0, broadly decodable
      width: target.width,
      height: target.height,
      bitrate: options.bitrate,
      framerate: Math.min(options.maxFps, videoTrack.nb_samples / (videoTrack.duration / videoTrack.timescale) || options.maxFps),
      avc: { format: 'avc' },
    };
    const decoderConfig = {
      codec: videoTrack.codec,
      codedWidth: videoTrack.video.width,
      codedHeight: videoTrack.video.height,
      description,
    };
    try {
      const [encOk, decOk] = await Promise.all([
        window.VideoEncoder.isConfigSupported(encoderConfig),
        window.VideoDecoder.isConfigSupported(decoderConfig),
      ]);
      if (!encOk.supported || !decOk.supported) return source;
    } catch {
      return source;
    }

    const muxer = new window.Mp4Muxer.Muxer({
      target: new window.Mp4Muxer.ArrayBufferTarget(),
      video: { codec: 'avc', width: target.width, height: target.height },
      audio: audioTrack ? {
        codec: 'aac',
        sampleRate: audioTrack.audio.sample_rate,
        numberOfChannels: audioTrack.audio.channel_count,
      } : undefined,
      firstTimestampBehavior: 'offset',
      fastStart: 'in-memory', // moov up front, like the server's +faststart
    });

    const canvas = new OffscreenCanvas(target.width, target.height);
    const ctx = canvas.getContext('2d', { alpha: false });

    let failure = null;
    const encoder = new window.VideoEncoder({
      output: (chunk, meta) => muxer.addVideoChunk(chunk, meta),
      error: (err) => { failure = err; },
    });
    encoder.configure(encoderConfig);

    let processed = 0;
    const total = samples.video.length;
    // A keyframe every couple of seconds keeps the result seekable.
    const keyframeEvery = Math.max(1, Math.round((options.maxFps || 30) * 2));

    const decoder = new window.VideoDecoder({
      output: (frame) => {
        try {
          ctx.drawImage(frame, 0, 0, target.width, target.height);
          const scaled = new VideoFrame(canvas, {
            timestamp: frame.timestamp,
            duration: frame.duration || undefined,
          });
          encoder.encode(scaled, { keyFrame: processed % keyframeEvery === 0 });
          scaled.close();
        } catch (err) {
          failure = err;
        } finally {
          frame.close();
          processed += 1;
          if (onProgress && total) onProgress(processed / total);
        }
      },
      error: (err) => { failure = err; },
    });
    decoder.configure(decoderConfig);

    try {
      for (const sample of samples.video) {
        if (failure) break;
        decoder.decode(new EncodedVideoChunk({
          type: sample.is_sync ? 'key' : 'delta',
          timestamp: microseconds(sample.cts, sample.timescale),
          duration: microseconds(sample.duration, sample.timescale),
          data: sample.data,
        }));
        // Let the decoder drain so a long video cannot pile every frame into
        // memory at once.
        if (decoder.decodeQueueSize > 16) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
      if (failure) throw failure;
      await decoder.flush();
      await encoder.flush();

      if (audioTrack) {
        for (const sample of samples.audio) {
          muxer.addAudioChunkRaw(
            sample.data,
            sample.is_sync ? 'key' : 'delta',
            microseconds(sample.cts, sample.timescale),
            microseconds(sample.duration, sample.timescale),
            { decoderConfig: { codec: audioTrack.codec, description: audioDesc } }
          );
        }
      }
      muxer.finalize();
    } catch {
      try { decoder.close(); } catch { /* already closed */ }
      try { encoder.close(); } catch { /* already closed */ }
      return source;
    } finally {
      if (decoder.state !== 'closed') decoder.close();
      if (encoder.state !== 'closed') encoder.close();
    }

    const out = muxer.target.buffer;
    // Re-encoding can inflate an already-efficient file; keep whichever is
    // smaller so this can never make an upload worse.
    if (!out || out.byteLength >= source.size) return source;
    return new File(
      [out],
      source.name.replace(/\.[^.]+$/, '') + '.mp4',
      { type: 'video/mp4' }
    );
  }

  window.NUSVideoCompress = { compress, apisPresent };
})();
