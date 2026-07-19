FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json yarn.lock .yarnrc.yml ./
RUN corepack enable && corepack install && corepack yarn install --immutable
COPY index.js ./
ENV PORT=8787 \
    MODEL_CACHE_DIR=/app/models \
    NSFW_MODEL=onnx-community/nsfw-classifier-ONNX \
    NSFW_SAFETY_MODEL=OwenElliott/image-safety-classifier-m \
    NSFW_BINARY_MODEL=onnx-community/nsfw_image_detection-ONNX
RUN mkdir -p /app/models && chown -R node:node /app
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "index.js"]
