# --- build stage: install dependencies with Yarn Berry (native modules compile here)
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY .yarnrc.yml package.json yarn.lock ./
RUN corepack enable && corepack install && corepack yarn install --immutable

# --- runtime stage
FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/app/data
WORKDIR /app
# fontconfig + the 0xProto font so watermark text (rendered via librsvg) also
# uses 0xProto; without it, watermarks fall back to a generic monospace font.
# ffmpeg provides ffmpeg + ffprobe for probing and watermarking video uploads.
RUN apt-get update \
 && apt-get install -y --no-install-recommends fontconfig ca-certificates ffmpeg \
 && rm -rf /var/lib/apt/lists/*
COPY assets/fonts/0xProto-Regular.ttf assets/fonts/0xProto-Bold.ttf /usr/share/fonts/truetype/0xproto/
RUN fc-cache -f
COPY --from=build /app/node_modules ./node_modules
COPY . .
RUN corepack enable && corepack install
RUN mkdir -p /app/data && chown -R node:node /app
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+ (process.env.PORT||3000) +'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
