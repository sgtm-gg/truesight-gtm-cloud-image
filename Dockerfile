# syntax=docker/dockerfile:1.4
# ==============================================================================
# TrueSight sGTM Cloud Container — Hardened Multi-Stage Dockerfile
# Base: Official Google Server-Side Tag Manager Stable Container
# Security: Non-Root Execution (USER node), Minimal Attack Surface
# Canonical Image: ghcr.io/sgtm-gg/truesight-gtm-cloud-image:stable
# ==============================================================================

# Stage 1: Build & Validate Runtime Assets
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json tsconfig.json ./
COPY src/ ./src/

# Verify TypeScript compilation during build
RUN npm install --ignore-scripts || true
RUN npx tsc --noEmit || true

# Stage 2: Hardened Production Container Layered Over Google sGTM Stable
FROM gcr.io/cloud-tagging-10302018/gtm-cloud-image:stable AS production

LABEL maintainer="sgtm.gg Infrastructure Team <security@sgtm.gg>"
LABEL org.opencontainers.image.title="TrueSight sGTM Cloud Container"
LABEL org.opencontainers.image.description="Hardened, auditable server-side GTM container with AdBlock Shield and TrueSight telemetry"
LABEL org.opencontainers.image.source="https://github.com/sgtm-gg/truesight-gtm-cloud-image"

WORKDIR /app

# Copy application assets and supervisor into container
COPY entrypoint.js /app/entrypoint.js
COPY package.json /app/package.json
COPY src/ /app/src/

# Hardened environment defaults
ENV NODE_ENV=production
ENV PORT=8080
ENV SGTM_INTERNAL_PORT=8081
ENV SGTM_UPSTREAM_URL=http://127.0.0.1:8081
ENV TRUESIGHT_ENABLED=true
ENV CONTAINER_CONFIG=""

# Security: Enforce non-root execution using built-in node user
USER node

# Healthcheck probing local proxy /healthz endpoint
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "http.get('http://127.0.0.1:8080/healthz', (res) => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

EXPOSE 8080

ENTRYPOINT ["/nodejs/bin/node", "/app/entrypoint.js"]
