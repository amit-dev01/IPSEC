# Multi-stage frontend image: build with pinned Node LTS + pnpm, serve with
# an unprivileged Nginx. Zero Node.js runtime in production.
#
# Pin note: both base images are pinned by tag AND registry-verified digest
# (Docker Hub API, 2026-10-25). The previous runtime pin
# (1.29.4-alpine3.22) did not exist and broke the Render build.

# ---- Build stage ----
FROM node:22.22.0-alpine3.22@sha256:7aa86fa052f6e4b101557ccb56717cb4311be1334381f526fe013418fe157384 AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@12.15.0 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

# ---- Runtime stage (unprivileged, no Node) ----
FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6 AS runtime
# Defaults suit Docker Compose; hosted platforms override per environment.
ENV PORT=8080 \
    BACKEND_ORIGIN=http://api:8000 \
    NGINX_ENVSUBST_FILTER="PORT|BACKEND_ORIGIN"
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
USER nginx
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:${PORT}/ || exit 1
