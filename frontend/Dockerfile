# Multi-stage frontend image: build with pinned Node LTS + pnpm, serve with
# an unprivileged Nginx. Zero Node.js runtime in production.
#
# Pin note: image tags are exact; pin by digest (image@sha256:…) in real
# deployments once digests are verified against the registry — digests are
# not guessed here.

# ---- Build stage ----
FROM node:22.22.0-alpine3.22 AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@12.15.0 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

# ---- Runtime stage (unprivileged, no Node) ----
FROM nginxinc/nginx-unprivileged:1.29.4-alpine3.22 AS runtime
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
