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
COPY --from=build /app/dist /usr/share/nginx/html
# The nginx template is generated in-image (not COPYed) so the build does
# not depend on a context-relative config file. Only ${PORT} and
# ${BACKEND_ORIGIN} are substituted by the entrypoint at container start.
USER root
RUN <<'NGINXEOF'
mkdir -p /etc/nginx/templates
cat > /etc/nginx/templates/default.conf.template <<'EOF'
# IPsec Analyzer frontend — static SPA + /api/v1 reverse proxy.
# Rendered by the nginx entrypoint from environment:
#   PORT            listen port (Render injects this; Compose sets 8080)
#   BACKEND_ORIGIN  e.g. http://api:8000 (Compose) or
#                   https://ipsec-app.onrender.com (hosted split deployment)
# Only ${PORT} and ${BACKEND_ORIGIN} are substituted; nginx runtime
# variables ($uri, $host, …) are left untouched by the entrypoint filter.

server {
    listen ${PORT};
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Align with the backend PCAP upload limit (max_upload_bytes, 512 MiB
    # default). The backend enforces its own limit and returns 413.
    client_max_body_size 512m;

    # ---- Strict security headers (all responses) ----
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;

    # ---- API proxy to the FastAPI backend ----
    location /api/v1/ {
        proxy_pass ${BACKEND_ORIGIN};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Authorization $http_authorization;
        # Uploads (PCAP) and report generation can be slow.
        proxy_connect_timeout 10s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
        proxy_request_buffering off;
        add_header Cache-Control "no-store" always;
        add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
    }

    # ---- Hashed static assets: immutable caching ----
    location /assets/ {
        try_files $uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    # ---- SPA fallback; index.html is never cached ----
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-store" always;
    }

    location = /index.html {
        add_header Cache-Control "no-store" always;
    }
}
EOF
NGINXEOF
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:${PORT}/ || exit 1
