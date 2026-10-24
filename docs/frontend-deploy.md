# Frontend Deployment — Render (free tier)

The frontend ships as a hardened nginx Docker image (`frontend/Dockerfile`)
that serves the SPA and proxies `/api/v1/` to the backend, so the browser
only ever talks to one origin (no CORS, tokens never in URLs).

- Backend (already live): `https://ipsec-app.onrender.com`
  (`GET /api/v1/health/live` → `{"status":"ok"}`)
- Frontend service to create: `ipsec-web` (free Render Web Service, Docker)

## Create the service (≈5 minutes, dashboard only)

1. Go to **render.com → Dashboard → New + → Web Service**.
2. **Connect** the GitHub repository `amit-dev01/IPSEC` (authorize Render if
   asked) and pick branch **`main`**.
3. Configure:
   - **Name:** `ipsec-web`
   - **Region:** Singapore (same as the backend)
   - **Language / Runtime:** Docker
   - **Dockerfile Path:** `./frontend/Dockerfile`  (per Render's UI, this path is relative to the **repo root**)
   - **Docker Build Context Directory:** `./frontend`
   - **Instance Type:** Free
   - **Health Check Path:** `/`
4. **Environment Variables** — add exactly one:
   - `BACKEND_ORIGIN` = `https://ipsec-app.onrender.com`
   - (`PORT` is injected by Render automatically; nginx templates its
     listen port and proxy target from these two values.)
5. Click **Create Web Service**. First build takes a few minutes
   (Node build stage → nginx runtime stage). When the deploy is **Live**,
   open `https://ipsec-web.onrender.com`.

> Using Blueprint instead? `render.yaml` at the repo root already declares
> both `ipsec-app` and `ipsec-web` with these exact settings.

## Verify after first deploy

1. `https://ipsec-web.onrender.com` shows the **Sign in** page.
2. The top bar shows **Backend: ready** (the app polls
   `/api/v1/health/ready` through the nginx proxy).
3. Sign in with your analyst/admin account, upload a small lab PCAP,
   confirm the server SHA-256 appears, and run an analysis to completion.

Free-tier notes: both services sleep after ~15 min idle; the first request
after sleep takes ~1 minute while they wake. Keep total workspace usage
within the 750 free instance hours/month.

## Local equivalent

`docker compose up --build` runs the same image at
`http://localhost:8080` with `BACKEND_ORIGIN=http://api:8000` on the
internal network — see `docker-compose.yml`.
