# Neon CLI Setup (after cloning this PR)

State: `neon init` has already been run for this project
(org `org-mute-cake-50087929`, project `morning-breeze-87322528`,
branch `production`, services: postgres + object-storage).
`neon.ts` declares one **private** bucket: `ipsec-captures`.

The agent sandbox could not complete `neon login` (it cannot reach the
Neon API), so the remaining steps run on **your machine**.

## 1. Sign in and deploy

```bash
npm i -g neon@latest        # or use: npx neon@latest
neon login                  # finish the browser sign-in
neon deploy                 # provisions Postgres + bucket, writes .env.local
```

`neon deploy` pulls env vars into `.env.local` (gitignored). Expected keys
include `DATABASE_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_ENDPOINT_URL_S3`, `AWS_REGION`. **Never commit or share these.**

## 2. Map Neon env vars to this app (Python/FastAPI)

This app reads `IPSEC_*` variables (see `core/config.py`). Create a local
`.env` (also gitignored) with:

```ini
IPSEC_DATABASE_URL=postgresql+psycopg://<rest of Neon's DATABASE_URL after "postgresql://">
IPSEC_S3_ENDPOINT_URL=<AWS_ENDPOINT_URL_S3>
IPSEC_S3_ACCESS_KEY=<AWS_ACCESS_KEY_ID>          # nak_live_...
IPSEC_S3_SECRET_KEY=<AWS_SECRET_ACCESS_KEY>      # nsk_live_...
IPSEC_S3_REGION=<AWS_REGION>
IPSEC_S3_ADDRESSING_STYLE=path                   # Neon buckets are path-style only
IPSEC_S3_BUCKET=ipsec-captures
IPSEC_JWT_SIGNING_KEY=<generate 32+ random chars>
IPSEC_S3_SSE_ALGORITHM=AES256
IPSEC_ENVIRONMENT=production
IPSEC_REDIS_URL=<Upstash rediss:// URL, from the Render-stage setup>
```

Note: production mode requires `IPSEC_S3_SSE_ALGORITHM` (fail-closed by
design). Neon Object Storage is Beta and its PutObject docs do not list
the SSE header — if your first upload fails with a storage error, tell
the assistant the exact error before changing anything.

## 3. Verify

```bash
uv sync --frozen --group dev
uv run alembic upgrade head
uv run pytest tests/test_storage.py tests/test_config.py -q
uv run uvicorn ipsec_analyzer.main:app --host 0.0.0.0 --port 8000
# then: curl http://localhost:8000/api/v1/health/live
```

Then create the first admin (no public registration):

```bash
uv run ipsec-admin create-org-admin --organization "My Lab" --email you@example.com
```

## 4. Report back

Tell the assistant **only**: whether `neon deploy` succeeded, any error
text (no secrets), and the health-check result. Do not paste `.env.local`,
connection strings, or credential values into chat.
