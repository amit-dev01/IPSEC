#!/bin/sh
# Render free-tier single-service startup (demo topology):
# migrate -> start one small Celery worker -> serve the API.
# Used only by Dockerfile.render. Production uses docker-compose.yml
# with separate API and worker services.
set -e

alembic upgrade head

celery -A ipsec_analyzer.workers.celery_app:celery_app worker \
    --loglevel=INFO --pool=solo --concurrency=1 &

exec uvicorn ipsec_analyzer.main:app --host 0.0.0.0 --port "${PORT:-8000}"
