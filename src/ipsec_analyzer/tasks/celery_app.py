"""Backwards-compatible re-export; canonical Celery app lives in `workers.celery_app`."""

from ipsec_analyzer.workers.celery_app import celery_app

__all__ = ["celery_app"]
