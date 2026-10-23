"""Celery tasks. Messages contain only the analysis ID (see services.dispatch).

Retry policy: only the processing layer's transient outcome ("retry") is
retried by Celery, with backoff, up to the configured execution-attempt cap.
Invalid/unsupported captures fail terminally inside process_analysis and are
never retried.
"""

import logging
import uuid

from celery.exceptions import MaxRetriesExceededError

from ipsec_analyzer.core.config import get_settings
from ipsec_analyzer.db.session import SessionLocal
from ipsec_analyzer.services.analyses import reconcile_stale
from ipsec_analyzer.services.dispatch import CeleryDispatcher
from ipsec_analyzer.storage.s3 import S3Storage
from ipsec_analyzer.workers.celery_app import celery_app
from ipsec_analyzer.workers.processing import process_analysis

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="ipsec_analyzer.analyze_capture", max_retries=None)
def analyze_capture(self, analysis_id: str) -> None:
    settings = get_settings()
    run_id = uuid.UUID(analysis_id)  # the only payload: an ID
    with SessionLocal() as db:
        outcome = process_analysis(db, S3Storage(settings), run_id, settings)
    if outcome == "retry":
        try:
            raise self.retry(countdown=min(60, 5 * (2**self.request.retries)), max_retries=10)
        except MaxRetriesExceededError:
            logger.warning("analysis celery retries exhausted analysis_id=%s", run_id)


@celery_app.task(name="ipsec_analyzer.reconcile_queued_analyses")
def reconcile_queued_analyses() -> int:
    settings = get_settings()
    dispatcher = CeleryDispatcher()
    with SessionLocal() as db:
        return reconcile_stale(db, dispatcher.enqueue, settings)
