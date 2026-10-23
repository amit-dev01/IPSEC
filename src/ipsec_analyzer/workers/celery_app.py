from celery import Celery

from ipsec_analyzer.core.config import get_settings

_settings = get_settings()

# PostgreSQL is the authoritative job-status store. The Celery result backend is
# disabled on purpose: results/status are read from AnalysisRun rows, so no
# sensitive result data accumulates in an unbounded broker-side backend.
celery_app = Celery("ipsec_analyzer", broker=_settings.redis_url, backend=None)
celery_app.conf.update(
    task_ignore_result=True,
    task_track_started=False,  # status comes from PostgreSQL, not Celery
    task_time_limit=_settings.max_analysis_seconds,
    task_soft_time_limit=max(1, _settings.max_analysis_seconds - 60),
    worker_prefetch_multiplier=1,
    worker_concurrency=_settings.worker_concurrency,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_transport_options={"visibility_timeout": _settings.max_analysis_seconds + 300},
    include=["ipsec_analyzer.workers.tasks"],
    beat_schedule={
        # Reconciliation: queued rows that never started (broker outage, lost
        # worker) are redispatched instead of silently sticking.
        "reconcile-queued-analyses": {
            "task": "ipsec_analyzer.reconcile_queued_analyses",
            "schedule": 60.0,
        }
    },
)
