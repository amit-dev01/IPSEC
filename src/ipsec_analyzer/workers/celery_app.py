from celery import Celery

from ipsec_analyzer.core.config import get_settings

_settings = get_settings()

# No analysis tasks are registered yet (later stage). The app exists so API/worker
# share one broker configuration; absence of a task must surface as unavailable, not success.
celery_app = Celery("ipsec_analyzer", broker=_settings.redis_url, backend=_settings.redis_url)
celery_app.conf.update(
    task_track_started=True,
    task_time_limit=_settings.max_analysis_seconds,
    task_soft_time_limit=max(1, _settings.max_analysis_seconds - 60),
    worker_prefetch_multiplier=1,
)
