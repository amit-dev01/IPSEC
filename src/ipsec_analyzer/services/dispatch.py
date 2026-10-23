"""Analysis dispatch: Celery messages contain ONLY the analysis ID.

No PCAP data, no secrets, no user-supplied options ever enter the broker.
Broker failures raise DispatchError and are recorded on the AnalysisRun row
(status stays queued, error_code=dispatch_failed) so nothing is silently stuck.
"""

import logging
import uuid

logger = logging.getLogger(__name__)

TASK_NAME = "ipsec_analyzer.analyze_capture"


class DispatchError(Exception):
    pass


class CeleryDispatcher:
    def enqueue(self, analysis_id: uuid.UUID) -> None:
        from ipsec_analyzer.workers.celery_app import celery_app

        try:
            celery_app.send_task(TASK_NAME, args=[str(analysis_id)])
        except Exception as exc:  # kombu/broker errors surface here
            logger.warning("analysis dispatch failed analysis_id=%s", analysis_id)
            raise DispatchError("broker_unavailable") from exc
