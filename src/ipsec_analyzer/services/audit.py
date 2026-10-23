"""Append-only, hash-chained audit events (metadata only)."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.db.audit import canonical_payload, compute_event_hash
from ipsec_analyzer.models import AuditEvent

logger = logging.getLogger(__name__)


def record_event(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    organization_id: uuid.UUID | None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    occurred_at = datetime.now(UTC)
    previous_hash = None
    if organization_id is not None:
        previous_hash = db.scalar(
            select(AuditEvent.event_hash)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(1)
        )
    payload = canonical_payload(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_user_id=actor_user_id,
        organization_id=organization_id,
        occurred_at=occurred_at,
        metadata=metadata,
    )
    event = AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        occurred_at=occurred_at,
        event_metadata=metadata or {},
        canonical_payload=payload,
        previous_event_hash=previous_hash,
        event_hash=compute_event_hash(payload, previous_hash),
    )
    db.add(event)
    return event
