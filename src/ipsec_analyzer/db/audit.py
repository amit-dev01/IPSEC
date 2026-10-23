"""Canonical audit-event hashing.

canonical_payload is a deterministic JSON encoding (sorted keys, no insignificant
whitespace) of the event's identifying fields. event_hash chains events:
sha256((previous_event_hash or "") || canonical_payload). Storing the payload lets
anyone recompute and verify the hash; payloads contain metadata only — never packet
contents, credentials, or secrets.
"""

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any


def canonical_payload(
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    organization_id: uuid.UUID | None,
    occurred_at: datetime,
    metadata: dict[str, Any] | None = None,
) -> str:
    payload = {
        "action": action,
        "actor_user_id": str(actor_user_id) if actor_user_id else None,
        "metadata": metadata or {},
        "occurred_at": occurred_at.isoformat(),
        "organization_id": str(organization_id) if organization_id else None,
        "resource_id": str(resource_id) if resource_id else None,
        "resource_type": resource_type,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_event_hash(canonical: str, previous_event_hash: str | None = None) -> str:
    digest = hashlib.sha256()
    digest.update((previous_event_hash or "").encode("ascii"))
    digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()
