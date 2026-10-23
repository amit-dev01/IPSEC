"""Tenant-isolated object keys. User input never becomes a raw path/key."""

import re
import uuid

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def capture_object_key(tenant_id: uuid.UUID, capture_id: uuid.UUID, filename: str) -> str:
    # Strip any directory components and unsafe characters from the client-supplied name.
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    safe = _SAFE.sub("_", base).strip(".") or "capture"
    return f"tenants/{tenant_id}/captures/{capture_id}/{safe}"
