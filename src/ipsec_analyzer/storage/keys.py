"""Tenant-isolated, random object keys and safe display names.

User input never becomes a path or storage key: keys are built from the tenant
ID, capture ID, and a random token. The submitted filename is retained only as a
sanitized display name.
"""

import re
import secrets
import uuid

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def random_capture_object_key(tenant_id: uuid.UUID, capture_id: uuid.UUID) -> str:
    return f"tenants/{tenant_id}/captures/{capture_id}/{secrets.token_hex(16)}"


def capture_object_key(tenant_id: uuid.UUID, capture_id: uuid.UUID) -> str:
    return random_capture_object_key(tenant_id, capture_id)


def sanitize_display_name(filename: str | None) -> str:
    base = _CTRL.sub("", (filename or "").replace("\\", "/")).rsplit("/", 1)[-1]
    base = _SAFE.sub("_", base).strip(". ")[:255]
    return base or "capture"
