"""One-time bootstrap admin for first hosted deployments.

There is intentionally no public registration and no shell access on the
free hosted tier, so the first admin is created either by the local
``ipsec-admin`` CLI or — when IPSEC_BOOTSTRAP_EMAIL/PASSWORD are set — once
at application startup. Idempotent: if a user with the bootstrap email
already exists, this is a no-op. The password is never logged.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from ipsec_analyzer.admin import create_org_admin
from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.db.session import SessionLocal
from ipsec_analyzer.models import User

logger = logging.getLogger(__name__)


def ensure_bootstrap_admin(settings: Settings, session_factory=SessionLocal) -> bool:
    """Create the bootstrap org+admin if configured and not yet present.

    Returns True when an account was created. Never logs the password.
    """
    email = (settings.bootstrap_email or "").strip().lower()
    password = settings.bootstrap_password or ""
    if not email or not password:
        return False
    if len(password) < 12:
        logger.error("bootstrap admin skipped: password must be at least 12 characters")
        return False
    with session_factory() as db:
        existing = db.scalar(select(User).where(User.email == email))
    if existing is not None:
        logger.info("bootstrap admin already exists; skipping")
        return False
    org, admin = create_org_admin(
        settings.bootstrap_organization, email, password, session_factory=session_factory
    )
    logger.info("bootstrap admin created (organization_id=%s admin_user_id=%s)", org.id, admin.id)
    return True
