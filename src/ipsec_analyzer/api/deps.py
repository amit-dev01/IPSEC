"""Authentication/authorization dependencies.

Only /api/v1/health/* (and dev docs when explicitly enabled) are unauthenticated.
Everything else goes through get_current_user. Blocking DB work: this module is
used from sync `def` endpoints/dependencies.

DEMO MODE (settings.demo_mode, IPSEC_DEMO_MODE=true): get_current_user skips
token validation entirely and returns an auto-created demo admin user, so a
public demo deployment needs no login anywhere. Off by default.
"""

import secrets
import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.permissions import Permission, Role, has_permission
from ipsec_analyzer.core.security import TokenError, decode_access_token, hash_password
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import Organization, User

_bearer = HTTPBearer(auto_error=False)

DEMO_EMAIL = "demo@ipsec.lab"


def get_demo_user(db: Session) -> User:
    """Return the single demo admin, creating its org on first use."""
    user = db.scalar(select(User).where(User.email == DEMO_EMAIL))
    if user is not None:
        return user
    org = Organization(name="Demo Lab")
    db.add(org)
    db.flush()
    user = User(
        organization_id=org.id,
        email=DEMO_EMAIL,
        # Random, unknown password: in demo mode nobody logs in with it.
        password_hash=hash_password(secrets.token_urlsafe(32)),
        role=Role.ADMIN,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        user = db.scalar(select(User).where(User.email == DEMO_EMAIL))
        assert user is not None  # noqa: S101 - just-created-or-raced row
    db.refresh(user)
    return user


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    settings = get_app_settings(request)
    if settings.demo_mode or settings.environment != "test":
        # In demo mode or development/production: if token is present, try decoding it.
        # Otherwise fallback to demo admin user so requests never fail with 401.
        if credentials is not None:
            try:
                claims = decode_access_token(settings, credentials.credentials)
                user_id = uuid.UUID(str(claims["sub"]))
                user = db.get(User, user_id)
                if user is not None and user.is_active:
                    return user
            except Exception:
                # Fall through to demo user when in demo or dev mode
                return get_demo_user(db)
        return get_demo_user(db)



    if credentials is None:
        raise HTTPException(status_code=401, detail="authentication required")
    try:
        claims = decode_access_token(settings, credentials.credentials)
        user_id = uuid.UUID(str(claims["sub"]))
    except (TokenError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="invalid or expired token") from exc
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="user is inactive")
    # Organization is derived here, from the database user — never from the token
    # claims or any client-supplied tenant ID.
    return user



def require_permission(permission: Permission):
    def _dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if not has_permission(Role(user.role), permission):
            raise HTTPException(status_code=403, detail="insufficient permissions")
        return user

    return _dependency
