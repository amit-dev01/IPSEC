"""Authentication/authorization dependencies.

Only /api/v1/health/* (and dev docs when explicitly enabled) are unauthenticated.
Everything else goes through get_current_user. Blocking DB work: this module is
used from sync `def` endpoints/dependencies.
"""

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.core.permissions import Permission, Role, has_permission
from ipsec_analyzer.core.security import TokenError, decode_access_token
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import User

_bearer = HTTPBearer(auto_error=False)


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="authentication required")
    settings = get_app_settings(request)
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
