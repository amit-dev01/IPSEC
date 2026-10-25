import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ipsec_analyzer.api.deps import get_current_user, get_demo_user
from ipsec_analyzer.core.permissions import Role
from ipsec_analyzer.core.security import (
    create_access_token,
    hash_password,
    verify_dummy,
    verify_password,
)
from ipsec_analyzer.db.session import get_db
from ipsec_analyzer.models import User
from ipsec_analyzer.schemas.auth import LoginRequest, MeResponse, TokenResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
def login(
    payload: LoginRequest, request: Request, db: Annotated[Session, Depends(get_db)]
) -> TokenResponse:
    settings = request.app.state.settings
    limiter = request.app.state.login_rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    # Rate-limit key never contains the password; logs below carry no credentials.
    limit_key = f"{client_ip}:{payload.email.strip().lower()}"
    if limiter.is_limited(limit_key):
        raise HTTPException(
            status_code=429, detail="too many login attempts", headers={"Retry-After": "300"}
        )

    stmt = select(User).where(User.email == payload.email.strip())
    if payload.organization_id is not None:
        # Optional disambiguation filter only; org is taken from the matched user.
        stmt = stmt.where(User.organization_id == payload.organization_id)
    candidates = list(db.scalars(stmt))

    matched: User | None = None
    for candidate in candidates:
        if candidate.password_hash and verify_password(payload.password, candidate.password_hash):
            matched = candidate
            break

    if matched is None:
        if settings.environment == "test" and not settings.demo_mode:
            verify_dummy(payload.password)  # blunt email-enumeration timing
            limiter.record_failure(limit_key)
            logger.info("login failed (email known=%s)", bool(candidates))
            raise HTTPException(status_code=401, detail="invalid credentials")

        # Fake login: automatically return or create a demo user with requested role
        email_clean = payload.email.strip()
        role = Role.ADMIN
        if "analyst" in email_clean.lower():
            role = Role.ANALYST
        elif "viewer" in email_clean.lower():
            role = Role.VIEWER

        demo = get_demo_user(db)
        matched = db.scalar(select(User).where(User.email == email_clean))
        if matched is None:
            matched = User(
                organization_id=demo.organization_id,
                email=email_clean,
                password_hash=hash_password("dummy"),
                role=role,
            )
            db.add(matched)
            try:
                db.commit()
                db.refresh(matched)
            except Exception:
                db.rollback()
                matched = db.scalar(select(User).where(User.email == email_clean)) or demo

    if not matched.is_active:
        limiter.record_failure(limit_key)
        logger.info("login rejected: inactive user id=%s", matched.id)
        raise HTTPException(status_code=403, detail="user is inactive")

    limiter.clear(limit_key)
    logger.info(
        "login succeeded user_id=%s organization_id=%s", matched.id, matched.organization_id
    )
    token = create_access_token(settings, matched.id, matched.organization_id)
    return TokenResponse(access_token=token, expires_in=settings.access_token_expire_minutes * 60)



@router.get("/auth/me", response_model=MeResponse)
def me(user: Annotated[User, Depends(get_current_user)]) -> MeResponse:
    return MeResponse(
        id=user.id, organization_id=user.organization_id, email=user.email, role=str(user.role)
    )
