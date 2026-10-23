"""Password hashing (Argon2id) and signed access tokens (JWT).

Passwords, tokens, and authorization headers must never be logged — callers log
only user/org IDs and outcome codes.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from ipsec_analyzer.core.config import Settings

_password_hash = PasswordHash((Argon2Hasher(),))

# Verified (and discarded) when a login email does not exist, to blunt
# user-enumeration timing differences.
_DUMMY_HASH = _password_hash.hash("dummy-password-never-used")


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _password_hash.verify(password, password_hash)


def verify_dummy(password: str) -> None:
    _password_hash.verify(password, _DUMMY_HASH)


def create_access_token(settings: Settings, user_id: uuid.UUID, organization_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "org": str(organization_id),  # informational; org is re-derived from the DB user
        "iss": settings.auth_issuer,
        "aud": settings.auth_audience,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, settings.signing_key, algorithm=settings.jwt_algorithm)


class TokenError(Exception):
    """Any token validation failure (signature, iss, aud, exp, claims)."""


def decode_access_token(settings: Settings, token: str) -> dict:
    try:
        claims = jwt.decode(
            token,
            settings.signing_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.auth_issuer,
            audience=settings.auth_audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("invalid token") from exc
    if claims.get("type") != "access":
        raise TokenError("wrong token type")
    return claims
