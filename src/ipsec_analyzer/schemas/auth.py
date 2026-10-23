import uuid

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Local login. This is NOT the OAuth2 resource-owner password grant:
    a plain JSON endpoint that issues a short-lived signed access token."""

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    # Optional disambiguation only. It is never trusted: the organization is
    # derived from the user row whose credentials actually verify.
    organization_id: uuid.UUID | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - token type label, not a secret
    expires_in: int  # seconds


class MeResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    role: str
