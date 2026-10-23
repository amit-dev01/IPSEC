"""user password hash and role

Revision ID: bc778301da0c
Revises: 195bae96ce19
Create Date: 2026-10-23 18:32:31.938093
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "bc778301da0c"
down_revision: str | None = "195bae96ce19"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.String(length=255), nullable=False))
    op.add_column(
        "users",
        sa.Column(
            "role",
            sa.Enum("admin", "analyst", "viewer", name="user_role", native_enum=False, length=32),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "role")
    op.drop_column("users", "password_hash")
