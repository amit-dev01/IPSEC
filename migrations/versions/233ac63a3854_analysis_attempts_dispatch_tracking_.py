"""analysis attempts dispatch tracking queued status

Revision ID: 233ac63a3854
Revises: bc778301da0c
Create Date: 2026-10-23 18:48:04.217676
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "233ac63a3854"
down_revision: str | None = "bc778301da0c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS_VALUES = "'queued','pending','running','succeeded','failed','unavailable','cancelled'"


def upgrade() -> None:
    op.add_column(
        "analysis_runs", sa.Column("attempts", sa.Integer(), server_default="0", nullable=False)
    )
    op.add_column(
        "analysis_runs",
        sa.Column("dispatch_attempts", sa.Integer(), server_default="0", nullable=False),
    )
    # The initial migration's VARCHAR enum never created its CHECK constraint;
    # add it explicitly, including the new 'queued' state.
    op.create_check_constraint(
        "ck_analysis_status_values",
        "analysis_runs",
        f"status IN ({_STATUS_VALUES})",
    )


def downgrade() -> None:
    op.drop_constraint("ck_analysis_status_values", "analysis_runs", type_="check")
    op.drop_column("analysis_runs", "dispatch_attempts")
    op.drop_column("analysis_runs", "attempts")
