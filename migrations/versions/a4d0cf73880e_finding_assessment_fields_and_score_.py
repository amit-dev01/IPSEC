"""finding assessment fields and score range

Revision ID: a4d0cf73880e
Revises: 84c75d49471f
Create Date: 2026-10-23 19:13:56.523060
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a4d0cf73880e"
down_revision: str | None = "84c75d49471f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    op.add_column("findings", sa.Column("actual_value", JSONB, nullable=True))
    op.add_column("findings", sa.Column("expected_value", JSONB, nullable=True))
    op.add_column("findings", sa.Column("policy_version", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("source_refs", JSONB, nullable=True))
    # Scores move from 0-1 to the documented 0-100 scale.
    op.drop_constraint("ck_run_risk_score_range", "analysis_runs", type_="check")
    op.drop_constraint("ck_run_security_score_range", "analysis_runs", type_="check")
    op.create_check_constraint(
        "ck_run_risk_score_range",
        "analysis_runs",
        "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
    )
    op.create_check_constraint(
        "ck_run_security_score_range",
        "analysis_runs",
        "security_score IS NULL OR (security_score >= 0 AND security_score <= 100)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_run_security_score_range", "analysis_runs", type_="check")
    op.drop_constraint("ck_run_risk_score_range", "analysis_runs", type_="check")
    op.create_check_constraint(
        "ck_run_risk_score_range",
        "analysis_runs",
        "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)",
    )
    op.create_check_constraint(
        "ck_run_security_score_range",
        "analysis_runs",
        "security_score IS NULL OR (security_score >= 0 AND security_score <= 1)",
    )
    op.drop_column("findings", "source_refs")
    op.drop_column("findings", "policy_version")
    op.drop_column("findings", "expected_value")
    op.drop_column("findings", "actual_value")
