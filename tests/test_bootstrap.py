"""Bootstrap admin: creates once, idempotent, silent when unconfigured."""

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.db.base import Base
from ipsec_analyzer.models import Organization, User
from ipsec_analyzer.services.bootstrap import ensure_bootstrap_admin


def _factory():
    engine = create_engine("sqlite:///:memory:")
    # Only the two tables bootstrap touches (full metadata has PG-only DDL).
    Base.metadata.create_all(engine, tables=[Organization.__table__, User.__table__])
    return sessionmaker(bind=engine)


def _settings(**kw) -> Settings:
    base = {
        "bootstrap_email": "Demo@IPsec.lab",
        "bootstrap_password": "correct horse battery",
        "bootstrap_organization": "Demo Lab",
    }
    base.update(kw)
    return Settings(**base)


def test_creates_org_admin_when_configured() -> None:
    factory = _factory()
    assert ensure_bootstrap_admin(_settings(), session_factory=factory) is True
    with factory() as db:
        org = db.scalar(select(Organization))
        user = db.scalar(select(User))
        assert org is not None and org.name == "Demo Lab"
        assert user is not None
        assert user.email == "demo@ipsec.lab"  # normalized
        assert str(user.role) in ("admin", "Role.ADMIN")
        assert user.password_hash != "correct horse battery"  # noqa: S105 - test fixture


def test_idempotent_second_run_is_noop() -> None:
    factory = _factory()
    assert ensure_bootstrap_admin(_settings(), session_factory=factory) is True
    assert ensure_bootstrap_admin(_settings(), session_factory=factory) is False
    with factory() as db:
        assert len(db.scalars(select(User)).all()) == 1


def test_noop_when_unconfigured() -> None:
    factory = _factory()
    assert ensure_bootstrap_admin(Settings(), session_factory=factory) is False
    assert (
        ensure_bootstrap_admin(_settings(bootstrap_password=None), session_factory=factory) is False
    )


def test_short_password_rejected() -> None:
    factory = _factory()
    assert (
        ensure_bootstrap_admin(
            _settings(bootstrap_password="short"),  # noqa: S106
            session_factory=factory,
        )
        is False
    )
