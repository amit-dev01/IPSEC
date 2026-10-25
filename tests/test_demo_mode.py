"""Demo Mode: get_demo_user creates one admin, idempotently; flag off by default."""

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from ipsec_analyzer.api.deps import get_demo_user
from ipsec_analyzer.core.config import Settings
from ipsec_analyzer.db.base import Base
from ipsec_analyzer.models import Organization, User


def _factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Organization.__table__, User.__table__])
    return sessionmaker(bind=engine)


def test_demo_user_created_once_with_admin_role() -> None:
    factory = _factory()
    with factory() as db:
        user = get_demo_user(db)
        assert user.email == "demo@ipsec.lab"
        assert str(user.role) in ("admin", "Role.ADMIN")
        assert user.password_hash  # random unknown password, hashed
        org_id = user.organization_id
    with factory() as db:
        again = get_demo_user(db)
        assert again.organization_id == org_id
        assert len(db.scalars(select(User)).all()) == 1


def test_demo_mode_off_by_default() -> None:
    assert Settings().demo_mode is False
