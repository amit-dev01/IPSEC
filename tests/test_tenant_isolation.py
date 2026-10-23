import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ipsec_analyzer.db.base import Base
from ipsec_analyzer.db.repository import get_capture_for_tenant
from ipsec_analyzer.models import Capture, Tenant, User


def test_capture_lookup_is_tenant_scoped() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    user_id, capture_id = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as db:
        db.add_all([Tenant(id=tenant_a, name="a"), Tenant(id=tenant_b, name="b")])
        db.add(User(id=user_id, tenant_id=tenant_a, email="a@example.test"))
        db.add(
            Capture(
                id=capture_id,
                tenant_id=tenant_a,
                uploaded_by=user_id,
                object_key="k",
                sha256="0" * 64,
                size_bytes=1,
            )
        )
        db.commit()
        assert get_capture_for_tenant(db, tenant_a, capture_id) is not None
        assert get_capture_for_tenant(db, tenant_b, capture_id) is None
