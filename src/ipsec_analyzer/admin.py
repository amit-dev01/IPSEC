"""Admin CLI — the only way to bootstrap users (no public registration).

Usage:
    ipsec-admin create-org-admin --organization "Acme" --email admin@example.com
    # password read from IPSEC_ADMIN_PASSWORD or prompted via getpass (never logged)

    ipsec-admin create-user --organization-id <uuid> --email a@example.com --role analyst
"""

import argparse
import getpass
import os
import sys
import uuid

from sqlalchemy import select

from ipsec_analyzer.core.permissions import Role
from ipsec_analyzer.core.security import hash_password
from ipsec_analyzer.db.session import SessionLocal
from ipsec_analyzer.models import Organization, User


def _password(args_password_env: bool = True) -> str:
    password = os.environ.get("IPSEC_ADMIN_PASSWORD") if args_password_env else None
    if not password:
        password = getpass.getpass("Password (min 12 chars): ")
        if getpass.getpass("Confirm password: ") != password:
            raise SystemExit("passwords do not match")
    if len(password) < 12:
        raise SystemExit("password must be at least 12 characters")
    return password


def create_org_admin(
    organization_name: str, email: str, password: str, session_factory=SessionLocal
) -> tuple[Organization, User]:
    with session_factory() as db:
        org = Organization(name=organization_name)
        db.add(org)
        db.flush()
        admin = User(
            organization_id=org.id,
            email=email.strip().lower(),
            password_hash=hash_password(password),
            role=Role.ADMIN,
        )
        db.add(admin)
        db.commit()
        db.refresh(org)
        db.refresh(admin)
        return org, admin


def create_user(
    organization_id: uuid.UUID,
    email: str,
    role: Role,
    password: str,
    session_factory=SessionLocal,
) -> User:
    with session_factory() as db:
        org = db.get(Organization, organization_id)
        if org is None:
            raise SystemExit("organization not found")
        existing = db.scalar(
            select(User).where(User.organization_id == org.id, User.email == email.strip().lower())
        )
        if existing is not None:
            raise SystemExit("user already exists in this organization")
        user = User(
            organization_id=org.id,
            email=email.strip().lower(),
            password_hash=hash_password(password),
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ipsec-admin")
    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("create-org-admin", help="create an organization and its first admin")
    p1.add_argument("--organization", required=True)
    p1.add_argument("--email", required=True)

    p2 = sub.add_parser("create-user", help="create a user in an existing organization")
    p2.add_argument("--organization-id", required=True, type=uuid.UUID)
    p2.add_argument("--email", required=True)
    p2.add_argument("--role", choices=[r.value for r in Role], default=Role.VIEWER.value)

    args = parser.parse_args(argv)
    password = _password()
    if args.command == "create-org-admin":
        org, admin = create_org_admin(args.organization, args.email, password)
        print(f"organization_id={org.id} admin_user_id={admin.id}")  # IDs only, no secrets
    else:
        user = create_user(args.organization_id, args.email, Role(args.role), password)
        print(f"user_id={user.id} organization_id={user.organization_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
