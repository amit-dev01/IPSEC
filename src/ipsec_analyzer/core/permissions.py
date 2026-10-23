"""Roles and explicit permissions.

Authorization rule: the organization is always derived from the authenticated
user's database row. A tenant/organization ID in a request body, query, or URL is
never trusted — resource queries are scoped by the derived organization and
cross-tenant access returns 404.
"""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(StrEnum):
    CAPTURES_READ = "captures:read"
    CAPTURES_WRITE = "captures:write"
    CAPTURES_DELETE = "captures:delete"
    ANALYSES_READ = "analyses:read"
    ANALYSES_WRITE = "analyses:write"
    REPORTS_READ = "reports:read"
    REPORTS_DOWNLOAD = "reports:download"
    USERS_MANAGE = "users:manage"
    ORG_ADMIN = "org:admin"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.ANALYST: frozenset(
        {
            Permission.CAPTURES_READ,
            Permission.CAPTURES_WRITE,
            Permission.ANALYSES_READ,
            Permission.ANALYSES_WRITE,
            Permission.REPORTS_READ,
            Permission.REPORTS_DOWNLOAD,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Permission.CAPTURES_READ,
            Permission.ANALYSES_READ,
            Permission.REPORTS_READ,
            Permission.REPORTS_DOWNLOAD,
        }
    ),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
