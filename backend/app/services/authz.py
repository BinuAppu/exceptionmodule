from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.errors import AuthenticationError, AuthorizationError
from app.db.session import get_db
from app.models import Permission, Role, RolePermission, User, UserRole


@dataclass(frozen=True)
class Principal:
    user: User
    roles: frozenset[str]
    permissions: frozenset[str]
    session_id: uuid.UUID
    is_authenticated: bool = True

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        resource, _, action = permission.partition(".")
        if action and f"{resource}.*" in self.permissions:
            return True
        if resource and f"*.{action}" in self.permissions:
            return True
        return False


class AnonymousPrincipal:
    roles = frozenset[str]()
    permissions = frozenset[str]()
    is_authenticated = False

    @property
    def user(self) -> None:
        return None

    def has_role(self, _: str) -> bool:
        return False

    def has_permission(self, _: str) -> bool:
        return False


def load_principal(db: DbSession, user: User, session_id: uuid.UUID) -> Principal:
    role_codes = set(
        db.scalars(
            select(Role.code)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user.id, Role.is_active.is_(True))
        )
    )
    permissions = set(
        db.scalars(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == RolePermission.role_id)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user.id, Role.is_active.is_(True))
        )
    )
    # Admin is a superset for system administration but does not fabricate an approval assignment.
    if "admin" in role_codes:
        permissions.add("*")
    return Principal(
        user=user,
        roles=frozenset(role_codes),
        permissions=frozenset(permissions),
        session_id=session_id,
    )


def require_permission(permission: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not principal.has_permission(permission):
            raise AuthorizationError("You do not have permission to perform this action")
        return principal

    return dependency


def require_role(*roles: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not principal.is_authenticated or not any(principal.has_role(role) for role in roles):
            raise AuthorizationError("Your role does not permit this action")
        return principal

    return dependency


def require_self_or_permission(permission: str, user_id_field: str) -> Callable[..., Principal]:
    """Dependency factory for routes where object authorization is completed in the service."""

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not principal.is_authenticated:
            raise AuthenticationError()
        return principal

    return dependency


def get_current_principal(
    request: Request,
    db: DbSession = Depends(get_db),
) -> Principal:
    # Imported lazily to avoid an auth/authz import cycle.
    from app.services.authentication import authenticate_session

    session_token = request.cookies.get(request.app.state.settings.session_cookie_name)
    if not session_token:
        raise AuthenticationError()
    principal = authenticate_session(db, request, session_token)
    if principal.user.must_change_password:
        allowed_paths = {
            f"{request.app.state.settings.api_prefix}/auth/me",
            f"{request.app.state.settings.api_prefix}/auth/change-password",
            f"{request.app.state.settings.api_prefix}/auth/logout",
        }
        if request.url.path not in allowed_paths:
            raise AuthorizationError("Password change is required before using the workspace")
    return principal
