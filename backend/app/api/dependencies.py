from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session as DbSession

from app.core.errors import AuthorizationError
from app.core.security import verify_password
from app.db.session import get_db
from app.models import Session
from app.schemas.common import AuditContext
from app.services.authz import Principal, get_current_principal
from app.services.rate_limit import client_ip, enforce_rate_limit


def audit_context(request: Request, principal: Principal = Depends(get_current_principal)) -> AuditContext:
    return AuditContext(
        actor_id=str(principal.user.id),
        actor_label=principal.user.email,
        source_ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        request_id=getattr(request.state, "request_id", None),
        correlation_id=request.state.correlation_id,
    )


def require_reauthentication(
    request: Request,
    reauthentication_password: str | None = Header(
        default=None, alias="X-Reauthentication-Password"
    ),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> bool:
    session = db.get(Session, principal.session_id)
    if session is None:
        raise AuthorizationError("Re-authentication could not be verified")
    if session.identity_provider == "local_break_glass":
        if not reauthentication_password or not principal.user.password_hash:
            raise AuthorizationError("Current break-glass password is required")
        if not verify_password(principal.user.password_hash, reauthentication_password):
            raise AuthorizationError("Re-authentication password is invalid")
        return True
    created_at = session.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if created_at < datetime.now(UTC) - timedelta(minutes=5):
        raise AuthorizationError("A fresh high-assurance SSO sign-in is required")
    required_acr = request.app.state.settings.oidc_high_assurance_acr
    try:
        from app.services.sso import get_effective_sso_config

        active_sso = get_effective_sso_config(db, request.app.state.settings)
        if not active_sso.bootstrap and active_sso.provider == "oidc":
            required_acr = active_sso.required_acr or required_acr
    except Exception as exc:
        # The step-up dependency must fail closed if the active policy cannot
        # be read; never fall back to a weaker environment-only policy.
        raise AuthorizationError("Step-up policy could not be verified") from exc
    if required_acr and session.assurance_level != required_acr:
        raise AuthorizationError("The required SSO authentication assurance level was not met")
    methods = {str(item).casefold() for item in (session.auth_methods or [])}
    if not methods or not (methods & {"mfa", "otp", "fido2", "webauthn", "swk", "hwk"}):
        raise AuthorizationError("MFA is required for this administrative operation")
    return True


def enforce_api_rate_limit(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> Principal:
    enforce_rate_limit(
        db,
        scope="api",
        identity=f"{principal.user.id}:{client_ip(request)}",
        limit=request.app.state.settings.api_rate_limit_per_minute,
        window_seconds=60,
        block_seconds=60,
    )
    return principal
