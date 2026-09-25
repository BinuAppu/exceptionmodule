from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.correlation import get_correlation_id
from app.core.errors import AuthenticationError, AuthorizationError
from app.core.security import (
    generate_opaque_token,
    hash_password,
    hash_token,
    session_expiry,
    verify_password,
)
from app.models import LocalRecoveryCode, Session, User
from app.schemas.common import AuditContext
from app.services.audit import record_audit
from app.services.authz import Principal, load_principal
from app.services.rate_limit import client_ip, enforce_rate_limit

logger = logging.getLogger(__name__)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _context(request: Request, actor: User | None = None) -> AuditContext:
    return AuditContext(
        actor_id=str(actor.id) if actor else None,
        actor_label=actor.email if actor else None,
        source_ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        request_id=getattr(request.state, "request_id", None),
        correlation_id=getattr(request.state, "correlation_id", get_correlation_id()),
    )


def _check_csrf(request: Request, session: Session) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    header = request.headers.get("X-CSRF-Token", "")
    cookie = request.cookies.get("em_csrf", "")
    if not header or not cookie or not secrets.compare_digest(header, cookie):
        raise AuthorizationError("CSRF validation failed")
    if not secrets.compare_digest(hash_token(header), session.csrf_token_hash):
        raise AuthorizationError("CSRF token is invalid")


def _create_session(
    db: DbSession,
    request: Request,
    user: User,
    provider: str,
    *,
    auth_time: datetime | None = None,
    assurance_level: str | None = None,
    auth_methods: list[str] | None = None,
) -> tuple[Session, str, str]:
    raw_session = generate_opaque_token(48)
    raw_csrf = generate_opaque_token(32)
    idle_expiry, absolute_expiry = session_expiry(request.app.state.settings)
    session = Session(
        user_id=user.id,
        token_hash=hash_token(raw_session),
        csrf_token_hash=hash_token(raw_csrf),
        source_ip=client_ip(request),
        created_ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        identity_provider=provider,
        auth_time=auth_time,
        assurance_level=assurance_level,
        auth_methods=auth_methods,
        idle_expires_at=idle_expiry,
        absolute_expires_at=absolute_expiry,
        last_seen_at=datetime.now(UTC),
    )
    db.add(session)
    # Limit concurrent sessions per user, revoking oldest first.
    active = list(
        db.scalars(
            select(Session)
            .where(Session.user_id == user.id, Session.revoked_at.is_(None))
            .order_by(Session.created_at.desc())
        )
    )
    limit = request.app.state.settings.concurrent_session_limit
    for old in active[limit - 1 :]:
        old.revoked_at = datetime.now(UTC)
        old.revoked_reason = "concurrent_session_limit"
    db.flush()
    return session, raw_session, raw_csrf


def _set_session_cookies(response: Response, settings: Settings, raw_session: str, raw_csrf: str) -> None:
    max_age = settings.session_absolute_minutes * 60
    response.set_cookie(
        settings.session_cookie_name,
        raw_session,
        max_age=max_age,
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    # Readable only to same-origin JavaScript so it can send the double-submit header.
    response.set_cookie(
        "em_csrf",
        raw_csrf,
        max_age=max_age,
        secure=settings.session_cookie_secure,
        httponly=False,
        samesite="strict",
        path="/",
    )


def _session_response(db: DbSession, user: User, roles: list[str], permissions: list[str], csrf: str, session: Session) -> dict[str, Any]:
    return {
        "user": user,
        "roles": roles,
        "permissions": permissions,
        "csrf_token": csrf,
        "idle_expires_at": session.idle_expires_at,
        "absolute_expires_at": session.absolute_expires_at,
    }


def login_local(db: DbSession, request: Request, response: Response, username: str, password: str) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    normalized = username.strip().casefold()
    enforce_rate_limit(
        db,
        scope="local_login_ip",
        identity=client_ip(request),
        limit=settings.login_failure_threshold * 3,
        window_seconds=900,
        block_seconds=settings.login_lockout_minutes * 60,
    )
    user = db.scalar(
        select(User).where(
            (func.lower(User.email_normalized) == normalized) | (User.public_id == username.strip()),
            User.is_break_glass.is_(True),
        )
    )
    generic_failure = "Invalid credentials or account unavailable"
    if user is None or user.status != "active" or user.password_hash is None:
        record_audit(
            db,
            _context(request),
            action="auth.local.failure",
            object_type="user",
            object_id=str(user.id) if user else None,
            result="failure",
            failure_reason=generic_failure,
        )
        db.commit()
        raise AuthenticationError(generic_failure)
    now = datetime.now(UTC)
    locked_until = _aware(user.locked_until)
    if locked_until and locked_until > now:
        record_audit(
            db,
            _context(request, user),
            action="auth.local.locked",
            object_type="user",
            object_id=str(user.id),
            result="denied",
            failure_reason="account_locked",
        )
        db.commit()
        raise AuthenticationError(generic_failure)
    if not verify_password(user.password_hash, password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_failure_threshold:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.status = "locked" if user.is_break_glass else user.status
        record_audit(
            db,
            _context(request, user),
            action="auth.local.failure",
            object_type="user",
            object_id=str(user.id),
            result="failure",
            failure_reason="invalid_credentials",
        )
        db.commit()
        raise AuthenticationError(generic_failure)
    user.failed_login_count = 0
    user.locked_until = None
    user.status = "active"
    user.last_login_at = now
    session, raw_session, raw_csrf = _create_session(db, request, user, "local_break_glass")
    record_audit(db, _context(request, user), action="auth.local.success", object_type="user", object_id=str(user.id))
    db.commit()
    _set_session_cookies(response, settings, raw_session, raw_csrf)
    principal = load_principal(db, user, session.id)
    return _session_response(
        db, user, sorted(principal.roles), sorted(principal.permissions), raw_csrf, session
    )


def authenticate_session(db: DbSession, request: Request, raw_session: str) -> Principal:
    session = db.scalar(select(Session).where(Session.token_hash == hash_token(raw_session)))
    if session is None or session.revoked_at is not None:
        raise AuthenticationError()
    now = datetime.now(UTC)
    if _aware(session.idle_expires_at) <= now or _aware(session.absolute_expires_at) <= now:
        session.revoked_at = now
        session.revoked_reason = "expired"
        db.commit()
        raise AuthenticationError("Your session has expired")
    user = db.get(User, session.user_id)
    if user is None or user.status != "active" or user.disabled_at:
        session.revoked_at = now
        db.commit()
        raise AuthenticationError()
    _check_csrf(request, session)
    session.last_seen_at = now
    # Extend idle expiry only within the absolute lifetime.
    session.idle_expires_at = min(
        _aware(session.absolute_expires_at),
        now + timedelta(minutes=request.app.state.settings.session_idle_minutes),
    )
    db.commit()
    return load_principal(db, user, session.id)


def logout(db: DbSession, request: Request, response: Response, principal: Principal) -> None:
    session = db.get(Session, principal.session_id)
    if session:
        session.revoked_at = datetime.now(UTC)
        session.revoked_reason = "user_logout"
        record_audit(
            db,
            _context(request, principal.user),
            action="auth.logout",
            object_type="user",
            object_id=str(principal.user.id),
        )
    db.commit()
    response.delete_cookie(request.app.state.settings.session_cookie_name, path="/")
    response.delete_cookie("em_csrf", path="/")
    return {"message": "Signed out"}


def change_local_password(
    db: DbSession, request: Request, response: Response, principal: Principal, current: str, new: str
) -> dict[str, Any]:
    user = principal.user
    if user.password_hash is None or not verify_password(user.password_hash, current):
        record_audit(
            db,
            _context(request, user),
            action="auth.password_change",
            object_type="user",
            object_id=str(user.id),
            result="failure",
            failure_reason="current_password_invalid",
        )
        db.commit()
        raise AuthenticationError("Current password is invalid")
    if current == new:
        raise AuthenticationError("New password must differ from the current password")
    try:
        user.password_hash = hash_password(new)
    except ValueError as exc:
        raise AuthenticationError(str(exc)) from exc
    user.must_change_password = False
    user.version += 1
    # Rotate the session and invalidate all other sessions after a credential change.
    for old in db.scalars(select(Session).where(Session.user_id == user.id, Session.id != principal.session_id)):
        old.revoked_at = datetime.now(UTC)
        old.revoked_reason = "password_changed"
    record_audit(db, _context(request, user), action="auth.password_changed", object_type="user", object_id=str(user.id))
    db.commit()
    # Require a fresh login rather than keeping a session associated with the old credential.
    response.delete_cookie(request.app.state.settings.session_cookie_name, path="/")
    response.delete_cookie("em_csrf", path="/")
    return {"message": "Password changed; sign in with the new password"}


def _oidc_client(settings: Settings, config: DbSession | None = None):
    """Compatibility helper for callers that still request an Authlib client.

    Runtime login uses the version-bound DB snapshot.  This helper intentionally
    returns only a disabled environment client for diagnostics and is never a
    source of authorization.
    """

    if config is None:
        raise AuthenticationError("Enterprise SSO is not configured")
    from app.services.sso import _client_for_config, get_effective_sso_config

    return _client_for_config(get_effective_sso_config(config, settings), settings, config)


async def begin_oidc_login(db: DbSession, request: Request) -> tuple[str, Any]:
    from app.services.sso import begin_oidc_transaction, get_enabled_login_config

    snapshot = get_enabled_login_config(db, request.app.state.settings)
    if snapshot.provider != "oidc":
        raise AuthenticationError("OIDC SSO is not active")
    _client, secret, url = await begin_oidc_transaction(db, request, snapshot)
    # Retain the historical tuple shape while returning the browser binding to
    # the route, which must set it on the exact RedirectResponse it returns.
    return url, secret


def _finalize_external_session(
    db: DbSession,
    request: Request,
    response: Response,
    user: User,
    *,
    provider: str,
    auth_time: datetime | None,
    assurance_level: str | None,
    auth_methods: list[str] | None,
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    session, raw_session, raw_csrf = _create_session(
        db,
        request,
        user,
        provider,
        auth_time=auth_time,
        assurance_level=assurance_level,
        auth_methods=auth_methods,
    )
    record_audit(
        db,
        _context(request, user),
        action="auth.sso.success",
        object_type="user",
        object_id=str(user.id),
        new_value={"provider": provider},
    )
    db.commit()
    # This is deliberately the same response object returned by the route.
    _set_session_cookies(response, settings, raw_session, raw_csrf)
    principal = load_principal(db, user, session.id)
    return {
        **_session_response(db, user, sorted(principal.roles), sorted(principal.permissions), raw_csrf, session),
        "return_path": getattr(response, "_sso_return_path", "/"),
    }


async def complete_oidc_login(
    db: DbSession, request: Request, response: Response, code: str, state: str
) -> dict[str, Any]:
    import base64
    import json as json_module

    from app.services.sso import (
        OIDC_ALLOWED_ALGORITHMS,
        _client_for_config,
        claim_transaction,
        get_enabled_login_config,
        invalidate_transaction,
        provision_sso_user,
        validate_oidc_claims,
        verify_browser_binding,
    )

    settings: Settings = request.app.state.settings
    config = get_enabled_login_config(db, settings)
    if config.provider != "oidc":
        raise AuthenticationError("OIDC SSO is not active")
    if not code or len(code) > 4096 or not state or len(state) > 1024:
        raise AuthenticationError("SSO login transaction is invalid or expired")
    transaction, envelope, _ = claim_transaction(
        db,
        lookup_field="state_hash",
        raw_value=state,
        config=config,
        transaction_type="oidc",
        settings=settings,
    )
    if not verify_browser_binding(request, transaction):
        invalidate_transaction(db, transaction.id, "browser_binding")
        raise AuthenticationError("SSO login transaction is invalid or expired")
    nonce = str(envelope.get("nonce") or "")
    verifier = str(envelope.get("pkce_verifier") or "")
    if (
        not nonce
        or not verifier
        or not secrets.compare_digest(hash_token(nonce), transaction.nonce_hash or "")
        or not secrets.compare_digest(hash_token(verifier), transaction.pkce_verifier_hash or "")
        or envelope.get("config_id") != str(config.config_id)
    ):
        invalidate_transaction(db, transaction.id, "invalid_payload")
        raise AuthenticationError("SSO login transaction is invalid or expired")
    metadata = envelope.get("metadata") if isinstance(envelope.get("metadata"), dict) else None
    if not metadata or metadata.get("issuer") != config.issuer:
        invalidate_transaction(db, transaction.id, "metadata_mismatch")
        raise AuthenticationError("SSO identity validation failed")
    advertised_algorithms = set(metadata.get("id_token_signing_alg_values_supported") or ["RS256"])
    if not advertised_algorithms.intersection(OIDC_ALLOWED_ALGORITHMS):
        invalidate_transaction(db, transaction.id, "unsupported_algorithm")
        raise AuthenticationError("SSO identity validation failed")
    client = _client_for_config(config, settings, db, metadata)
    try:
        token = await client.fetch_access_token(
            str(envelope.get("redirect_uri") or config.redirect_uri),
            code=code,
            code_verifier=verifier,
        )
        id_token = token.get("id_token") if isinstance(token, dict) else None
        if not id_token:
            raise AuthenticationError("SSO identity validation failed")
        # Algorithm agility is constrained to asymmetric signing algorithms.
        # Authlib still performs the actual JWS signature validation below.
        header_segment = str(id_token).split(".", 1)[0]
        padded = header_segment + "=" * (-len(header_segment) % 4)
        header = json_module.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        algorithm = str(header.get("alg") or "")
        if algorithm not in OIDC_ALLOWED_ALGORITHMS or algorithm not in advertised_algorithms:
            raise AuthenticationError("SSO identity validation failed")
        parsed = await client.parse_id_token(
            token,
            nonce=nonce,
            claims_options={"iss": {"values": [config.issuer]}},
        )
        claims = dict(parsed)
        subject, email, display_name = validate_oidc_claims(claims, config, nonce, settings)
        auth_time = None
        if claims.get("auth_time") is not None:
            auth_time = datetime.fromtimestamp(int(claims["auth_time"]), UTC)
        amr = claims.get("amr") or []
        if isinstance(amr, str):
            amr = [amr]
        user = provision_sso_user(db, config, subject, email, display_name)
    except AuthenticationError:
        invalidate_transaction(db, transaction.id, "oidc_validation_failed")
        raise
    except Exception as exc:
        invalidate_transaction(db, transaction.id, "oidc_validation_failed")
        raise AuthenticationError("SSO identity validation failed") from exc
    setattr(response, "_sso_return_path", _safe_external_path(transaction.return_path))
    return _finalize_external_session(
        db,
        request,
        response,
        user,
        provider="oidc",
        auth_time=auth_time,
        assurance_level=str(claims.get("acr")) if claims.get("acr") else None,
        auth_methods=[str(item) for item in amr][:20],
    )


def _safe_external_path(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if value.casefold().replace("%2f", "/").startswith("//"):
        return "/"
    return value[:255]


def recover_break_glass(
    db: DbSession, request: Request, response: Response, username: str, recovery_code: str, new_password: str
) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    enforce_rate_limit(db, scope="break_glass_recovery_ip", identity=client_ip(request), limit=5, window_seconds=900, block_seconds=900)
    user = db.scalar(select(User).where((User.email_normalized == username.casefold()) | (User.public_id == username), User.is_break_glass.is_(True)))
    if user is None:
        raise AuthenticationError("Recovery could not be completed")
    record = db.scalar(select(LocalRecoveryCode).where(LocalRecoveryCode.user_id == user.id, LocalRecoveryCode.code_hash == hash_token(recovery_code), LocalRecoveryCode.used_at.is_(None)))
    if record is None or user.status not in {"active", "locked"}:
        record_audit(db, _context(request, user), action="auth.break_glass_recovery.failure", object_type="user", object_id=str(user.id), result="failure", failure_reason="invalid_recovery_code")
        db.commit()
        raise AuthenticationError("Recovery could not be completed")
    try:
        user.password_hash = hash_password(new_password)
    except ValueError as exc:
        raise AuthenticationError(str(exc)) from exc
    record.used_at = datetime.now(UTC)
    record.used_from_ip = client_ip(request)
    user.must_change_password = False
    user.failed_login_count = 0
    user.locked_until = None
    user.status = "active"
    for old in db.scalars(select(Session).where(Session.user_id == user.id)):
        old.revoked_at = now = datetime.now(UTC)
        old.revoked_reason = "break_glass_recovery"
    record_audit(db, _context(request, user), action="auth.break_glass_recovered", object_type="user", object_id=str(user.id))
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie("em_csrf", path="/")
    return {"message": "Break-glass credential recovered; sign in with the new password"}
