from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.responses import RedirectResponse

from app.core.errors import AuthenticationError, DomainError
from app.db.session import get_db
from app.models import Session, User
from app.schemas.auth import (
    BreakGlassRecoveryRequest,
    LoginRequest,
    LogoutResponse,
    PasswordChangeRequest,
    SessionResponse,
)
from app.services.authentication import (
    _finalize_external_session,
    begin_oidc_login,
    change_local_password,
    complete_oidc_login,
    login_local,
    logout,
    recover_break_glass,
)
from app.services.authz import Principal, get_current_principal
from app.services.sso import (
    clear_binding_cookie,
    enforce_login_rate_limit,
    get_effective_sso_config,
    get_enabled_login_config,
    set_binding_cookie,
)

router = APIRouter(prefix="/auth", tags=["authentication"])

_SSO_FAILURE_PATH = "/login?sso_error=sso_failed"
_SSO_UNAVAILABLE_PATH = "/login?sso_error=sso_unavailable"


def _no_store_redirect(path: str, code: int = status.HTTP_303_SEE_OTHER) -> RedirectResponse:
    # Never reflect an IdP error, callback parameter, transaction value, or
    # backend exception into a redirect URL.
    response = RedirectResponse(path, status_code=code)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    clear_binding_cookie(response)
    return response


@router.get("/configuration")
def authentication_configuration(request: Request, db: DbSession = Depends(get_db)) -> dict[str, object]:
    config = get_effective_sso_config(db, request.app.state.settings)
    enabled = bool(config.enabled and not config.bootstrap)
    try:
        break_glass_available = (
            db.scalar(
                select(User.id)
                .where(User.is_break_glass.is_(True), User.status == "active")
                .limit(1)
            )
            is not None
        )
    except Exception:
        db.rollback()
        break_glass_available = False
    # This endpoint is public.  Keep it deliberately narrow: no issuer,
    # client ID, redirect URI, claims, certificates, URLs, or secret flags.
    return {
        "sso_enabled": enabled,
        "sso_provider": config.provider if enabled else None,
        "sso_display_name": config.display_name if enabled else None,
        "sso_protocol": config.provider if enabled else None,
        "local_break_glass_enabled": break_glass_available,
        "password_minimum_length": getattr(request.app.state.settings, "password_minimum_length", 14),
    }


@router.post("/login", response_model=SessionResponse)
def local_login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
) -> dict:
    return login_local(db, request, response, payload.username, payload.password)


@router.post("/recovery", response_model=LogoutResponse)
def break_glass_recovery(
    payload: BreakGlassRecoveryRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
) -> dict:
    return recover_break_glass(
        db,
        request,
        response,
        payload.username,
        payload.recovery_code,
        payload.new_password,
    )


@router.get("/sso/login")
async def sso_login(request: Request, db: DbSession = Depends(get_db)) -> Response:
    try:
        config = get_enabled_login_config(db, request.app.state.settings)
        if config.provider == "oidc":
            url, secret = await begin_oidc_login(db, request)
            response = RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
            set_binding_cookie(
                response,
                secret.browser_binding,
                request.app.state.settings,
                provider="oidc",
            )
        elif config.provider == "saml":
            from app.services.saml import begin_saml_login

            enforce_login_rate_limit(db, request)
            _client, saml_request = begin_saml_login(db, request, config)
            if not saml_request.url:
                # The configured profile requires HTTP-Redirect binding.  Do
                # not emit an unsigned auto-post form as a fallback.
                raise AuthenticationError("SAML SSO is not available")
            response = RedirectResponse(
                saml_request.url,
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
            set_binding_cookie(
                response,
                saml_request.transaction.browser_binding,
                request.app.state.settings,
                provider="saml",
            )
        else:  # Fail closed if a future provider is introduced without a flow.
            raise AuthenticationError("Enterprise SSO is not configured")
    except (AuthenticationError, DomainError):
        db.rollback()
        return _no_store_redirect(_SSO_UNAVAILABLE_PATH)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/sso/callback")
async def sso_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: DbSession = Depends(get_db),
) -> RedirectResponse:
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    if error or not code or not state:
        return _no_store_redirect(_SSO_FAILURE_PATH)
    try:
        enforce_login_rate_limit(db, request)
        db.commit()
        result = await complete_oidc_login(db, request, response, code, state)
    except (AuthenticationError, DomainError):
        db.rollback()
        return _no_store_redirect(_SSO_FAILURE_PATH)
    # Keep the same response object that received the authentication cookies.
    response.headers["Location"] = str(result.get("return_path") or "/")
    clear_binding_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.post("/sso/saml/acs")
async def saml_acs(
    request: Request,
    saml_response: str = Form(alias="SAMLResponse", min_length=1, max_length=4_000_000),
    relay_state: str | None = Form(default=None, alias="RelayState", max_length=1024),
    db: DbSession = Depends(get_db),
) -> RedirectResponse:
    from app.services.saml import complete_saml_login

    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    try:
        enforce_login_rate_limit(db, request)
        db.commit()
        result = complete_saml_login(db, request, response, saml_response, relay_state)
        session_result = _finalize_external_session(
            db,
            request,
            response,
            result["user"],
            provider="saml",
            auth_time=result.get("auth_time"),
            assurance_level=result.get("assurance_level"),
            auth_methods=list(result.get("auth_methods") or ["saml"]),
        )
    except (AuthenticationError, DomainError):
        db.rollback()
        return _no_store_redirect(_SSO_FAILURE_PATH)
    response.headers["Location"] = str(session_result.get("return_path") or result.get("return_path") or "/")
    clear_binding_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/sso/saml/metadata", include_in_schema=False)
@router.get("/sso/metadata", include_in_schema=False)
def saml_metadata(request: Request, db: DbSession = Depends(get_db)) -> Response:
    from app.services.saml import sp_metadata

    config = get_effective_sso_config(db, request.app.state.settings)
    if config.provider != "saml" or config.config_id is None:
        return Response(status_code=404, headers={"Cache-Control": "no-store"})
    try:
        content = sp_metadata(config)
    except DomainError:
        return Response(status_code=404, headers={"Cache-Control": "no-store"})
    return Response(
        content=content,
        media_type="application/samlmetadata+xml",
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.get("/me", response_model=SessionResponse)
def current_session(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    # The raw CSRF value is only returned at login. The browser already has it in a readable cookie.
    csrf = request.cookies.get("em_csrf", "")
    session = db.get(Session, principal.session_id)
    if session is None:
        return logout(db, request, Response(), principal)
    return {
        "user": principal.user,
        "roles": sorted(principal.roles),
        "permissions": sorted(principal.permissions),
        "csrf_token": csrf,
        "idle_expires_at": session.idle_expires_at,
        "absolute_expires_at": session.absolute_expires_at,
    }


@router.post("/logout", response_model=LogoutResponse)
def sign_out(
    request: Request,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    return logout(db, request, response, principal)


@router.post("/change-password", response_model=LogoutResponse)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    return change_local_password(
        db,
        request,
        response,
        principal,
        payload.current_password,
        payload.new_password,
    )
