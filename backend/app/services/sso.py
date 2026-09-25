"""Runtime SSO configuration, validation, and protocol transaction support.

This module deliberately keeps protocol payloads out of the generic
``SystemConfig`` table.  The database contains versioned public settings,
write-only encrypted credentials, hashed one-time transaction values, and an
encrypted protocol envelope only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
from authlib.integrations.starlette_client import OAuth
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError, AuthorizationError, ConflictError, DomainError
from app.core.security import (
    decrypt_secret,
    encrypt_secret,
    generate_opaque_token,
    hash_token,
    public_reference,
)
from app.models import (
    Role,
    SSOExternalIdentity,
    SSOLoginTransaction,
    SSOProvider,
    SSOProviderConfig,
    SSOSecretRecord,
    User,
    UserRole,
)
from app.schemas.common import AuditContext
from app.schemas.sso import SSOConfigurationUpdate, SSOValidationResult
from app.services.audit import record_audit
from app.services.authz import Principal
from app.services.rate_limit import client_ip, enforce_rate_limit

OIDC_ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
SAML_BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
SAML_BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SSO_BINDING_COOKIE = "em_sso_binding"
SSO_TRANSACTION_TTL = timedelta(minutes=10)
MAX_DISCOVERY_BYTES = 1_000_000
MAX_SAML_RESPONSE_BYTES = 2_000_000
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class EffectiveSSOConfig:
    """A read-only view that also represents the disabled env bootstrap."""

    provider: str
    enabled: bool
    version: int
    display_name: str
    issuer: str | None = None
    client_id: str | None = None
    scopes: str = "openid profile email"
    redirect_uri: str | None = None
    required_acr: str | None = None
    email_claim: str = "email"
    name_claim: str = "name"
    tenant_claim: str | None = None
    tenant_value: str | None = None
    allowed_domains: tuple[str, ...] = ()
    auto_provision: bool = True
    idp_entity_id: str | None = None
    sso_url: str | None = None
    idp_x509_certificate: str | None = None
    email_attribute: str = "email"
    name_attribute: str = "displayName"
    sp_entity_id: str | None = None
    acs_url: str | None = None
    metadata_url: str | None = None
    provider_id: Any | None = None
    config_id: Any | None = None
    db_config: SSOProviderConfig | None = None
    bootstrap: bool = False


@dataclass(frozen=True)
class TransactionSecret:
    """Raw values exist only in this short-lived in-memory object."""

    transaction: SSOLoginTransaction
    state: str | None = None
    nonce: str | None = None
    pkce_verifier: str | None = None
    browser_binding: str = ""
    relay_state: str | None = None
    request_id: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _safe_url(
    value: str | None,
    *,
    field: str,
    allow_query: bool = False,
    require_https: bool = False,
) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if _CONTROL_RE.search(value) or " " in value:
        raise ValueError(f"{field} is not a valid URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL")
    if require_https and parsed.scheme != "https":
        raise ValueError(f"{field} must use HTTPS")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{field} contains unsupported URL components")
    if not allow_query and parsed.query:
        raise ValueError(f"{field} must not contain a query string")
    return value


def _safe_entity_id(value: str | None, *, field: str, require_https: bool = False) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if _CONTROL_RE.search(value) or " " in value or len(value) > 2048:
        raise ValueError(f"{field} is not a valid entity ID")
    parsed = urlparse(value)
    if not parsed.scheme or (parsed.scheme not in {"http", "https", "urn"}):
        raise ValueError(f"{field} is not a valid entity ID")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError(f"{field} contains unsupported entity ID components")
    if require_https and parsed.scheme == "http":
        raise ValueError(f"{field} must use HTTPS")
    return value


def _domain_allowed(email: str, domains: tuple[str, ...] | list[str]) -> bool:
    if not domains:
        return True
    try:
        domain = email.rsplit("@", 1)[1].casefold().rstrip(".")
    except IndexError:
        return False
    return domain in {item.casefold().rstrip(".") for item in domains}


def _safe_return_path(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    normalized = value.casefold().replace("%2f", "/")
    if normalized.startswith("//") or _CONTROL_RE.search(value) or len(value) > 255:
        return "/"
    return value


def _config_from_row(row: SSOProviderConfig, provider: SSOProvider) -> EffectiveSSOConfig:
    return EffectiveSSOConfig(
        provider=provider.provider,
        enabled=bool(row.enabled and row.is_active),
        version=row.version,
        display_name=row.display_name,
        issuer=row.issuer,
        client_id=row.client_id,
        scopes=row.scopes,
        redirect_uri=row.redirect_uri,
        required_acr=row.required_acr,
        email_claim=row.email_claim,
        name_claim=row.name_claim,
        tenant_claim=row.tenant_claim,
        tenant_value=row.tenant_value,
        allowed_domains=tuple(str(item).casefold() for item in (row.allowed_domains or [])),
        auto_provision=bool(row.auto_provision),
        idp_entity_id=row.idp_entity_id,
        sso_url=row.sso_url,
        idp_x509_certificate=row.idp_x509_certificate,
        email_attribute=row.email_attribute,
        name_attribute=row.name_attribute,
        sp_entity_id=row.sp_entity_id,
        acs_url=row.acs_url,
        metadata_url=row.metadata_url,
        provider_id=provider.id,
        config_id=row.id,
        db_config=row,
    )


def _env_bootstrap(settings: Settings) -> EffectiveSSOConfig:
    # Environment OIDC values are intentionally not an enabled login source.
    # They are retained only so an operator can see the bootstrap settings in
    # the admin UI before creating a database configuration.
    return EffectiveSSOConfig(
        provider="oidc",
        enabled=False,
        version=0,
        display_name="Environment OIDC (disabled bootstrap)",
        issuer=getattr(settings, "oidc_issuer", None),
        client_id=getattr(settings, "oidc_client_id", None),
        scopes=getattr(settings, "oidc_scopes", "openid profile email"),
        redirect_uri=getattr(settings, "oidc_redirect_uri", None),
        required_acr=getattr(settings, "oidc_high_assurance_acr", None),
        email_claim="email",
        name_claim="name",
        allowed_domains=(),
        auto_provision=True,
        bootstrap=True,
    )


def get_effective_sso_config(db: DbSession, settings: Settings) -> EffectiveSSOConfig:
    """Return the active DB config, or a disabled environment bootstrap.

    Once *any* DB provider configuration exists, environment OIDC values are
    ignored, including when the DB configuration is disabled.  This prevents
    an old environment secret from silently re-enabling SSO after an operator
    disables the database configuration.
    """

    try:
        rows = list(
            db.execute(
                select(SSOProviderConfig, SSOProvider)
                .join(SSOProvider, SSOProvider.id == SSOProviderConfig.provider_id)
                .order_by(SSOProviderConfig.is_active.desc(), SSOProviderConfig.version.desc())
            )
        )
    except OperationalError:
        # A rolling deployment may serve a request before the new migration is
        # complete.  Failing closed is safer than activating an env provider.
        db.rollback()
        return _env_bootstrap(settings)
    if not rows:
        return _env_bootstrap(settings)
    active = [pair for pair in rows if pair[0].is_active]
    row, provider = active[0] if active else rows[0]
    return _config_from_row(row, provider)


def get_db_config_for_provider(db: DbSession, provider_name: str) -> EffectiveSSOConfig | None:
    try:
        row_pair = db.execute(
            select(SSOProviderConfig, SSOProvider)
            .join(SSOProvider, SSOProvider.id == SSOProviderConfig.provider_id)
            .where(SSOProvider.provider == provider_name)
            .order_by(SSOProviderConfig.version.desc())
        ).first()
    except OperationalError:
        db.rollback()
        return None
    return _config_from_row(row_pair[0], row_pair[1]) if row_pair else None


def get_enabled_login_config(db: DbSession, settings: Settings) -> EffectiveSSOConfig:
    config = get_effective_sso_config(db, settings)
    if config.bootstrap or not config.enabled or config.config_id is None:
        raise AuthenticationError("Enterprise SSO is not configured")
    return config


def _configured_secret(db: DbSession, config: EffectiveSSOConfig, secret_type: str) -> SSOSecretRecord | None:
    if config.config_id is None:
        return None
    return db.scalar(
        select(SSOSecretRecord).where(
            SSOSecretRecord.config_id == config.config_id,
            SSOSecretRecord.secret_type == secret_type,
            SSOSecretRecord.is_active.is_(True),
        )
    )


def get_client_secret(db: DbSession, config: EffectiveSSOConfig, settings: Settings) -> str | None:
    record = _configured_secret(db, config, "client_secret")
    if record is None:
        return None
    return decrypt_secret(record.encrypted_value, settings)


def get_signing_private_key(db: DbSession, config: EffectiveSSOConfig, settings: Settings) -> str | None:
    record = _configured_secret(db, config, "signing_private_key")
    if record is None:
        return None
    return decrypt_secret(record.encrypted_value, settings)


def _secret_flags(db: DbSession, config: EffectiveSSOConfig) -> tuple[bool, bool]:
    if config.config_id is None:
        return False, False
    return (
        _configured_secret(db, config, "client_secret") is not None,
        _configured_secret(db, config, "signing_private_key") is not None,
    )


def sanitized_sso_configuration(
    db: DbSession, settings: Settings, config: EffectiveSSOConfig | None = None
) -> dict[str, Any]:
    """Build the exact flat admin response; never include ciphertext/secrets."""

    config = config or get_effective_sso_config(db, settings)
    client_secret_configured, signing_key_configured = _secret_flags(db, config)
    return {
        "version": config.version,
        "provider": config.provider,
        "enabled": config.enabled,
        "display_name": config.display_name,
        "issuer": config.issuer,
        "client_id": config.client_id,
        "scopes": config.scopes,
        "redirect_uri": config.redirect_uri,
        "required_acr": config.required_acr,
        "email_claim": config.email_claim,
        "name_claim": config.name_claim,
        "tenant_claim": config.tenant_claim,
        "tenant_value": config.tenant_value,
        "allowed_domains": list(config.allowed_domains),
        "auto_provision": config.auto_provision,
        "idp_entity_id": config.idp_entity_id,
        "sso_url": config.sso_url,
        "idp_x509_certificate": config.idp_x509_certificate,
        "email_attribute": config.email_attribute,
        "name_attribute": config.name_attribute,
        "sp_entity_id": config.sp_entity_id,
        "acs_url": config.acs_url,
        "client_secret_configured": client_secret_configured,
        "signing_key_configured": signing_key_configured,
        "metadata_url": config.metadata_url,
        "updated_at": config.db_config.updated_at if config.db_config else None,
    }


def _validate_certificate(value: str | None) -> tuple[bool, str | None]:
    if not value:
        return False, "SAML IdP certificate is required"
    if "PRIVATE KEY" in value.upper():
        return False, "SAML IdP certificate must not contain a private key"
    try:
        normalized = value.strip()
        if "BEGIN CERTIFICATE" not in normalized:
            normalized = "-----BEGIN CERTIFICATE-----\n" + normalized + "\n-----END CERTIFICATE-----"
        cert = x509.load_pem_x509_certificate(normalized.encode("ascii"))
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                return False, "SAML IdP RSA certificate must use at least 2048 bits"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.key_size < 256:
                return False, "SAML IdP EC certificate must use at least 256 bits"
        else:
            return False, "SAML IdP certificate must use RSA or EC"
        now = _now()
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=UTC)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=UTC)
        if now < not_before or now >= not_after:
            return False, "SAML IdP certificate is expired or not yet valid"
        return True, None
    except (ValueError, TypeError, UnicodeError):
        return False, "SAML IdP certificate is invalid"


def _validate_url_fields(
    provider: str, payload: SSOConfigurationUpdate, *, require_https: bool = False
) -> list[str]:
    errors: list[str] = []
    checks = {
        "issuer": payload.issuer,
        "redirect_uri": payload.redirect_uri,
        "sso_url": payload.sso_url,
        "sp_entity_id": payload.sp_entity_id,
        "acs_url": payload.acs_url,
        "metadata_url": payload.metadata_url,
    }
    for field, value in checks.items():
        try:
            if field in {"idp_entity_id", "sp_entity_id"}:
                _safe_entity_id(value, field=field, require_https=require_https)
            else:
                _safe_url(
                    value,
                    field=field,
                    allow_query=field == "metadata_url",
                    require_https=require_https,
                )
        except ValueError as exc:
            errors.append(str(exc))
    if provider == "oidc":
        if payload.enabled:
            for field in ("issuer", "client_id", "redirect_uri"):
                if not getattr(payload, field):
                    errors.append(f"OIDC {field} is required when SSO is enabled")
            if "openid" not in payload.scopes.split():
                errors.append("OIDC scopes must include openid")
    else:
        if payload.enabled:
            for field in ("idp_entity_id", "sso_url", "idp_x509_certificate", "sp_entity_id", "acs_url"):
                if not getattr(payload, field):
                    errors.append(f"SAML {field} is required when SSO is enabled")
        ok, certificate_error = _validate_certificate(payload.idp_x509_certificate)
        if payload.idp_x509_certificate and not ok and certificate_error:
            errors.append(certificate_error)
    return errors


async def discover_oidc_metadata(
    issuer: str,
    *,
    client: httpx.AsyncClient | None = None,
    require_https: bool = False,
) -> dict[str, Any]:
    """Fetch and pin OIDC discovery metadata with strict issuer matching."""

    normalized = _safe_url(issuer, field="issuer", require_https=require_https)
    if not normalized:
        raise ValueError("OIDC issuer is required")
    discovery_url = f"{normalized.rstrip('/')}/.well-known/openid-configuration"
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
    try:
        response = await http.get(discovery_url)
        if response.status_code != 200:
            raise ValueError("OIDC discovery endpoint returned an unsuccessful response")
        content = response.content
        if len(content) > MAX_DISCOVERY_BYTES:
            raise ValueError("OIDC discovery document is too large")
        metadata = response.json()
        if not isinstance(metadata, dict) or metadata.get("issuer") != normalized:
            raise ValueError("OIDC discovery issuer does not match configured issuer")
        for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(metadata.get(endpoint), str):
                raise ValueError("OIDC discovery document is incomplete")
            _safe_url(metadata[endpoint], field=endpoint, require_https=require_https)
        algorithms = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
        if not isinstance(algorithms, list) or not algorithms or not set(algorithms).intersection(OIDC_ALLOWED_ALGORITHMS):
            raise ValueError("OIDC provider does not advertise a supported signing algorithm")
        # Pin a fetch timestamp so Authlib does not silently fetch a different
        # document between authorization and callback.
        metadata["_loaded_at"] = time.time()
        return metadata
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("OIDC discovery"):
            raise
        raise ValueError("OIDC discovery could not be validated") from exc
    finally:
        if owns_client:
            await http.aclose()


async def validate_sso_configuration(
    payload: SSOConfigurationUpdate,
    settings: Settings,
    *,
    check_remote: bool = True,
) -> SSOValidationResult:
    """Validate a form without persisting it or reflecting secret values."""

    errors = _validate_url_fields(
        payload.provider,
        payload,
        require_https=getattr(settings, "environment", "development") in {"staging", "production"},
    )
    checks = {
        "schema": not errors,
        "settings": not errors,
        "issuer": not any("issuer" in error.casefold() for error in errors),
        "discovery": True,
        "certificate": True,
    }
    if payload.provider == "saml" and payload.idp_x509_certificate:
        cert_ok, cert_error = _validate_certificate(payload.idp_x509_certificate)
        checks["certificate"] = cert_ok
        if cert_error and cert_error not in errors:
            errors.append(cert_error)
    if payload.provider == "oidc" and payload.issuer and check_remote:
        try:
            await discover_oidc_metadata(
                payload.issuer,
                require_https=getattr(settings, "environment", "development") in {"staging", "production"},
            )
            checks["discovery"] = True
        except ValueError as exc:
            checks["discovery"] = False
            errors.append(str(exc) if str(exc).startswith("OIDC ") else "OIDC discovery could not be validated")
    if payload.provider == "saml":
        checks["settings"] = not any(error.startswith("SAML ") for error in errors)
    if errors:
        checks["schema"] = False
        checks["settings"] = False
    # Keep errors deliberately generic and bounded; never include issuer
    # response bodies, certificate contents, or client secrets.
    safe_errors = list(dict.fromkeys(item[:240] for item in errors))[:20]
    return SSOValidationResult(
        valid=not safe_errors,
        provider=payload.provider,
        checks=checks,
        errors=safe_errors,
    )


def _certificate_and_key(entity_id: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, entity_id[:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Exception Manager SP"),
        ]
    )
    now = _now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return private_pem, cert_pem


def _old_secret(db: DbSession, provider_id: Any, secret_type: str) -> SSOSecretRecord | None:
    return db.scalar(
        select(SSOSecretRecord)
        .where(
            SSOSecretRecord.provider_id == provider_id,
            SSOSecretRecord.secret_type == secret_type,
            SSOSecretRecord.is_active.is_(True),
        )
        .order_by(SSOSecretRecord.created_at.desc())
    )


def _copy_or_create_secret(
    db: DbSession,
    *,
    provider: SSOProvider,
    config: SSOProviderConfig,
    secret_type: str,
    value: str | None,
    old: SSOSecretRecord | None,
    settings: Settings,
    actor_id: Any | None,
    value_is_encrypted: bool = False,
) -> None:
    if value is None and old is not None:
        # A copied Fernet token is already encrypted.  Do not decrypt a secret
        # merely to clone a version.
        db.add(
            SSOSecretRecord(
                provider_id=provider.id,
                config_id=config.id,
                secret_type=secret_type,
                encrypted_value=old.encrypted_value,
                key_version=1,
                rotated_at=old.rotated_at,
                is_active=True,
                changed_by_id=actor_id,
            )
        )
        return
    if value is None:
        return
    encrypted = value if value_is_encrypted else encrypt_secret(value, settings)
    db.add(
        SSOSecretRecord(
            provider_id=provider.id,
            config_id=config.id,
            secret_type=secret_type,
            encrypted_value=encrypted,
            key_version=1,
            rotated_at=_now(),
            is_active=True,
            changed_by_id=actor_id,
        )
    )


def update_sso_configuration(
    db: DbSession,
    payload: SSOConfigurationUpdate,
    principal: Principal,
    context: AuditContext,
    settings: Settings,
    *,
    request_base_url: str | None = None,
) -> dict[str, Any]:
    """Persist a new immutable configuration version with optimistic locking."""

    if not payload.reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    current = get_effective_sso_config(db, settings)
    if current.version == 0:
        if payload.expected_version != 0:
            raise ConflictError()
    elif payload.expected_version != current.version:
        raise ConflictError()

    # Structural validation is synchronous and always performed.  Network
    # discovery is exposed by the explicit validate endpoint; keeping PUT
    # independent of a transient IdP outage allows an administrator to stage a
    # reviewed configuration while the runtime remains disabled if needed.
    structural_errors = _validate_url_fields(
        payload.provider,
        payload,
        require_https=getattr(settings, "environment", "development") in {"staging", "production"},
    )
    if structural_errors:
        raise DomainError("; ".join(structural_errors[:5]), code="invalid_sso_configuration")
    if payload.provider == "saml" and payload.idp_x509_certificate:
        cert_ok, cert_error = _validate_certificate(payload.idp_x509_certificate)
        if not cert_ok:
            raise DomainError(cert_error or "SAML certificate is invalid", code="invalid_sso_configuration")

    provider = db.scalar(select(SSOProvider).where(SSOProvider.provider == payload.provider))
    if provider is None:
        provider = SSOProvider(provider=payload.provider, created_by_id=principal.user.id)
        db.add(provider)
        db.flush()
    old_provider_config = current.db_config if current.db_config and current.provider == payload.provider else None
    old_provider_id = provider.id
    old_client_secret = _old_secret(db, old_provider_id, "client_secret") if old_provider_config else _old_secret(db, old_provider_id, "client_secret")
    old_signing_secret = _old_secret(db, old_provider_id, "signing_private_key") if old_provider_config else _old_secret(db, old_provider_id, "signing_private_key")
    old_cert = old_provider_config.sp_x509_certificate if old_provider_config else None

    # Find the next version globally.  This keeps expected_version meaningful
    # even when an operator switches provider protocols.
    max_version = db.scalar(select(SSOProviderConfig.version).order_by(SSOProviderConfig.version.desc()).limit(1)) or 0
    version = int(max_version) + 1
    values = payload.model_dump(exclude={"client_secret", "expected_version", "reason", "reauthenticated"})
    values["allowed_domains"] = list(payload.allowed_domains)
    values["issuer"] = _safe_url(payload.issuer, field="issuer") if payload.issuer else None
    values["redirect_uri"] = _safe_url(payload.redirect_uri, field="redirect_uri") if payload.redirect_uri else None
    values["sso_url"] = _safe_url(payload.sso_url, field="sso_url") if payload.sso_url else None
    values["idp_entity_id"] = (
        _safe_entity_id(
            payload.idp_entity_id,
            field="idp_entity_id",
            require_https=getattr(settings, "environment", "development") in {"staging", "production"},
        )
        if payload.idp_entity_id
        else None
    )
    values["sp_entity_id"] = (
        _safe_entity_id(
            payload.sp_entity_id,
            field="sp_entity_id",
            require_https=getattr(settings, "environment", "development") in {"staging", "production"},
        )
        if payload.sp_entity_id
        else None
    )
    values["acs_url"] = _safe_url(payload.acs_url, field="acs_url") if payload.acs_url else None
    metadata_url = payload.metadata_url
    if payload.provider == "saml" and not metadata_url and values["acs_url"]:
        parsed_acs = urlparse(values["acs_url"])
        values["metadata_url"] = urlunparse(
            (
                parsed_acs.scheme,
                parsed_acs.netloc,
                "/api/auth/sso/saml/metadata",
                "",
                "",
                "",
            )
        )
    elif payload.provider == "saml" and not metadata_url and request_base_url:
        values["metadata_url"] = f"{request_base_url.rstrip('/')}/api/auth/sso/saml/metadata"
    else:
        values["metadata_url"] = (
            _safe_url(metadata_url, field="metadata_url", allow_query=True) if metadata_url else None
        )
    values["provider_id"] = provider.id
    values["version"] = version
    values["is_active"] = True
    values["active_slot"] = 1
    values["created_by_id"] = principal.user.id
    values.pop("provider", None)
    values.pop("enabled", None)
    # enabled is a model field, not an input key after provider is removed.
    values["enabled"] = payload.enabled
    if payload.provider == "saml":
        if not old_cert or not old_signing_secret:
            private_key, certificate = _certificate_and_key(payload.sp_entity_id or "exception-manager-sp")
        else:
            private_key = decrypt_secret(old_signing_secret.encrypted_value, settings)
            certificate = old_cert
        values["sp_x509_certificate"] = certificate
    else:
        values["sp_x509_certificate"] = None
        private_key = None
        certificate = None

    # Deactivate all old rows before inserting the new active slot.  Clearing
    # active_slot first avoids a transient unique-key collision.
    active_rows = list(db.scalars(select(SSOProviderConfig).where(SSOProviderConfig.is_active.is_(True))))
    for old_row in active_rows:
        old_row.active_slot = None
        old_row.is_active = False
    db.flush()
    config = SSOProviderConfig(**values)
    db.add(config)
    db.flush()

    if payload.provider == "oidc":
        supplied_secret = payload.client_secret.get_secret_value() if payload.client_secret else None
        _copy_or_create_secret(
            db,
            provider=provider,
            config=config,
            secret_type="client_secret",  # noqa: S106 - schema discriminator, not a credential
            value=supplied_secret,
            old=old_client_secret,
            settings=settings,
            actor_id=principal.user.id,
        )
    else:
        _copy_or_create_secret(
            db,
            provider=provider,
            config=config,
            secret_type="signing_private_key",  # noqa: S106 - schema discriminator, not a credential
            value=private_key,
            old=None,
            settings=settings,
            actor_id=principal.user.id,
        )

    old_public = sanitized_sso_configuration(db, settings, current) if current.version else None
    if old_public is not None and old_public.get("updated_at") is not None:
        old_public["updated_at"] = old_public["updated_at"].isoformat()
    # Build the response from the newly persisted row without exposing the
    # secret record.  Flush first so flags query the active config.
    db.flush()
    record_audit(
        db,
        context,
        action="admin.sso_configuration_updated",
        object_type="sso_provider_configuration",
        object_id=str(config.id),
        old_value=old_public,
        new_value={
            "provider": payload.provider,
            "version": version,
            "enabled": payload.enabled,
            "reason": payload.reason,
            "client_secret_updated": payload.client_secret is not None,
        },
    )
    return sanitized_sso_configuration(db, settings, _config_from_row(config, provider))


def create_transaction(
    db: DbSession,
    request,
    config: EffectiveSSOConfig,
    transaction_type: str,
    *,
    protocol_payload: dict[str, Any],
    return_path: str = "/",
    relay_state: str | None = None,
    browser_binding: str | None = None,
    request_id: str | None = None,
) -> TransactionSecret:
    """Persist only hashes plus an encrypted protocol envelope."""

    state = generate_opaque_token(32) if transaction_type == "oidc" else None
    nonce = generate_opaque_token(32) if transaction_type == "oidc" else None
    verifier = generate_opaque_token(48) if transaction_type == "oidc" else None
    browser_binding = browser_binding or generate_opaque_token(32)
    relay_state = relay_state or (generate_opaque_token(32) if transaction_type == "saml" else None)
    request_id = str(request_id or protocol_payload.get("request_id") or "") or None
    envelope = dict(protocol_payload)
    envelope.update({"return_path": _safe_return_path(return_path), "config_id": str(config.config_id)})
    if transaction_type == "oidc":
        # Only hashes are queryable columns; the raw protocol values needed to
        # finish the flow exist inside the encrypted envelope.
        envelope.update({"nonce": nonce, "pkce_verifier": verifier})
    encrypted_payload = encrypt_secret(json.dumps(envelope, separators=(",", ":"), sort_keys=True), _request_settings(request))
    transaction = SSOLoginTransaction(
        provider_id=config.provider_id,
        config_id=config.config_id,
        config_version=config.version,
        transaction_type=transaction_type,
        state_hash=hash_token(state) if state else None,
        nonce_hash=hash_token(nonce) if nonce else None,
        pkce_verifier_hash=hash_token(verifier) if verifier else None,
        browser_binding_hash=hash_token(browser_binding),
        relay_state_hash=hash_token(relay_state) if relay_state else None,
        request_id_hash=hash_token(request_id) if request_id else None,
        encrypted_payload=encrypted_payload,
        return_path=_safe_return_path(return_path),
        source_ip=client_ip(request),
        expires_at=_now() + SSO_TRANSACTION_TTL,
    )
    db.add(transaction)
    db.commit()
    return TransactionSecret(
        transaction=transaction,
        state=state,
        nonce=nonce,
        pkce_verifier=verifier,
        browser_binding=browser_binding,
        relay_state=relay_state,
        request_id=request_id,
    )


def _request_settings(request) -> Settings:
    return request.app.state.settings


def claim_transaction(
    db: DbSession,
    *,
    lookup_field: str,
    raw_value: str,
    config: EffectiveSSOConfig,
    transaction_type: str,
    settings: Settings | None = None,
) -> tuple[SSOLoginTransaction, dict[str, Any], str]:
    """Atomically claim and consume a transaction, returning its raw envelope.

    A conditional UPDATE is used instead of a read-then-write sequence so two
    simultaneous callbacks cannot both proceed on databases with row locks.
    """

    if not raw_value or len(raw_value) > 1024:
        raise AuthenticationError("SSO login transaction is invalid or expired")
    field = getattr(SSOLoginTransaction, lookup_field, None)
    if field is None or lookup_field not in {"state_hash", "relay_state_hash"}:
        raise AuthenticationError("SSO login transaction is invalid or expired")
    now = _now()
    digest = hash_token(raw_value)
    result = db.execute(
        update(SSOLoginTransaction)
        .where(
            field == digest,
            SSOLoginTransaction.provider_id == config.provider_id,
            SSOLoginTransaction.config_id == config.config_id,
            SSOLoginTransaction.config_version == config.version,
            SSOLoginTransaction.transaction_type == transaction_type,
            SSOLoginTransaction.claimed_at.is_(None),
            SSOLoginTransaction.consumed_at.is_(None),
            SSOLoginTransaction.invalidated_at.is_(None),
            SSOLoginTransaction.expires_at > now,
        )
        .values(claimed_at=now, consumed_at=now)
    )
    if result.rowcount != 1:
        db.rollback()
        raise AuthenticationError("SSO login transaction is invalid or expired")
    db.commit()
    transaction = db.scalar(
        select(SSOLoginTransaction).where(
            field == digest,
            SSOLoginTransaction.provider_id == config.provider_id,
            SSOLoginTransaction.config_id == config.config_id,
        )
    )
    if transaction is None:
        raise AuthenticationError("SSO login transaction is invalid or expired")
    try:
        envelope = json.loads(decrypt_secret(transaction.encrypted_payload, settings or get_settings_for_request(db)))
    except (ValueError, TypeError, json.JSONDecodeError):
        invalidate_transaction(db, transaction.id, "invalid_payload")
        raise AuthenticationError("SSO login transaction is invalid or expired") from None
    if not isinstance(envelope, dict):
        invalidate_transaction(db, transaction.id, "invalid_payload")
        raise AuthenticationError("SSO login transaction is invalid or expired")
    return transaction, envelope, digest


def get_settings_for_request(db: DbSession) -> Settings:
    # The request is not available on every callback/error path.  The process
    # settings are the same object used by the app and tests can bind a
    # session-specific encryption key by passing it to create_transaction.
    return db.info.get("sso_settings") or get_settings()


def invalidate_transaction(db: DbSession, transaction_id: Any, code: str) -> None:
    db.execute(
        update(SSOLoginTransaction)
        .where(SSOLoginTransaction.id == transaction_id, SSOLoginTransaction.consumed_at.is_not(None))
        .values(invalidated_at=_now(), failure_code=code[:80])
    )
    db.commit()


def set_binding_cookie(
    response,
    raw_token: str,
    settings: Settings,
    *,
    provider: str,
) -> None:
    cross_site_post = provider == "saml"
    response.set_cookie(
        SSO_BINDING_COOKIE,
        raw_token,
        max_age=int(SSO_TRANSACTION_TTL.total_seconds()),
        # SAML assertions arrive through a cross-site POST. SameSite=None is
        # required for that browser binding; modern browsers require Secure.
        secure=settings.session_cookie_secure or cross_site_post,
        httponly=True,
        samesite="none" if cross_site_post else "lax",
        path="/api/auth/sso",
    )


def clear_binding_cookie(response) -> None:
    response.delete_cookie(SSO_BINDING_COOKIE, path="/api/auth/sso")


def verify_browser_binding(request, transaction: SSOLoginTransaction) -> bool:
    raw = request.cookies.get(SSO_BINDING_COOKIE, "")
    return bool(raw) and secrets.compare_digest(hash_token(raw), transaction.browser_binding_hash)


def enforce_login_rate_limit(db: DbSession, request) -> None:
    enforce_rate_limit(
        db,
        scope="sso_login_ip",
        identity=client_ip(request),
        limit=20,
        window_seconds=300,
        block_seconds=300,
    )


def _claim_browser_bound(db: DbSession, transaction: SSOLoginTransaction, request) -> None:
    if not verify_browser_binding(request, transaction):
        invalidate_transaction(db, transaction.id, "browser_binding")
        raise AuthenticationError("SSO login transaction is invalid or expired")


def _client_for_config(config: EffectiveSSOConfig, settings: Settings, db: DbSession, metadata: dict[str, Any] | None = None):
    if config.provider != "oidc" or not config.client_id or not config.issuer:
        raise AuthenticationError("OIDC is not configured")
    secret = get_client_secret(db, config, settings)
    oauth = OAuth()
    kwargs: dict[str, Any] = {
        "client_id": config.client_id,
        "client_secret": secret,
        "client_kwargs": {"scope": config.scopes},
        "server_metadata_url": f"{config.issuer.rstrip('/')}/.well-known/openid-configuration",
    }
    if metadata is not None:
        kwargs["server_metadata"] = dict(metadata)
    oauth.register(name="runtime-sso", **kwargs)
    return oauth.create_client("runtime-sso")


async def begin_oidc_transaction(
    db: DbSession, request, config: EffectiveSSOConfig
) -> tuple[Any, TransactionSecret, str]:
    """Create an OIDC request with S256 PKCE and a browser-bound transaction."""

    settings: Settings = request.app.state.settings
    enforce_login_rate_limit(db, request)
    try:
        metadata = await discover_oidc_metadata(
            config.issuer or "",
            require_https=getattr(settings, "environment", "development") in {"staging", "production"},
        )
        client = _client_for_config(config, settings, db, metadata)
        secret = create_transaction(
            db,
            request,
            config,
            "oidc",
            protocol_payload={
                "redirect_uri": config.redirect_uri,
                "issuer": config.issuer,
                "metadata": metadata,
            },
            return_path=_safe_return_path(request.query_params.get("return_to")),
        )
        verifier = secret.pkce_verifier
        assert verifier is not None
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        url, _ = await client.create_authorization_url(
            config.redirect_uri,
            state=secret.state,
            nonce=secret.nonce,
            code_challenge=challenge,
            code_challenge_method="S256",
            acr_values=config.required_acr,
        )
        return client, secret, url
    except (AuthenticationError, ValueError, httpx.HTTPError):
        db.rollback()
        raise AuthenticationError("OIDC login could not be started") from None


def _claim_browser_bound_and_config(db: DbSession, request, config: EffectiveSSOConfig, field: str, value: str, kind: str):
    transaction, envelope, _ = claim_transaction(
        db, lookup_field=field, raw_value=value, config=config, transaction_type=kind
    )
    _claim_browser_bound(db, transaction, request)
    return transaction, envelope


def validate_oidc_claims(
    claims: dict[str, Any],
    config: EffectiveSSOConfig,
    nonce: str,
    settings: Settings,
) -> tuple[str, str, str]:
    """Apply explicit OIDC claim checks after Authlib signature validation."""

    if claims.get("iss") != config.issuer:
        raise AuthenticationError("SSO identity validation failed")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if config.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") != config.client_id):
        raise AuthenticationError("SSO identity validation failed")
    if claims.get("azp") is not None and claims.get("azp") != config.client_id:
        raise AuthenticationError("SSO identity validation failed")
    if not claims.get("nonce") or not secrets.compare_digest(str(claims["nonce"]), nonce):
        raise AuthenticationError("SSO identity validation failed")
    now = _now().timestamp()
    for claim_name in ("exp",):
        if claim_name in claims:
            try:
                if float(claims[claim_name]) <= now:
                    raise AuthenticationError("SSO identity validation failed")
            except (TypeError, ValueError):
                raise AuthenticationError("SSO identity validation failed") from None
    for claim_name in ("iat", "auth_time"):
        if claims.get(claim_name) is not None:
            try:
                if float(claims[claim_name]) > now + 120:
                    raise AuthenticationError("SSO identity validation failed")
            except (TypeError, ValueError):
                raise AuthenticationError("SSO identity validation failed") from None
    if config.required_acr and str(claims.get("acr") or "") != config.required_acr:
        raise AuthenticationError("SSO identity validation failed")
    if config.tenant_claim:
        actual_tenant = claims.get(config.tenant_claim)
        if actual_tenant is None or not config.tenant_value or not secrets.compare_digest(str(actual_tenant), config.tenant_value):
            raise AuthenticationError("SSO identity validation failed")
    subject = str(claims.get("sub") or "").strip()
    email = str(claims.get(config.email_claim) or "").strip().casefold()
    if not subject or len(subject) > 512 or not email or len(email) > 320 or _CONTROL_RE.search(email):
        raise AuthenticationError("SSO identity did not include the required subject and email")
    if "@" not in email or not _domain_allowed(email, config.allowed_domains):
        raise AuthenticationError("SSO identity is not permitted by policy")
    if claims.get("email_verified") is False:
        raise AuthenticationError("SSO identity is not permitted by policy")
    name = str(claims.get(config.name_claim) or claims.get("preferred_username") or email).strip()
    if not name or len(name) > 160 or _CONTROL_RE.search(name):
        name = email
    return subject, email, name


def provision_sso_user(
    db: DbSession,
    config: EffectiveSSOConfig,
    subject: str,
    email: str,
    display_name: str,
    *,
    now: datetime | None = None,
) -> User:
    """Resolve provider+subject without ever reactivating a local account."""

    now = now or _now()
    identity = db.scalar(
        select(SSOExternalIdentity).where(
            SSOExternalIdentity.provider_id == config.provider_id,
            SSOExternalIdentity.subject == subject,
        )
    )
    if identity is not None:
        user = db.get(User, identity.user_id)
        if user is None:
            raise AuthenticationError("SSO identity is unavailable")
        locked_until = _aware(user.locked_until)
        if user.status != "active" or user.disabled_at is not None or (locked_until and locked_until > now):
            raise AuthenticationError("SSO identity is unavailable")
        if db.scalar(
            select(User.id)
            .where(User.email_normalized == email, User.id != user.id)
            .limit(1)
        ) is not None:
            raise AuthenticationError("SSO identity is not authorized")
        user.email = email
        user.email_normalized = email
        user.display_name = display_name[:160]
        user.last_login_at = now
        identity.email_at_link = email
        identity.last_login_at = now
        return user

    if not config.auto_provision:
        raise AuthenticationError("SSO identity is not authorized")
    # Never silently attach a new IdP identity to an existing local account.
    # An explicit, separately audited linking workflow would be required.
    if db.scalar(select(User.id).where(User.email_normalized == email).limit(1)) is not None:
        raise AuthenticationError("SSO identity is not authorized")
    role = db.scalar(select(Role).where(Role.code == "user", Role.is_active.is_(True)))
    user = User(
        public_id=public_reference("USR"),
        identity_provider=config.provider,
        identity_subject=subject,
        email=email,
        email_normalized=email,
        display_name=display_name[:160],
        status="active",
        is_break_glass=False,
        last_login_at=now,
    )
    try:
        with db.begin_nested():
            db.add(user)
            db.flush()
            identity = SSOExternalIdentity(
                provider_id=config.provider_id,
                subject=subject,
                user_id=user.id,
                email_at_link=email,
                last_login_at=now,
            )
            db.add(identity)
            db.flush()
    except IntegrityError:
        identity = db.scalar(
            select(SSOExternalIdentity).where(
                SSOExternalIdentity.provider_id == config.provider_id,
                SSOExternalIdentity.subject == subject,
            )
        )
        if identity is None:
            raise AuthenticationError("SSO identity is not authorized") from None
        user = db.get(User, identity.user_id)
        if user is None or user.status != "active" or user.disabled_at is not None:
            raise AuthenticationError("SSO identity is unavailable") from None
    if role is not None and not db.scalar(select(UserRole.id).where(UserRole.user_id == user.id).limit(1)):
        db.add(UserRole(user_id=user.id, role_id=role.id))
    return user


def get_sso_configuration(db: DbSession, settings: Settings) -> dict[str, Any]:
    """Compatibility/read helper for admin and integration callers."""

    return sanitized_sso_configuration(db, settings)


async def validate_sso_config(
    payload: SSOConfigurationUpdate, settings: Settings, *, check_remote: bool = True
) -> SSOValidationResult:
    return await validate_sso_configuration(payload, settings, check_remote=check_remote)


def save_sso_configuration(
    db: DbSession,
    payload: SSOConfigurationUpdate,
    principal: Principal,
    context: AuditContext,
    settings: Settings,
    *,
    request_base_url: str | None = None,
) -> dict[str, Any]:
    return update_sso_configuration(
        db,
        payload,
        principal,
        context,
        settings,
        request_base_url=request_base_url,
    )


__all__ = [
    "EffectiveSSOConfig",
    "TransactionSecret",
    "OIDC_ALLOWED_ALGORITHMS",
    "SSO_BINDING_COOKIE",
    "SSO_TRANSACTION_TTL",
    "SAML_BINDING_HTTP_POST",
    "SAML_BINDING_HTTP_REDIRECT",
    "MAX_SAML_RESPONSE_BYTES",
    "begin_oidc_transaction",
    "claim_transaction",
    "clear_binding_cookie",
    "create_transaction",
    "discover_oidc_metadata",
    "enforce_login_rate_limit",
    "get_client_secret",
    "get_sso_configuration",
    "get_effective_sso_config",
    "get_enabled_login_config",
    "get_signing_private_key",
    "provision_sso_user",
    "sanitized_sso_configuration",
    "save_sso_configuration",
    "set_binding_cookie",
    "update_sso_configuration",
    "validate_oidc_claims",
    "validate_sso_configuration",
    "validate_sso_config",
    "verify_browser_binding",
]
