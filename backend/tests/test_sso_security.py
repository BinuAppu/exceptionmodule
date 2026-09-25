from __future__ import annotations

import asyncio
import base64
import uuid
from urllib.parse import parse_qs, urlparse
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import Settings
from app.core.errors import AuthenticationError, ConflictError
from app.core.security import hash_password, hash_token
from app.models import (
    SSOExternalIdentity,
    SSOProvider,
    SSOProviderConfig,
    SSOSecretRecord,
    User,
)
from app.schemas.common import AuditContext
from app.schemas.sso import SSOConfigurationUpdate
from app.services.authz import Principal
from app.services.saml import sp_metadata
from app.services.sso import (
    EffectiveSSOConfig,
    begin_oidc_transaction,
    claim_transaction,
    create_transaction,
    get_effective_sso_config,
    provision_sso_user,
    sanitized_sso_configuration,
    set_binding_cookie,
    update_sso_configuration,
    validate_oidc_claims,
)


def _settings() -> Settings:
    return Settings(
        environment="test",
        app_encryption_key=SecretStr(base64.urlsafe_b64encode(b"1" * 32).decode()),
    )


def _request(settings: Settings) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(settings=settings))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/auth/sso/login",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "app": app,
        }
    )


def _principal(user: User) -> Principal:
    return Principal(
        user=user,
        roles=frozenset({"admin"}),
        permissions=frozenset({"*"}),
        session_id=uuid.uuid4(),
    )


def _idp_certificate() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _oidc_snapshot(db, *, enabled: bool = True) -> EffectiveSSOConfig:
    provider = SSOProvider(provider="oidc")
    db.add(provider)
    db.flush()
    config = SSOProviderConfig(
        provider_id=provider.id,
        version=1,
        is_active=True,
        active_slot=1,
        enabled=enabled,
        display_name="Test OIDC",
        issuer="https://issuer.example.test",
        client_id="test-client",
        redirect_uri="https://app.example.test/api/auth/sso/callback",
        required_acr="urn:example:loa:2",
    )
    db.add(config)
    db.commit()
    return get_effective_sso_config(db, _settings())


def test_sso_schema_forbids_extras_and_never_dumps_client_secret() -> None:
    with pytest.raises(ValidationError):
        SSOConfigurationUpdate(
            provider="oidc",
            display_name="OIDC",
            expected_version=0,
            reason="reviewed configuration",
            unexpected="must-not-be-accepted",
        )

    payload = SSOConfigurationUpdate(
        provider="oidc",
        display_name="OIDC",
        expected_version=0,
        reason="reviewed configuration",
        client_secret="do-not-serialize",  # noqa: S106 - test fixture
    )
    assert "client_secret" not in payload.model_dump()
    assert "do-not-serialize" not in payload.model_dump_json()


def test_saml_browser_binding_cookie_supports_cross_site_post() -> None:
    response = Response()
    set_binding_cookie(response, "opaque-binding", _settings(), provider="saml")

    cookie = response.headers["set-cookie"]
    normalized = cookie.lower()
    assert "samesite=none" in normalized
    assert "secure" in normalized
    assert "httponly" in normalized


def test_sso_config_is_versioned_and_secrets_are_encrypted(db_session) -> None:
    settings = _settings()
    admin = User(
        public_id="USR-SSO-ADMIN",
        email="sso-admin@example.test",
        email_normalized="sso-admin@example.test",
        display_name="SSO Admin",
        status="active",
        password_hash=hash_password("Aa1!aaaaaaaaaaaa"),
    )
    db_session.add(admin)
    db_session.flush()
    context = AuditContext(actor_id=str(admin.id), correlation_id="sso-test")
    payload = SSOConfigurationUpdate(
        provider="oidc",
        enabled=False,
        display_name="Reviewed OIDC",
        issuer="https://issuer.example.test",
        client_id="client-id",
        redirect_uri="https://app.example.test/callback",
        expected_version=0,
        reason="initial reviewed setup",
        reauthenticated=True,
        client_secret="client-secret-value",  # noqa: S106 - test fixture
    )
    result = update_sso_configuration(db_session, payload, _principal(admin), context, settings)
    db_session.commit()

    assert result["version"] == 1
    assert result["client_secret_configured"] is True
    assert "client_secret" not in result
    secret = db_session.scalar(select(SSOSecretRecord))
    assert secret is not None
    assert "client-secret-value" not in secret.encrypted_value
    assert secret.encrypted_value.startswith("gAAAA")

    with pytest.raises(ConflictError):
        update_sso_configuration(
            db_session,
            payload.model_copy(update={"expected_version": 0, "reauthenticated": True}),
            _principal(admin),
            context,
            settings,
        )

    sanitized = sanitized_sso_configuration(db_session, settings)
    assert set(sanitized) == {
        "version",
        "provider",
        "enabled",
        "display_name",
        "issuer",
        "client_id",
        "scopes",
        "redirect_uri",
        "required_acr",
        "email_claim",
        "name_claim",
        "tenant_claim",
        "tenant_value",
        "allowed_domains",
        "auto_provision",
        "idp_entity_id",
        "sso_url",
        "idp_x509_certificate",
        "email_attribute",
        "name_attribute",
        "sp_entity_id",
        "acs_url",
        "client_secret_configured",
        "signing_key_configured",
        "metadata_url",
        "updated_at",
    }


def test_oidc_login_uses_pkce_s256_and_persists_a_browser_binding(db_session, monkeypatch) -> None:
    settings = _settings()
    snapshot = _oidc_snapshot(db_session)
    captured: dict[str, object] = {}

    class FakeClient:
        async def create_authorization_url(self, redirect_uri, **kwargs):
            captured.update(kwargs)
            from urllib.parse import urlencode

            return "https://issuer.example.test/authorize?" + urlencode(kwargs), {}

    async def fake_discovery(issuer, **_kwargs):
        return {
            "issuer": issuer,
            "authorization_endpoint": "https://issuer.example.test/authorize",
            "token_endpoint": "https://issuer.example.test/token",
            "jwks_uri": "https://issuer.example.test/keys",
            "id_token_signing_alg_values_supported": ["RS256"],
            "_loaded_at": 1,
        }

    monkeypatch.setattr("app.services.sso.discover_oidc_metadata", fake_discovery)
    monkeypatch.setattr("app.services.sso._client_for_config", lambda *_args, **_kwargs: FakeClient())
    _client, secret, url = asyncio.run(begin_oidc_transaction(db_session, _request(settings), snapshot))
    query = parse_qs(urlparse(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [captured["code_challenge"]]
    assert secret.browser_binding
    assert secret.state in query["state"][0]
    assert secret.nonce in query["nonce"][0]


def test_oidc_transaction_is_hashed_encrypted_and_one_time(db_session) -> None:
    settings = _settings()
    snapshot = _oidc_snapshot(db_session)
    request = _request(settings)
    secret = create_transaction(
        db_session,
        request,
        snapshot,
        "oidc",
        protocol_payload={"redirect_uri": snapshot.redirect_uri},
        return_path="/requests",
    )
    transaction = db_session.scalar(select(type(secret.transaction)))
    assert transaction is not None
    assert secret.state not in transaction.encrypted_payload
    assert secret.nonce not in transaction.encrypted_payload
    assert secret.pkce_verifier not in transaction.encrypted_payload
    assert transaction.state_hash == hash_token(secret.state or "")
    assert transaction.nonce_hash == hash_token(secret.nonce or "")
    assert transaction.pkce_verifier_hash == hash_token(secret.pkce_verifier or "")

    request.cookies["em_sso_binding"] = secret.browser_binding
    claimed, envelope, _ = claim_transaction(
        db_session,
        lookup_field="state_hash",
        raw_value=secret.state or "",
        config=snapshot,
        transaction_type="oidc",
        settings=settings,
    )
    assert claimed.consumed_at is not None
    assert envelope["return_path"] == "/requests"
    with pytest.raises(AuthenticationError):
        claim_transaction(
            db_session,
            lookup_field="state_hash",
            raw_value=secret.state or "",
            config=snapshot,
            transaction_type="oidc",
            settings=settings,
        )


def test_oidc_claims_and_disabled_user_are_not_reactivated(db_session) -> None:
    settings = _settings()
    snapshot = _oidc_snapshot(db_session)
    claims = {
        "iss": snapshot.issuer,
        "aud": snapshot.client_id,
        "sub": "subject-1",
        "email": "person@example.test",
        "name": "Person",
        "nonce": "nonce-value",
        "acr": snapshot.required_acr,
        "exp": datetime.now(UTC).timestamp() + 300,
    }
    assert validate_oidc_claims(claims, snapshot, "nonce-value", settings)[0] == "subject-1"

    user = User(
        public_id="USR-SSO-DISABLED",
        email="disabled@example.test",
        email_normalized="disabled@example.test",
        display_name="Disabled",
        status="disabled",
        disabled_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()
    db_session.add(
        SSOExternalIdentity(
            provider_id=snapshot.provider_id,
            subject="subject-1",
            user_id=user.id,
        )
    )
    db_session.commit()
    with pytest.raises(AuthenticationError):
        provision_sso_user(
            db_session,
            snapshot,
            "subject-1",
            "person@example.test",
            "Person",
        )
    db_session.refresh(user)
    assert user.status == "disabled"


def test_saml_settings_contain_protected_signing_material_and_metadata(db_session) -> None:
    settings = _settings()
    admin = User(
        public_id="USR-SAML-ADMIN",
        email="saml-admin@example.test",
        email_normalized="saml-admin@example.test",
        display_name="SAML Admin",
        status="active",
        password_hash=hash_password("Aa1!aaaaaaaaaaaa"),
    )
    db_session.add(admin)
    db_session.flush()
    payload = SSOConfigurationUpdate(
        provider="saml",
        enabled=False,
        display_name="Reviewed SAML",
        idp_entity_id="https://idp.example.test/metadata",
        sso_url="https://idp.example.test/sso",
        idp_x509_certificate=_idp_certificate(),
        sp_entity_id="https://app.example.test/saml/metadata",
        acs_url="https://app.example.test/api/auth/sso/saml/acs",
        expected_version=0,
        reason="initial SAML setup",
        reauthenticated=True,
    )
    result = update_sso_configuration(
        db_session,
        payload,
        _principal(admin),
        AuditContext(actor_id=str(admin.id), correlation_id="saml-test"),
        settings,
    )
    db_session.commit()
    assert result["provider"] == "saml"
    assert result["signing_key_configured"] is True
    assert "PRIVATE KEY" not in result["idp_x509_certificate"]

    snapshot = get_effective_sso_config(db_session, settings)
    metadata = sp_metadata(snapshot).decode("utf-8")
    assert 'AuthnRequestsSigned="true"' in metadata
    assert "AssertionConsumerService" in metadata
    assert "PRIVATE KEY" not in metadata
