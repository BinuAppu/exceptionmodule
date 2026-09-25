"""Strict, secret-safe contracts for runtime SSO administration."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

Provider = Literal["oidc", "saml"]

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
_CLAIM_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,254}$")
_URI_CLAIM_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,240}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class SSOConfigurationUpdate(BaseModel):
    """Complete replacement payload for the active SSO configuration.

    The payload is deliberately a flat, strict model.  In particular, there
    is no ``dict`` catch-all where a secret could be smuggled into a generic
    system configuration store.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    provider: Provider
    enabled: bool = False
    display_name: str = Field(min_length=2, max_length=160)
    issuer: str | None = Field(default=None, max_length=2048)
    client_id: str | None = Field(default=None, max_length=512)
    scopes: str = Field(default="openid profile email", min_length=1, max_length=1000)
    redirect_uri: str | None = Field(default=None, max_length=2048)
    required_acr: str | None = Field(default=None, max_length=255)
    email_claim: str = Field(default="email", min_length=1, max_length=255)
    name_claim: str = Field(default="name", min_length=1, max_length=255)
    tenant_claim: str | None = Field(default=None, max_length=255)
    tenant_value: str | None = Field(default=None, max_length=255)
    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    auto_provision: bool = True
    idp_entity_id: str | None = Field(default=None, max_length=2048)
    sso_url: str | None = Field(default=None, max_length=2048)
    idp_x509_certificate: str | None = Field(default=None, max_length=100_000)
    email_attribute: str = Field(default="email", min_length=1, max_length=255)
    name_attribute: str = Field(default="displayName", min_length=1, max_length=255)
    sp_entity_id: str | None = Field(default=None, max_length=2048)
    acs_url: str | None = Field(default=None, max_length=2048)
    metadata_url: str | None = Field(default=None, max_length=2048)

    # SecretStr prevents accidental interpolation in repr/logging.  It is
    # write-only, so it cannot be serialized into either admin response.
    client_secret: SecretStr | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
        exclude=True,
        json_schema_extra={"writeOnly": True},
    )
    expected_version: int = Field(ge=0, le=2_147_483_647)
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = False

    @field_validator(
        "issuer",
        "redirect_uri",
        "sso_url",
        "sp_entity_id",
        "acs_url",
        "metadata_url",
        "required_acr",
        "tenant_claim",
        "tenant_value",
        "idp_entity_id",
        mode="before",
    )
    @classmethod
    def reject_control_characters(cls, value: object) -> object:
        if isinstance(value, str) and _CONTROL_RE.search(value):
            raise ValueError("Control characters are not permitted")
        return value

    @field_validator("email_claim", "name_claim", "email_attribute", "name_attribute", "tenant_claim")
    @classmethod
    def validate_claim_name(cls, value: str | None) -> str | None:
        if value is not None and not (
            _CLAIM_RE.fullmatch(value) or _URI_CLAIM_RE.fullmatch(value)
        ):
            raise ValueError("Claim/attribute names must be simple identifiers or URIs")
        return value

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for domain in value:
            candidate = domain.strip().lower().rstrip(".")
            if not _DOMAIN_RE.fullmatch(candidate) or ".." in candidate:
                raise ValueError("allowed_domains must contain valid DNS domains")
            if candidate not in normalized:
                normalized.append(candidate)
        return normalized

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: str) -> str:
        if _CONTROL_RE.search(value) or "  " in value:
            raise ValueError("scopes contains invalid whitespace")
        return " ".join(value.split())

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if _CONTROL_RE.search(value):
            raise ValueError("reason contains control characters")
        return value

    @model_validator(mode="after")
    def validate_claim_pair(self) -> SSOConfigurationUpdate:
        if bool(self.tenant_claim) != bool(self.tenant_value):
            raise ValueError("tenant_claim and tenant_value must be configured together")
        return self


class SSOConfigurationResponse(BaseModel):
    """Sanitized flat representation consumed by the admin UI."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=0)
    provider: Provider
    enabled: bool
    display_name: str
    issuer: str | None = None
    client_id: str | None = None
    scopes: str
    redirect_uri: str | None = None
    required_acr: str | None = None
    email_claim: str
    name_claim: str
    tenant_claim: str | None = None
    tenant_value: str | None = None
    allowed_domains: list[str]
    auto_provision: bool
    idp_entity_id: str | None = None
    sso_url: str | None = None
    idp_x509_certificate: str | None = None
    email_attribute: str
    name_attribute: str
    sp_entity_id: str | None = None
    acs_url: str | None = None
    client_secret_configured: bool = False
    signing_key_configured: bool = False
    metadata_url: str | None = None
    updated_at: datetime | None = None


class SSOValidationResult(BaseModel):
    """Safe result for the non-persisting validation endpoint."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    provider: Provider
    checks: dict[str, bool]
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# Names used by different API clients; keep aliases rather than maintaining
# subtly different (and potentially less strict) schemas.
SSOConfigUpdate = SSOConfigurationUpdate
SSOConfigResponse = SSOConfigurationResponse
SSOValidateRequest = SSOConfigurationUpdate
SSOValidationResponse = SSOValidationResult
SSOConfiguration = SSOConfigurationResponse
SSOConfig = SSOConfigurationUpdate
SSOConfigurationRequest = SSOConfigurationUpdate
SSOConfigurationView = SSOConfigurationResponse
