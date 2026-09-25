from __future__ import annotations

import base64
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_TRUE_VALUES = {"1", "true", "yes", "on"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Exception-Manager"
    app_version: str = "0.1.0"
    environment: Literal["development", "test", "staging", "production"] = "development"
    api_prefix: str = "/api"
    log_level: str = "INFO"
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    trusted_proxy_hops: int = 0

    database_url: str = "sqlite:///./data/exception_manager.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_pool_timeout: int = 30

    app_encryption_key: SecretStr | None = None
    ephemeral_development_key: SecretStr | None = None
    session_cookie_name: str = "em_session"
    session_cookie_secure: bool = False
    session_idle_minutes: int = 30
    session_absolute_minutes: int = 480
    concurrent_session_limit: int = 3
    csrf_trusted_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    break_glass_username: str = "breakglass-admin"
    break_glass_initial_password: SecretStr | None = None

    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    # Used only by the legacy environment bootstrap validator.  Runtime SSO
    # configuration is DB-backed and never copies this value into
    # SystemConfig.
    oidc_auth_mode: Literal["api_key", "managed_identity"] = "api_key"
    oidc_redirect_uri: str = "http://localhost:8000/api/auth/sso/callback"
    oidc_scopes: str = "openid profile email"
    oidc_high_assurance_acr: str = "urn:mace:incommon:iap:silver"

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_use_tls: bool = True
    smtp_from: str = "exception-manager@example.invalid"
    smtp_timeout_seconds: int = 15

    storage_root: Path = Path("./storage")
    attachment_max_bytes: int = 10 * 1024 * 1024
    attachment_scan_mode: Literal["clamav", "disabled"] = "clamav"
    attachment_allowed_mime_types: list[str] = Field(
        default_factory=lambda: [
            "application/pdf",
            "image/jpeg",
            "image/png",
            "text/plain",
            "message/rfc822",
        ]
    )
    attachment_allowed_extensions: list[str] = Field(
        default_factory=lambda: ["pdf", "jpg", "jpeg", "png", "txt", "eml"]
    )
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 15

    ai_enabled: bool = False
    azure_openai_endpoint: str | None = None
    azure_openai_api_version: str = "2024-10-21"
    azure_openai_deployment: str | None = None
    azure_openai_api_key: SecretStr | None = None
    azure_openai_auth_mode: Literal["api_key", "managed_identity"] = "api_key"
    azure_openai_timeout_seconds: int = 45
    azure_openai_max_input_tokens: int = 12000
    ai_send_restricted_data: bool = False
    ai_send_attachment_text: bool = True

    default_exception_days: int = 90
    minimum_exception_days: int = 1
    maximum_exception_days: int = 365
    maximum_extension_days: int = 90
    maximum_extensions: int = 2
    default_expiration_reminders: list[int] = Field(default_factory=lambda: [30, 14, 7, 3, 1])
    default_manager_sla_business_days: int = 3
    default_delivery_sla_business_days: int = 2
    default_approver_sla_business_days: int = 3
    business_timezone: str = "UTC"
    business_weekdays: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])

    login_failure_threshold: int = 5
    login_lockout_minutes: int = 15
    api_rate_limit_per_minute: int = 240
    upload_rate_limit_per_minute: int = 20
    password_minimum_length: int = 14
    audit_retention_days: int = 1095
    backup_retention_count: int = 14
    seed_development_data: bool = False

    backup_command: str = "pg_dump"
    backup_encryption_key: SecretStr | None = None
    backup_directory: Path = Path("./storage/backups")

    @field_validator("cors_origins", "csrf_trusted_origins", "allowed_hosts", mode="before")
    @classmethod
    def split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator(
        "attachment_allowed_mime_types",
        "attachment_allowed_extensions",
        "default_expiration_reminders",
        "business_weekdays",
        mode="before",
    )
    @classmethod
    def split_csv_or_json_array(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return value
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def validate_security_boundaries(self) -> Settings:
        if self.environment in {"staging", "production"}:
            problems: list[str] = []
            if not self.session_cookie_secure:
                problems.append("SESSION_COOKIE_SECURE must be true")
            if not self.app_encryption_key:
                problems.append("APP_ENCRYPTION_KEY is required")
            if self.oidc_enabled:
                if not self.oidc_issuer or not self.oidc_client_id:
                    problems.append("OIDC issuer and client ID are required")
                if self.oidc_auth_mode == "api_key" and not self.oidc_client_secret:
                    problems.append("OIDC client secret is required for confidential clients")
            if "*" in self.cors_origins or "*" in self.allowed_hosts:
                problems.append("Wildcard CORS and hosts are forbidden")
            if self.attachment_scan_mode != "clamav":
                problems.append("Production attachment scanning must use ClamAV")
            if not self.backup_encryption_key:
                problems.append("BACKUP_ENCRYPTION_KEY is required for protected backups")
            if problems:
                raise ValueError("; ".join(problems))
        if self.minimum_exception_days > self.default_exception_days:
            raise ValueError("Minimum duration cannot exceed default duration")
        if self.default_exception_days > self.maximum_exception_days:
            raise ValueError("Default duration cannot exceed maximum duration")
        if self.maximum_extensions < 0:
            raise ValueError("Maximum extensions cannot be negative")
        return self

    def resolved_encryption_key(self) -> bytes:
        if self.app_encryption_key:
            raw = self.app_encryption_key.get_secret_value().encode()
            try:
                return base64.urlsafe_b64decode(raw)
            except Exception as exc:
                raise ValueError("APP_ENCRYPTION_KEY must be a base64-encoded 32-byte key") from exc
        if self.ephemeral_development_key:
            return base64.urlsafe_b64decode(self.ephemeral_development_key.get_secret_value().encode())
        # Development/test only. This deliberately invalidates stored ciphertext on restart.
        raw = secrets.token_bytes(32)
        object.__setattr__(
            self,
            "ephemeral_development_key",
            SecretStr(base64.urlsafe_b64encode(raw).decode()),
        )
        return raw


@lru_cache
def get_settings() -> Settings:
    return Settings()
