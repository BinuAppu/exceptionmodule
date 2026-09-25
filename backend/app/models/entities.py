"""Normalized relational domain model.

The schema intentionally uses constrained scalar columns and relation tables for
identity, workflow, audit, and approval data. JSON is used only for bounded
configuration or structured integration payloads, never as the database design.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class RoleName:
    USER = "user"
    APPROVER = "approver"
    ADMIN = "admin"
    ALL = {USER, APPROVER, ADMIN}


class RequestStatus:
    DRAFT = "draft"
    SUBMITTED = "submitted"
    PENDING_MANAGER = "pending_manager_approval"
    MANAGER_APPROVED = "manager_approved"
    MANAGER_REJECTED = "manager_rejected"
    PENDING_DELIVERY = "pending_delivery_head_approval"
    DELIVERY_APPROVED = "delivery_head_approved"
    DELIVERY_REJECTED = "delivery_head_rejected"
    PENDING_APPROVER = "pending_approver_review"
    CLARIFICATION_REQUIRED = "clarification_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    EXTENSION_REQUESTED = "extension_requested"
    EXTENSION_PENDING_APPROVAL = "extension_pending_approval"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    WITHDRAWN = "withdrawn"
    CLOSED = "closed"

    TERMINAL = {REJECTED, EXPIRED, CANCELLED, WITHDRAWN, CLOSED}


class StageKind:
    MANAGER = "manager"
    DELIVERY_HEAD = "delivery_head"
    EXCEPTION_APPROVER = "exception_approver"
    FINAL = "final"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("failed_login_count >= 0", name="failed_login_nonnegative"),
        Index("ix_users_identity", "identity_provider", "identity_subject", unique=True),
        Index("ix_users_email_active", "email_normalized"),
    )

    public_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    identity_provider: Mapped[str | None] = mapped_column(String(80))
    identity_subject: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    department: Mapped[str | None] = mapped_column(String(160))
    job_title: Mapped[str | None] = mapped_column(String(160))
    manager_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    is_break_glass: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(512))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    manager: Mapped[User | None] = relationship(
        foreign_keys=[manager_id], remote_side=lambda: [User.id], backref="direct_reports"
    )
    user_roles: Mapped[list[UserRole]] = relationship(
        back_populates="user", cascade="all, delete-orphan", foreign_keys="UserRole.user_id"
    )
    sessions: Mapped[list[Session]] = relationship(back_populates="user", cascade="all, delete-orphan")

    __mapper_args__ = {"version_id_col": version}


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "roles"

    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Permission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="standard", nullable=False)


class UserRole(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_roles_user_role"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    user: Mapped[User] = relationship(back_populates="user_roles", foreign_keys=[user_id])
    role: Mapped[Role] = relationship()


class RolePermission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),
    )

    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)


class LocalRecoveryCode(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "local_recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_from_ip: Mapped[str | None] = mapped_column(String(64))


class Session(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_user_active", "user_id", "revoked_at", "idle_expires_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    identity_provider: Mapped[str] = mapped_column(String(80), nullable=False)
    auth_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assurance_level: Mapped[str | None] = mapped_column(String(160))
    auth_methods: Mapped[Any | None] = mapped_column(JSON)
    created_ip: Mapped[str | None] = mapped_column(String(64))
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(160))

    user: Mapped[User] = relationship(back_populates="sessions")


class OidcTransaction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Legacy OIDC transaction table retained for rolling upgrades.

    New logins use :class:`SSOTransaction`.  Keeping this table avoids making a
    rolling deployment depend on a destructive migration, but no runtime code
    writes to it.
    """

    __tablename__ = "oidc_transactions"

    state_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    nonce_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    return_path: Mapped[str] = mapped_column(String(255), default="/", nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SSOProvider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Stable identity-provider record.

    Provider rows are intentionally independent from configuration versions.
    Renaming a provider or rotating its settings must not change the subject
    namespace used by :class:`SSOExternalIdentity`.
    """

    __tablename__ = "sso_providers"
    __table_args__ = (
        CheckConstraint("provider IN ('oidc', 'saml')", name="sso_provider_type_valid"),
    )

    provider: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    configurations: Mapped[list[SSOProviderConfig]] = relationship(
        back_populates="provider", cascade="all, delete-orphan"
    )


class SSOProviderConfig(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable version of one provider's non-secret configuration."""

    __tablename__ = "sso_provider_configs"
    __table_args__ = (
        UniqueConstraint("provider_id", "version", name="uq_sso_provider_config_version"),
        UniqueConstraint("provider_id", "active_slot", name="uq_sso_provider_active_config"),
        CheckConstraint("version > 0", name="sso_provider_config_version_positive"),
        CheckConstraint("active_slot IS NULL OR active_slot = 1", name="sso_provider_active_slot_valid"),
        CheckConstraint(
            "(is_active = false AND active_slot IS NULL) OR (is_active = true AND active_slot = 1)",
            name="sso_provider_active_flag_valid",
        ),
        Index("ix_sso_provider_configs_active", "is_active", "provider_id"),
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # NULL means inactive; the unique slot makes the one-active invariant work
    # on both PostgreSQL and SQLite (which does not implement partial indexes
    # uniformly across versions).
    active_slot: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(2048))
    client_id: Mapped[str | None] = mapped_column(String(512))
    scopes: Mapped[str] = mapped_column(String(1000), default="openid profile email", nullable=False)
    redirect_uri: Mapped[str | None] = mapped_column(String(2048))
    required_acr: Mapped[str | None] = mapped_column(String(255))
    email_claim: Mapped[str] = mapped_column(String(255), default="email", nullable=False)
    name_claim: Mapped[str] = mapped_column(String(255), default="name", nullable=False)
    tenant_claim: Mapped[str | None] = mapped_column(String(255))
    tenant_value: Mapped[str | None] = mapped_column(String(255))
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    idp_entity_id: Mapped[str | None] = mapped_column(String(2048))
    sso_url: Mapped[str | None] = mapped_column(String(2048))
    idp_x509_certificate: Mapped[str | None] = mapped_column(Text)
    email_attribute: Mapped[str] = mapped_column(String(255), default="email", nullable=False)
    name_attribute: Mapped[str] = mapped_column(String(255), default="displayName", nullable=False)
    sp_entity_id: Mapped[str | None] = mapped_column(String(2048))
    acs_url: Mapped[str | None] = mapped_column(String(2048))
    # The SP certificate is public metadata, but is kept with the versioned
    # configuration so a historical transaction can be verified after a
    # rotation.  It is intentionally not part of the admin response.
    sp_x509_certificate: Mapped[str | None] = mapped_column(Text)
    metadata_url: Mapped[str | None] = mapped_column(String(2048))

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    provider: Mapped[SSOProvider] = relationship(back_populates="configurations")
    secrets: Mapped[list[SSOSecretRecord]] = relationship(
        back_populates="config", cascade="all, delete-orphan"
    )


class SSOExternalIdentity(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable mapping from an IdP subject to a local user."""

    __tablename__ = "sso_external_identities"
    __table_args__ = (
        UniqueConstraint("provider_id", "subject", name="uq_sso_external_identity_subject"),
        Index("ix_sso_external_identity_user", "user_id", "provider_id"),
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"), nullable=False
    )
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    email_at_link: Mapped[str | None] = mapped_column(String(320))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    provider: Mapped[SSOProvider] = relationship()
    user: Mapped[User] = relationship()


class SSOSecretRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Write-only encrypted SSO credential or signing key.

    Values are encrypted with the application encryption key before they
    reach SQLAlchemy.  There is intentionally no plaintext property and this
    model is never used as an API response model.
    """

    __tablename__ = "sso_secret_records"
    __table_args__ = (
        UniqueConstraint("config_id", "secret_type", "key_version", name="uq_sso_secret_version"),
        CheckConstraint("key_version > 0", name="sso_secret_key_version_positive"),
        Index("ix_sso_secret_active", "provider_id", "secret_type", "is_active"),
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"), nullable=False
    )
    config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_provider_configs.id", ondelete="CASCADE"), nullable=False
    )
    secret_type: Mapped[str] = mapped_column(String(80), nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    config: Mapped[SSOProviderConfig] = relationship(back_populates="secrets")
    provider: Mapped[SSOProvider] = relationship()


class SSOTransaction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Short-lived, one-time OIDC/SAML login transaction.

    State, nonce, PKCE verifier, RelayState, browser binding, and SAML request
    IDs are stored only as hashes.  The small protocol envelope needed to
    finish a flow is encrypted as a whole.
    """

    __tablename__ = "sso_login_transactions"
    __table_args__ = (
        CheckConstraint("transaction_type IN ('oidc', 'saml')", name="sso_transaction_type_valid"),
        Index("ix_sso_transactions_expiry", "expires_at", "consumed_at"),
        Index("ix_sso_transactions_provider", "provider_id", "config_id"),
    )

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"), nullable=False
    )
    config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_provider_configs.id", ondelete="CASCADE"), nullable=False
    )
    config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    transaction_type: Mapped[str] = mapped_column(String(20), nullable=False)
    state_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    nonce_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    pkce_verifier_hash: Mapped[str | None] = mapped_column(String(64))
    browser_binding_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    relay_state_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    request_id_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    return_path: Mapped[str] = mapped_column(String(255), default="/", nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(80))

    provider: Mapped[SSOProvider] = relationship()
    config: Mapped[SSOProviderConfig] = relationship()


# Compatibility aliases for integrations that used the more verbose names
# while the dedicated SSO schema was being introduced.
SSOProviderConfiguration = SSOProviderConfig
SSOConfigurationVersion = SSOProviderConfig
SSOConfig = SSOProviderConfig
SSOSecret = SSOSecretRecord
SSOProviderSecret = SSOSecretRecord
SSOEncryptedSecret = SSOSecretRecord
SSOCredential = SSOSecretRecord
SSOExternalIdentityLink = SSOExternalIdentity
SSOLoginTransaction = SSOTransaction


class SystemConfig(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "system_configs"
    __table_args__ = (UniqueConstraint("config_key", "scope", name="uq_system_configs_key_scope"),)

    config_key: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(String(120), default="global", nullable=False)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    value_type: Mapped[str] = mapped_column(String(30), default="json", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    effective_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    effective_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecretRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "secret_records"

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    encrypted_value: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(String(30), default="database_encrypted", nullable=False)
    provider_reference: Mapped[str | None] = mapped_column(String(512))
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class RateLimitBucket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "rate_limit_buckets"

    bucket_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BusinessHoliday(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "business_holidays"
    __table_args__ = (UniqueConstraint("calendar_code", "holiday_date", name="uq_business_holiday_date"),)

    calendar_code: Mapped[str] = mapped_column(String(80), default="global", nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    holiday_date: Mapped[date] = mapped_column(Date, nullable=False)


class ExceptionCategory(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "exception_categories"

    code: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("exception_categories.id", ondelete="SET NULL"))
    default_duration_days: Mapped[int | None] = mapped_column(Integer)
    maximum_duration_days: Mapped[int | None] = mapped_column(Integer)
    risk_level_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("risk_levels.id", ondelete="SET NULL"))
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class RiskLevel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "risk_levels"
    __table_args__ = (CheckConstraint("score >= 0 AND score <= 100", name="risk_score_range"),)

    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    color: Mapped[str] = mapped_column(String(20), default="#5f6368", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class DataClassification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "data_classifications"

    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    allow_ai: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_export: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ApprovalWorkflow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approval_workflows"

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    category_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("exception_categories.id", ondelete="SET NULL"))
    exception_type: Mapped[str | None] = mapped_column(String(100))
    risk_level_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("risk_levels.id", ondelete="SET NULL"))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    stages: Mapped[list[WorkflowStage]] = relationship(
        back_populates="workflow", cascade="all, delete-orphan", order_by="WorkflowStage.sequence"
    )


class WorkflowStage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "workflow_stages"
    __table_args__ = (
        UniqueConstraint("workflow_id", "sequence", name="uq_workflow_stage_sequence"),
        CheckConstraint("sequence > 0", name="workflow_stage_sequence_positive"),
    )

    workflow_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_workflows.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    stage_key: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sla_business_days: Mapped[int] = mapped_column(Integer, nullable=False)
    approver_group_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approver_groups.id", ondelete="SET NULL"))
    backup_approver_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    minimum_approvals: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    maximum_approvals: Mapped[int | None] = mapped_column(Integer)
    settings: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)

    workflow: Mapped[ApprovalWorkflow] = relationship(back_populates="stages")


class ApproverGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approver_groups"

    code: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("exception_categories.id", ondelete="SET NULL"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ApproverGroupMember(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approver_group_members"
    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_approver_group_member"),)

    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("approver_groups.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    is_backup: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    active_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Delegation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "delegations"
    __table_args__ = (
        CheckConstraint("end_at > start_at", name="delegation_end_after_start"),
    )

    delegator_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    delegate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    scope_type: Mapped[str] = mapped_column(String(30), default="category", nullable=False)
    scope_value: Mapped[str | None] = mapped_column(String(160))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ExceptionRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "exception_requests"
    __table_args__ = (
        CheckConstraint("version > 0", name="request_version_positive"),
        CheckConstraint("extension_count >= 0", name="extension_count_nonnegative"),
        CheckConstraint("requested_expiry_date >= requested_start_date", name="request_expiry_after_start"),
        Index("ix_requests_requester_status", "requester_id", "status"),
        Index("ix_requests_status_expiry", "status", "expiry_date"),
        Index("ix_requests_risk_status", "risk_level_id", "status"),
    )

    public_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    business_justification: Mapped[str] = mapped_column(Text, nullable=False)
    category_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exception_categories.id"), nullable=False)
    exception_type: Mapped[str] = mapped_column(String(120), nullable=False)
    department: Mapped[str] = mapped_column(String(160), nullable=False)
    manager_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    application_name: Mapped[str] = mapped_column(String(200), nullable=False)
    application_service_id: Mapped[str | None] = mapped_column(String(120))
    application_owner: Mapped[str | None] = mapped_column(String(200))
    business_owner: Mapped[str] = mapped_column(String(200), nullable=False)
    technology_owner: Mapped[str] = mapped_column(String(200), nullable=False)
    environment: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_system: Mapped[str] = mapped_column(String(240), nullable=False)
    cloud_account: Mapped[str | None] = mapped_column(String(200))
    data_classification_code: Mapped[str] = mapped_column(String(50), default="Internal", nullable=False)
    information_sensitivity: Mapped[str | None] = mapped_column(String(120))
    regulatory_impact: Mapped[str | None] = mapped_column(Text)
    control_excepted: Mapped[str] = mapped_column(String(500), nullable=False)
    current_control: Mapped[str] = mapped_column(Text, nullable=False)
    requested_exception: Mapped[str] = mapped_column(Text, nullable=False)
    reason_control_cannot_follow: Mapped[str] = mapped_column(Text, nullable=False)
    risk_description: Mapped[str] = mapped_column(Text, nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, nullable=False)
    security_impact: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_plan: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    remediation_target_date: Mapped[date | None] = mapped_column(Date)
    remediation_status: Mapped[str] = mapped_column(String(40), default="not_started", nullable=False)
    remediation_progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    remediation_closure_date: Mapped[date | None] = mapped_column(Date)
    requested_start_date: Mapped[date] = mapped_column(Date, nullable=False)
    requested_expiry_date: Mapped[date] = mapped_column(Date, nullable=False)
    requested_duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("risk_levels.id"), nullable=False)
    additional_comments: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default=RequestStatus.DRAFT, nullable=False, index=True)
    current_stage_key: Mapped[str | None] = mapped_column(String(100))
    original_expiry_date: Mapped[date] = mapped_column(Date, nullable=False)
    expiry_date: Mapped[date] = mapped_column(Date, nullable=False)
    extension_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pending_extension_expiry_date: Mapped[date | None] = mapped_column(Date)
    pending_extension_reason: Mapped[str | None] = mapped_column(Text)
    last_notification_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    workflow_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approval_workflows.id", ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_modified_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)

    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    manager: Mapped[User | None] = relationship(foreign_keys=[manager_id])
    category: Mapped[ExceptionCategory] = relationship()
    risk_level: Mapped[RiskLevel] = relationship()
    workflow: Mapped[ApprovalWorkflow | None] = relationship()
    approvals: Mapped[list[ApprovalAssignment]] = relationship(
        back_populates="request", cascade="all, delete-orphan"
    )
    comments: Mapped[list[Comment]] = relationship(back_populates="request", cascade="all, delete-orphan")
    attachments: Mapped[list[Attachment]] = relationship(back_populates="request", cascade="all, delete-orphan")

    __mapper_args__ = {"version_id_col": version}


class RequestFieldDefinition(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "request_field_definitions"

    field_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    data_type: Mapped[str] = mapped_column(String(40), nullable=False)
    is_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_value: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    placeholder: Mapped[str | None] = mapped_column(String(255))
    validation_schema: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    allowed_values: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    visible_roles: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    visible_categories: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    editable_after_submission: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class RequestTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reusable, non-authoritative starting point for a new exception request.

    Templates contain bounded configuration defaults only. They never grant an
    approval or bypass the normal request workflow.
    """

    __tablename__ = "request_templates"
    __table_args__ = (Index("ix_request_templates_active_category", "is_active", "category_id"),)

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("exception_categories.id", ondelete="SET NULL")
    )
    default_values: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    category: Mapped[ExceptionCategory | None] = relationship()
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])

    __mapper_args__ = {"version_id_col": version}


class RequestFieldValue(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "request_field_values"
    __table_args__ = (UniqueConstraint("request_id", "field_id", name="uq_request_field_value"),)

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exception_requests.id", ondelete="CASCADE"), nullable=False, index=True
    )
    field_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("request_field_definitions.id"), nullable=False
    )
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    created_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    updated_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))

    request: Mapped[ExceptionRequest] = relationship()
    field: Mapped[RequestFieldDefinition] = relationship()


class ApprovalAssignment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approval_assignments"
    __table_args__ = (
        Index("ix_approvals_assignee_status", "approver_id", "status", "due_at"),
        Index("ix_approvals_request_stage", "request_id", "stage_key"),
    )

    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exception_requests.id", ondelete="CASCADE"), nullable=False
    )
    workflow_stage_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workflow_stages.id", ondelete="SET NULL"))
    stage_key: Mapped[str] = mapped_column(String(100), nullable=False)
    stage_name: Mapped[str] = mapped_column(String(160), nullable=False)
    approver_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    delegated_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reminded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    request: Mapped[ExceptionRequest] = relationship(back_populates="approvals")
    approver: Mapped[User] = relationship(foreign_keys=[approver_id])
    actions: Mapped[list[ApprovalAction]] = relationship(back_populates="assignment")


class ApprovalAction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approval_actions"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_approval_action_idempotency"),)

    assignment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_assignments.id", ondelete="CASCADE"), nullable=False
    )
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exception_requests.id"), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    delegated_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decision: Mapped[str] = mapped_column(String(30), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    request_version: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)
    acted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    assignment: Mapped[ApprovalAssignment] = relationship(back_populates="actions")
    actor: Mapped[User] = relationship(foreign_keys=[actor_id])


class ApprovalToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "approval_tokens"

    assignment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_assignments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(50), default="approval", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_ip: Mapped[str | None] = mapped_column(String(64))
    last_used_ip: Mapped[str | None] = mapped_column(String(64))


class Comment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "comments"

    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exception_requests.id"), nullable=False, index=True)
    author_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("comments.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(40), default="comment", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_clarification_response: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    request: Mapped[ExceptionRequest] = relationship(back_populates="comments")
    author: Mapped[User] = relationship()


class Attachment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "attachments"
    __table_args__ = (CheckConstraint("size_bytes > 0", name="attachment_size_positive"),)

    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exception_requests.id"), nullable=False, index=True)
    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    content_type: Mapped[str] = mapped_column(String(160), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_status: Mapped[str] = mapped_column(String(30), default="quarantined", nullable=False)
    scan_engine: Mapped[str | None] = mapped_column(String(80))
    scan_engine_version: Mapped[str | None] = mapped_column(String(80))
    scan_result: Mapped[str | None] = mapped_column(Text)
    evidence_type: Mapped[str | None] = mapped_column(String(80))
    evidence_source: Mapped[str | None] = mapped_column(String(160))
    provided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    provided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extracted_text: Mapped[str | None] = mapped_column(Text)
    accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    access_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    request: Mapped[ExceptionRequest] = relationship(back_populates="attachments")
    uploader: Mapped[User] = relationship(foreign_keys=[uploaded_by_id])


class Notification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_notification_idempotency_key"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("exception_requests.id", ondelete="CASCADE"))
    notification_type: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(240), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    action_url: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(1000))

    user: Mapped[User] = relationship()
    request: Mapped[ExceptionRequest | None] = relationship()


class EmailTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "email_templates"
    __table_args__ = (UniqueConstraint("event_key", "locale", "version", name="uq_email_template_version"),)

    event_key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    locale: Mapped[str] = mapped_column(String(20), default="en", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    subject_template: Mapped[str] = mapped_column(String(500), nullable=False)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_variables: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    validation_error: Mapped[str | None] = mapped_column(Text)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class BackgroundJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "background_jobs"
    __table_args__ = (
        UniqueConstraint("deduplication_key", name="uq_background_job_dedupe"),
        Index("ix_jobs_claim", "status", "run_at", "locked_until"),
    )

    job_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    payload: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    locked_by: Mapped[str | None] = mapped_column(String(160))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    deduplication_key: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    last_error: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def next_backoff_seconds(self) -> int:
        return min(3600, 2 ** min(self.attempts, 10) * 15)


class AiAnalysis(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (Index("ix_ai_request_feature", "request_id", "feature", "created_at"),)

    request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("exception_requests.id", ondelete="CASCADE"))
    feature: Mapped[str] = mapped_column(String(80), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(30), nullable=False)
    deployment_name: Mapped[str | None] = mapped_column(String(160))
    model_name: Mapped[str | None] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_token_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_token_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(String(30))
    confidence: Mapped[float | None] = mapped_column(Float)
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(String(1000))
    injection_indicators: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AiHistoricalReference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_historical_references"
    __table_args__ = (UniqueConstraint("analysis_id", "historical_request_id", name="uq_ai_historical_reference"),)

    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_analyses.id", ondelete="CASCADE"), nullable=False)
    historical_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("exception_requests.id", ondelete="CASCADE"), nullable=False
    )
    similarity_reason: Mapped[str] = mapped_column(Text, nullable=False)
    historical_decision: Mapped[str | None] = mapped_column(String(40))
    historical_risk_level: Mapped[str | None] = mapped_column(String(40))


class AiRecommendation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_recommendations"

    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_analyses.id", ondelete="CASCADE"), nullable=False)
    recommendation_type: Mapped[str] = mapped_column(String(80), nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class AiLogFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ai_log_findings"
    __table_args__ = (Index("ix_ai_log_findings_window", "window_start", "window_end"),)

    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_analyses.id", ondelete="CASCADE"), nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(320))
    event_type: Mapped[str] = mapped_column(String(200), nullable=False)
    reason_flagged: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    supporting_evidence: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_investigation: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_malicious_claim: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AuditEvent(TimestampMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("event_hash", name="uq_audit_event_hash"),
        Index("ix_audit_object", "object_type", "object_id", "occurred_at"),
        Index("ix_audit_actor", "actor_id", "occurred_at"),
        Index("ix_audit_action", "action", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_label: Mapped[str | None] = mapped_column(String(320))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    action: Mapped[str] = mapped_column(String(160), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(100))
    object_id: Mapped[str | None] = mapped_column(String(100))
    old_value: Mapped[Any | None] = mapped_column(JSON)
    new_value: Mapped[Any | None] = mapped_column(JSON)
    result: Mapped[str] = mapped_column(String(30), default="success", nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(1000))
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    request_id: Mapped[str | None] = mapped_column(String(64))
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    retention_archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def immutable(self) -> bool:
        return True


class AuditArchive(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_archives"

    source_event_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    event_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    original_occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    archive_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(80), nullable=False)
    retention_reason: Mapped[str] = mapped_column(Text, nullable=False)


class IdempotencyRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("actor_id", "operation", "idempotency_key", name="uq_idempotency_operation"),)

    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_body: Mapped[Any] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BackupRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "backup_records"

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    backup_type: Mapped[str] = mapped_column(String(30), default="manual", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False)
    location_uri: Mapped[str | None] = mapped_column(String(1000))
    file_name: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    verification_status: Mapped[str | None] = mapped_column(String(40))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str] = mapped_column(String(64))


class ExportRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "export_records"

    requested_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    export_type: Mapped[str] = mapped_column(String(80), nullable=False)
    scope: Mapped[Any] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False)
    location_uri: Mapped[str | None] = mapped_column(String(1000))
    row_count: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)


class RemediationUpdate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "remediation_updates"

    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exception_requests.id"), nullable=False, index=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    from_status: Mapped[str] = mapped_column(String(40), nullable=False)
    to_status: Mapped[str] = mapped_column(String(40), nullable=False)
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_attachment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("attachments.id", ondelete="SET NULL"))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
