"""add normalized runtime SSO configuration

Revision ID: c4e8a1b2d3f4
Revises: d58e9143a8d0
Create Date: 2026-09-24 00:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4e8a1b2d3f4"
down_revision: Union[str, Sequence[str], None] = "d58e9143a8d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sso_providers",
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("provider IN ('oidc', 'saml')", name="sso_provider_type_valid"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], name="fk_sso_providers_created_by_id_users", ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name="pk_sso_providers"),
        sa.UniqueConstraint("provider", name="uq_sso_providers_provider"),
    )
    with op.batch_alter_table("sso_providers", schema=None) as batch_op:
        batch_op.create_index("ix_sso_providers_created_at", ["created_at"], unique=False)

    op.create_table(
        "sso_provider_configs",
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("active_slot", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("display_name", sa.String(length=160), nullable=False),
        sa.Column("issuer", sa.String(length=2048), nullable=True),
        sa.Column("client_id", sa.String(length=512), nullable=True),
        sa.Column("scopes", sa.String(length=1000), nullable=False),
        sa.Column("redirect_uri", sa.String(length=2048), nullable=True),
        sa.Column("required_acr", sa.String(length=255), nullable=True),
        sa.Column("email_claim", sa.String(length=255), nullable=False),
        sa.Column("name_claim", sa.String(length=255), nullable=False),
        sa.Column("tenant_claim", sa.String(length=255), nullable=True),
        sa.Column("tenant_value", sa.String(length=255), nullable=True),
        sa.Column("allowed_domains", sa.JSON(), nullable=False),
        sa.Column("auto_provision", sa.Boolean(), nullable=False),
        sa.Column("idp_entity_id", sa.String(length=2048), nullable=True),
        sa.Column("sso_url", sa.String(length=2048), nullable=True),
        sa.Column("idp_x509_certificate", sa.Text(), nullable=True),
        sa.Column("email_attribute", sa.String(length=255), nullable=False),
        sa.Column("name_attribute", sa.String(length=255), nullable=False),
        sa.Column("sp_entity_id", sa.String(length=2048), nullable=True),
        sa.Column("acs_url", sa.String(length=2048), nullable=True),
        sa.Column("sp_x509_certificate", sa.Text(), nullable=True),
        sa.Column("metadata_url", sa.String(length=2048), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("active_slot IS NULL OR active_slot = 1", name="sso_provider_active_slot_valid"),
        sa.CheckConstraint(
            "(is_active = false AND active_slot IS NULL) OR (is_active = true AND active_slot = 1)",
            name="sso_provider_active_flag_valid",
        ),
        sa.CheckConstraint("version > 0", name="sso_provider_config_version_positive"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], name="fk_sso_provider_configs_created_by_id_users", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["provider_id"], ["sso_providers.id"], name="fk_sso_provider_configs_provider_id_sso_providers", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_sso_provider_configs"),
        sa.UniqueConstraint("provider_id", "active_slot", name="uq_sso_provider_active_config"),
        sa.UniqueConstraint("provider_id", "version", name="uq_sso_provider_config_version"),
    )
    with op.batch_alter_table("sso_provider_configs", schema=None) as batch_op:
        batch_op.create_index("ix_sso_provider_configs_active", ["is_active", "provider_id"], unique=False)
        batch_op.create_index("ix_sso_provider_configs_created_at", ["created_at"], unique=False)
        batch_op.create_index("ix_sso_provider_configs_provider_id", ["provider_id"], unique=False)

    op.create_table(
        "sso_external_identities",
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("email_at_link", sa.String(length=320), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["provider_id"], ["sso_providers.id"], name="fk_sso_external_identities_provider_id_sso_providers", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_sso_external_identities_user_id_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_sso_external_identities"),
        sa.UniqueConstraint("provider_id", "subject", name="uq_sso_external_identity_subject"),
    )
    with op.batch_alter_table("sso_external_identities", schema=None) as batch_op:
        batch_op.create_index("ix_sso_external_identity_user", ["user_id", "provider_id"], unique=False)
        batch_op.create_index("ix_sso_external_identities_created_at", ["created_at"], unique=False)

    op.create_table(
        "sso_secret_records",
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("config_id", sa.Uuid(), nullable=False),
        sa.Column("secret_type", sa.String(length=80), nullable=False),
        sa.Column("encrypted_value", sa.Text(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("changed_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("key_version > 0", name="sso_secret_key_version_positive"),
        sa.ForeignKeyConstraint(["changed_by_id"], ["users.id"], name="fk_sso_secret_records_changed_by_id_users", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["config_id"], ["sso_provider_configs.id"], name="fk_sso_secret_records_config_id_sso_provider_configs", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["sso_providers.id"], name="fk_sso_secret_records_provider_id_sso_providers", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_sso_secret_records"),
        sa.UniqueConstraint("config_id", "secret_type", "key_version", name="uq_sso_secret_version"),
    )
    with op.batch_alter_table("sso_secret_records", schema=None) as batch_op:
        batch_op.create_index("ix_sso_secret_active", ["provider_id", "secret_type", "is_active"], unique=False)
        batch_op.create_index("ix_sso_secret_records_created_at", ["created_at"], unique=False)

    op.create_table(
        "sso_login_transactions",
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("config_id", sa.Uuid(), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("transaction_type", sa.String(length=20), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=True),
        sa.Column("nonce_hash", sa.String(length=64), nullable=True),
        sa.Column("pkce_verifier_hash", sa.String(length=64), nullable=True),
        sa.Column("browser_binding_hash", sa.String(length=64), nullable=False),
        sa.Column("relay_state_hash", sa.String(length=64), nullable=True),
        sa.Column("request_id_hash", sa.String(length=64), nullable=True),
        sa.Column("encrypted_payload", sa.Text(), nullable=False),
        sa.Column("return_path", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(length=80), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("transaction_type IN ('oidc', 'saml')", name="sso_transaction_type_valid"),
        sa.ForeignKeyConstraint(["config_id"], ["sso_provider_configs.id"], name="fk_sso_login_transactions_config_id_sso_provider_configs", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["sso_providers.id"], name="fk_sso_login_transactions_provider_id_sso_providers", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_sso_login_transactions"),
        sa.UniqueConstraint("nonce_hash", name="uq_sso_login_transactions_nonce_hash"),
        sa.UniqueConstraint("relay_state_hash", name="uq_sso_login_transactions_relay_state_hash"),
        sa.UniqueConstraint("request_id_hash", name="uq_sso_login_transactions_request_id_hash"),
        sa.UniqueConstraint("state_hash", name="uq_sso_login_transactions_state_hash"),
    )
    with op.batch_alter_table("sso_login_transactions", schema=None) as batch_op:
        batch_op.create_index("ix_sso_login_transactions_created_at", ["created_at"], unique=False)
        batch_op.create_index("ix_sso_transactions_expiry", ["expires_at", "consumed_at"], unique=False)
        batch_op.create_index("ix_sso_transactions_provider", ["provider_id", "config_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("sso_login_transactions", schema=None) as batch_op:
        batch_op.drop_index("ix_sso_transactions_provider")
        batch_op.drop_index("ix_sso_transactions_expiry")
        batch_op.drop_index("ix_sso_login_transactions_created_at")
    op.drop_table("sso_login_transactions")

    with op.batch_alter_table("sso_secret_records", schema=None) as batch_op:
        batch_op.drop_index("ix_sso_secret_records_created_at")
        batch_op.drop_index("ix_sso_secret_active")
    op.drop_table("sso_secret_records")

    with op.batch_alter_table("sso_external_identities", schema=None) as batch_op:
        batch_op.drop_index("ix_sso_external_identities_created_at")
        batch_op.drop_index("ix_sso_external_identity_user")
    op.drop_table("sso_external_identities")

    with op.batch_alter_table("sso_provider_configs", schema=None) as batch_op:
        batch_op.drop_index("ix_sso_provider_configs_created_at")
        batch_op.drop_index("ix_sso_provider_configs_provider_id")
        batch_op.drop_index("ix_sso_provider_configs_active")
    op.drop_table("sso_provider_configs")
    with op.batch_alter_table("sso_providers", schema=None) as batch_op:
        batch_op.drop_index("ix_sso_providers_created_at")
    op.drop_table("sso_providers")
