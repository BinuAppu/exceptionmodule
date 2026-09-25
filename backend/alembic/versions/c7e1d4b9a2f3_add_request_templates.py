"""add normalized request templates

Revision ID: c7e1d4b9a2f3
Revises: c4e8a1b2d3f4
Create Date: 2026-09-24 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7e1d4b9a2f3"
down_revision: str | Sequence[str] | None = "c4e8a1b2d3f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "request_templates",
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category_id", sa.Uuid(), nullable=True),
        sa.Column("default_values", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["category_id"],
            ["exception_categories.id"],
            name=op.f("fk_request_templates_category_id_exception_categories"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_request_templates_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_request_templates")),
    )
    with op.batch_alter_table("request_templates", schema=None) as batch_op:
        batch_op.create_index(
            "ix_request_templates_active_category", ["is_active", "category_id"], unique=False
        )
        batch_op.create_index(
            op.f("ix_request_templates_created_at"), ["created_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("request_templates", schema=None) as batch_op:
        batch_op.drop_index(op.f("ix_request_templates_created_at"))
        batch_op.drop_index("ix_request_templates_active_category")
    op.drop_table("request_templates")
