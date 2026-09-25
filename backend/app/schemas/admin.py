from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import MessageResponse
from app.schemas.sso import (
    SSOConfig,
    SSOConfigResponse,
    SSOConfigUpdate,
    SSOConfiguration,
    SSOConfigurationRequest,
    SSOConfigurationResponse,
    SSOConfigurationUpdate,
    SSOConfigurationView,
    SSOValidateRequest,
    SSOValidationResponse,
    SSOValidationResult,
)


class ConfigUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    value: Any
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = False


class UserAdminUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    display_name: str | None = Field(default=None, min_length=2, max_length=160)
    department: str | None = Field(default=None, max_length=160)
    job_title: str | None = Field(default=None, max_length=160)
    manager_id: str | None = None
    status: Literal["active", "disabled", "locked"] | None = None
    roles: list[Literal["user", "approver", "admin"]] | None = None
    reason: str = Field(min_length=5, max_length=2_000)


class CategoryCreate(BaseModel):
    code: str = Field(pattern=r"^[a-z0-9_]+$", max_length=80)
    name: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    parent_id: str | None = None
    default_duration_days: int | None = Field(default=None, ge=1, le=3650)
    maximum_duration_days: int | None = Field(default=None, ge=1, le=3650)
    risk_level_id: str | None = None
    display_order: int = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_category_dates(self) -> CategoryCreate:
        if (
            self.default_duration_days is not None
            and self.maximum_duration_days is not None
            and self.default_duration_days > self.maximum_duration_days
        ):
            raise ValueError("Default duration cannot exceed category maximum")
        return self


class CategoryUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    default_duration_days: int | None = Field(default=None, ge=1, le=3650)
    maximum_duration_days: int | None = Field(default=None, ge=1, le=3650)
    is_active: bool | None = None
    reason: str = Field(min_length=5, max_length=2_000)


class FieldCreate(BaseModel):
    field_key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,98}[a-z0-9]$", max_length=100)
    label: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    data_type: Literal[
        "text",
        "long_text",
        "number",
        "date",
        "datetime",
        "boolean",
        "dropdown",
        "multi_select",
        "user_selector",
        "application_selector",
        "attachment",
        "url",
    ]
    is_required: bool = False
    default_value: Any = None
    placeholder: str | None = Field(default=None, max_length=255)
    validation_schema: dict[str, Any] = Field(default_factory=dict)
    allowed_values: list[Any] = Field(default_factory=list)
    visible_roles: list[str] = Field(default_factory=list)
    visible_categories: list[str] = Field(default_factory=list)
    editable_after_submission: bool = False
    display_order: int = Field(default=100, ge=0, le=10_000)


class FieldUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    label: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    is_required: bool | None = None
    default_value: Any = None
    placeholder: str | None = Field(default=None, max_length=255)
    validation_schema: dict[str, Any] | None = None
    allowed_values: list[Any] | None = None
    visible_roles: list[str] | None = None
    visible_categories: list[str] | None = None
    editable_after_submission: bool | None = None
    display_order: int | None = Field(default=None, ge=0, le=10_000)
    is_active: bool | None = None
    reason: str = Field(min_length=5, max_length=2_000)


class RequestTemplateCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    category_id: str | None = None
    is_active: bool = True
    default_values: dict[str, Any] = Field(default_factory=dict)


class RequestTemplateUpdate(BaseModel):
    expected_version: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2_000)
    category_id: str | None = None
    is_active: bool | None = None
    default_values: dict[str, Any] | None = None


class EmailTemplateUpsert(BaseModel):
    event_key: str = Field(pattern=r"^[a-z0-9_.-]+$", max_length=100)
    name: str = Field(min_length=2, max_length=160)
    locale: str = Field(default="en", pattern=r"^[a-z]{2}(?:-[A-Z]{2})?$", max_length=20)
    subject_template: str = Field(min_length=3, max_length=500)
    body_template: str = Field(min_length=10, max_length=50_000)
    allowed_variables: list[str] = Field(default_factory=list)
    activate: bool = False
    reason: str = Field(min_length=5, max_length=2_000)


class EmailPreviewRequest(BaseModel):
    subject_template: str = Field(min_length=1, max_length=500)
    body_template: str = Field(min_length=1, max_length=50_000)
    sample_values: dict[str, str] = Field(default_factory=dict)


class AiConfigurationUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    enabled: bool
    endpoint: str | None = Field(default=None, max_length=500)
    api_version: str = Field(default="2024-10-21", max_length=30)
    deployment: str | None = Field(default=None, max_length=160)
    auth_mode: Literal["api_key", "managed_identity"] = "api_key"
    api_key: str | None = Field(default=None, min_length=8, max_length=2_000)
    timeout_seconds: int = Field(default=45, ge=5, le=300)
    token_limit: int = Field(default=12000, ge=1000, le=100_000)
    features: dict[str, bool] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = False


class DelegationCreate(BaseModel):
    delegator_id: str
    delegate_id: str
    start_at: datetime
    end_at: datetime
    reason: str = Field(min_length=5, max_length=2_000)
    scope_type: Literal["all", "category", "type", "workflow"] = "category"
    scope_value: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def validate_window(self) -> DelegationCreate:
        if self.end_at <= self.start_at:
            raise ValueError("Delegation end must be after its start")
        if (self.end_at - self.start_at).days > 365:
            raise ValueError("Delegations cannot exceed one year")
        if self.delegator_id == self.delegate_id:
            raise ValueError("A user cannot delegate to themselves")
        return self


class BackupCreate(BaseModel):
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = False


class RetentionRun(BaseModel):
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = False


class SecurityConfigUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    values: dict[str, Any]
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = True


class WorkflowStageInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    stage_key: str = Field(pattern=r"^[a-z0-9_.-]+$", max_length=100)
    kind: Literal["manager", "delivery_head", "exception_approver", "final"]
    sequence: int = Field(ge=1, le=50)
    required: bool = True
    sla_business_days: int = Field(ge=1, le=365)
    approver_group_id: str | None = None
    backup_approver_id: str | None = None
    minimum_approvals: int = Field(default=1, ge=1, le=20)
    maximum_approvals: int | None = Field(default=None, ge=1, le=20)
    settings: dict[str, Any] = Field(default_factory=dict)


class WorkflowUpsert(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    category_id: str | None = None
    exception_type: str | None = Field(default=None, max_length=120)
    risk_level_id: str | None = None
    is_default: bool = False
    stages: list[WorkflowStageInput] = Field(min_length=1, max_length=20)
    activate: bool = False
    reason: str = Field(min_length=5, max_length=2_000)
    reauthenticated: bool = True

    @model_validator(mode="after")
    def validate_stage_order(self) -> WorkflowUpsert:
        sequences = [stage.sequence for stage in self.stages]
        if len(set(sequences)) != len(sequences):
            raise ValueError("Workflow stage sequences must be unique")
        if sorted(sequences) != list(range(1, len(sequences) + 1)):
            raise ValueError("Workflow stages must be sequentially numbered")
        for stage in self.stages:
            if stage.maximum_approvals is not None and stage.maximum_approvals < stage.minimum_approvals:
                raise ValueError("Maximum approvals cannot be below minimum approvals")
        return self


class AuditExportCreate(BaseModel):
    start_date: date
    end_date: date
    format: Literal["csv", "jsonl"] = "csv"
    reason: str = Field(min_length=5, max_length=2_000)
