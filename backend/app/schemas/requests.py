from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RequestStatusLiteral = Literal[
    "draft",
    "submitted",
    "pending_manager_approval",
    "manager_approved",
    "pending_delivery_head_approval",
    "delivery_head_approved",
    "pending_approver_review",
    "clarification_required",
    "approved",
    "rejected",
    "active",
    "extension_requested",
    "extension_pending_approval",
    "expired",
    "cancelled",
    "withdrawn",
    "closed",
]


class RequestCreate(BaseModel):
    title: str = Field(min_length=5, max_length=240)
    description: str = Field(min_length=20, max_length=30_000)
    business_justification: str = Field(min_length=20, max_length=30_000)
    category_id: str
    exception_type: str = Field(min_length=2, max_length=120)
    department: str = Field(min_length=2, max_length=160)
    application_name: str = Field(min_length=2, max_length=200)
    application_service_id: str | None = Field(default=None, max_length=120)
    application_owner: str | None = Field(default=None, max_length=200)
    business_owner: str = Field(min_length=2, max_length=200)
    technology_owner: str = Field(min_length=2, max_length=200)
    environment: str = Field(min_length=2, max_length=80)
    asset_system: str = Field(min_length=2, max_length=240)
    cloud_account: str | None = Field(default=None, max_length=200)
    data_classification_code: str = "Internal"
    information_sensitivity: str | None = Field(default=None, max_length=120)
    regulatory_impact: str | None = Field(default=None, max_length=10_000)
    control_excepted: str = Field(min_length=3, max_length=500)
    current_control: str = Field(min_length=10, max_length=30_000)
    requested_exception: str = Field(min_length=10, max_length=30_000)
    reason_control_cannot_follow: str = Field(min_length=10, max_length=30_000)
    risk_description: str = Field(min_length=10, max_length=30_000)
    business_impact: str = Field(min_length=5, max_length=30_000)
    security_impact: str = Field(min_length=5, max_length=30_000)
    compensating_controls: str = Field(min_length=10, max_length=30_000)
    remediation_plan: str = Field(min_length=10, max_length=30_000)
    remediation_owner_id: str | None = None
    remediation_target_date: date | None = None
    requested_start_date: date
    requested_expiry_date: date
    risk_level_id: str
    additional_comments: str | None = Field(default=None, max_length=10_000)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def dates_are_ordered(self) -> RequestCreate:
        if self.requested_expiry_date < self.requested_start_date:
            raise ValueError("Requested expiry must not be before the start date")
        return self


class RequestUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=5, max_length=240)
    description: str | None = Field(default=None, min_length=20, max_length=30_000)
    business_justification: str | None = Field(default=None, min_length=20, max_length=30_000)
    category_id: str | None = None
    exception_type: str | None = Field(default=None, min_length=2, max_length=120)
    department: str | None = Field(default=None, min_length=2, max_length=160)
    application_name: str | None = Field(default=None, min_length=2, max_length=200)
    application_service_id: str | None = Field(default=None, max_length=120)
    application_owner: str | None = Field(default=None, max_length=200)
    business_owner: str | None = Field(default=None, min_length=2, max_length=200)
    technology_owner: str | None = Field(default=None, min_length=2, max_length=200)
    environment: str | None = Field(default=None, min_length=2, max_length=80)
    asset_system: str | None = Field(default=None, min_length=2, max_length=240)
    cloud_account: str | None = Field(default=None, max_length=200)
    data_classification_code: str | None = None
    information_sensitivity: str | None = Field(default=None, max_length=120)
    regulatory_impact: str | None = Field(default=None, max_length=10_000)
    control_excepted: str | None = Field(default=None, min_length=3, max_length=500)
    current_control: str | None = Field(default=None, min_length=10, max_length=30_000)
    requested_exception: str | None = Field(default=None, min_length=10, max_length=30_000)
    reason_control_cannot_follow: str | None = Field(default=None, min_length=10, max_length=30_000)
    risk_description: str | None = Field(default=None, min_length=10, max_length=30_000)
    business_impact: str | None = Field(default=None, min_length=5, max_length=30_000)
    security_impact: str | None = Field(default=None, min_length=5, max_length=30_000)
    compensating_controls: str | None = Field(default=None, min_length=10, max_length=30_000)
    remediation_plan: str | None = Field(default=None, min_length=10, max_length=30_000)
    remediation_owner_id: str | None = None
    remediation_target_date: date | None = None
    requested_start_date: date | None = None
    requested_expiry_date: date | None = None
    risk_level_id: str | None = None
    additional_comments: str | None = Field(default=None, max_length=10_000)
    custom_fields: dict[str, Any] | None = None

    @field_validator("remediation_target_date")
    @classmethod
    def reject_impossible_year(cls, value: date | None) -> date | None:
        if value and not 2000 <= value.year <= 2200:
            raise ValueError("Invalid remediation target date")
        return value


class SubmitRequest(BaseModel):
    expected_version: int = Field(ge=1)
    attestation: bool


class ApprovalDecisionRequest(BaseModel):
    expected_version: int = Field(ge=1)
    decision: Literal["approve", "reject", "request_clarification"]
    comment: str | None = Field(default=None, max_length=10_000)
    reason: str | None = Field(default=None, max_length=10_000)
    idempotency_key: str = Field(min_length=16, max_length=100)


class ClarificationResponseRequest(BaseModel):
    expected_version: int = Field(ge=1)
    message: str = Field(min_length=2, max_length=10_000)
    custom_fields: dict[str, Any] | None = None


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


class ExtensionCreate(BaseModel):
    expected_version: int = Field(ge=1)
    requested_expiry_date: date
    reason: str = Field(min_length=10, max_length=10_000)


class WithdrawRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=5, max_length=2_000)


class RemediationUpdateCreate(BaseModel):
    status: Literal["not_started", "in_progress", "blocked", "completed"]
    progress_percent: int = Field(ge=0, le=100)
    notes: str = Field(min_length=2, max_length=10_000)
    evidence_attachment_id: str | None = None


class CloseRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=2_000)
    remediation_completed: bool
    evidence_attachment_id: str | None = None


class AttachmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    scan_status: str
    evidence_type: str | None
    provided_by: str | None
    provided_at: datetime | None
    created_at: datetime


class CommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    author_id: str
    author_name: str
    kind: str
    body: str
    is_clarification_response: bool
    created_at: datetime


class ApprovalResponse(BaseModel):
    id: str
    stage_key: str
    stage_name: str
    approver_id: str
    approver_name: str
    delegated_from_id: str | None
    delegated_from_name: str | None
    status: str
    due_at: datetime
    completed_at: datetime | None
    decision: str | None
    decision_comment: str | None


class RequestSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    title: str
    exception_type: str
    category_name: str
    requester_id: str
    requester_name: str
    department: str
    application_name: str
    environment: str
    data_classification_code: str
    risk_level: str
    status: str
    current_stage_key: str | None
    requested_start_date: date
    expiry_date: date
    extension_count: int
    version: int
    created_at: datetime
    updated_at: datetime


class RequestDetail(RequestSummary):
    description: str
    business_justification: str
    manager_id: str | None
    manager_name: str | None
    application_service_id: str | None
    application_owner: str | None
    business_owner: str
    technology_owner: str
    asset_system: str
    cloud_account: str | None
    information_sensitivity: str | None
    regulatory_impact: str | None
    control_excepted: str
    current_control: str
    requested_exception: str
    reason_control_cannot_follow: str
    risk_description: str
    business_impact: str
    security_impact: str
    compensating_controls: str
    remediation_plan: str
    remediation_owner_id: str | None
    remediation_owner_name: str | None
    remediation_target_date: date | None
    remediation_status: str
    remediation_progress: int
    remediation_closure_date: date | None
    requested_duration_days: int
    additional_comments: str | None
    original_expiry_date: date
    submitted_at: datetime | None
    activated_at: datetime | None
    expired_at: datetime | None
    closed_at: datetime | None
    approvals: list[ApprovalResponse]
    comments: list[CommentResponse]
    attachments: list[AttachmentResponse]
    custom_fields: dict[str, Any]
    ai_analyses: list[dict[str, Any]]
    audit_timeline: list[dict[str, Any]]
    can_edit: bool = False
    can_decide_assignment_id: str | None = None
