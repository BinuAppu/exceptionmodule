from __future__ import annotations

import uuid
from typing import TypeVar

from sqlalchemy import Select, select
from sqlalchemy.orm import Session as DbSession, selectinload

from app.core.errors import AuthorizationError, NotFoundError
from app.models import (
    ApprovalAssignment,
    Comment,
    ExceptionCategory,
    ExceptionRequest,
    RequestFieldDefinition,
    RiskLevel,
    User,
)
from app.schemas.common import AuditContext
from app.services.audit import record_audit
from app.services.authz import Principal

ModelWithPublicId = TypeVar("ModelWithPublicId", ExceptionCategory, RiskLevel, User)


def resolve_model_id(db: DbSession, model: type[ModelWithPublicId], value: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        parsed = None
    obj = db.get(model, parsed) if parsed else None
    if obj is None:
        # User records expose public_id; reference entities such as categories and
        # risk levels intentionally expose a stable business code instead.
        lookup_column = getattr(model, "public_id", None) or getattr(model, "code", None)
        if lookup_column is not None:
            obj = db.scalar(select(model).where(lookup_column == value))
    if obj is None:
        raise NotFoundError(f"{model.__name__} was not found")
    return obj.id


def _request_query() -> Select[tuple[ExceptionRequest]]:
    return select(ExceptionRequest).options(
        selectinload(ExceptionRequest.approvals),
        selectinload(ExceptionRequest.comments).selectinload(Comment.author),
        selectinload(ExceptionRequest.attachments),
        selectinload(ExceptionRequest.category),
        selectinload(ExceptionRequest.risk_level),
        selectinload(ExceptionRequest.requester),
        selectinload(ExceptionRequest.manager),
    )


def can_view_request(principal: Principal, request: ExceptionRequest, db: DbSession) -> bool:
    if not principal.is_authenticated:
        return False
    if principal.has_role("admin"):
        return True
    if request.requester_id == principal.user.id:
        return True
    return bool(
        db.scalar(
            select(ApprovalAssignment.id).where(
                ApprovalAssignment.request_id == request.id,
                ApprovalAssignment.approver_id == principal.user.id,
                ApprovalAssignment.status.in_(["pending", "clarification"]),
            )
        )
    )


def get_authorized_request(
    db: DbSession,
    identifier: str,
    principal: Principal,
    *,
    lock: bool = False,
    audit_read: bool = False,
    context: AuditContext | None = None,
) -> ExceptionRequest:
    try:
        parsed = uuid.UUID(identifier)
    except (ValueError, AttributeError):
        parsed = None
    query = _request_query().where(
        ExceptionRequest.id == parsed if parsed else ExceptionRequest.public_id == identifier
    )
    if lock:
        query = query.with_for_update()
    request = db.scalar(query)
    if request is None or not can_view_request(principal, request, db):
        # Deliberately use the same response for nonexistent and unauthorized objects.
        raise NotFoundError("Exception request was not found")
    if audit_read and context:
        record_audit(
            db,
            context,
            action="request.view",
            object_type="exception_request",
            object_id=request.public_id,
        )
    return request


def scoped_requests_query(principal: Principal):
    query = _request_query()
    if principal.has_role("admin"):
        return query
    if principal.has_role("approver"):
        return query.where(
            (ExceptionRequest.requester_id == principal.user.id)
            | ExceptionRequest.approvals.any(
                (ApprovalAssignment.approver_id == principal.user.id)
                & ApprovalAssignment.status.in_(["pending", "clarification"])
            )
        )
    return query.where(ExceptionRequest.requester_id == principal.user.id)


def require_owner(principal: Principal, request: ExceptionRequest) -> None:
    if request.requester_id != principal.user.id and not principal.has_role("admin"):
        raise AuthorizationError("Only the requester can perform this action")


def validate_custom_field(
    db: DbSession,
    definition: RequestFieldDefinition,
    value,
    *,
    category_id: uuid.UUID,
) -> None:
    from datetime import date, datetime
    from urllib.parse import urlparse

    if definition.data_type in {"text", "long_text"}:
        if not isinstance(value, str):
            raise ValueError(f"{definition.label} must be text")
        minimum = int(definition.validation_schema.get("min_length", 0))
        maximum = int(definition.validation_schema.get("max_length", 10_000))
        if not minimum <= len(value) <= maximum:
            raise ValueError(f"{definition.label} must be between {minimum} and {maximum} characters")
    elif definition.data_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{definition.label} must be a number")
        if "minimum" in definition.validation_schema and value < definition.validation_schema["minimum"]:
            raise ValueError(f"{definition.label} is below the configured minimum")
        if "maximum" in definition.validation_schema and value > definition.validation_schema["maximum"]:
            raise ValueError(f"{definition.label} exceeds the configured maximum")
    elif definition.data_type == "date" and not isinstance(value, date):
        raise ValueError(f"{definition.label} must be a date")
    elif definition.data_type == "datetime" and not isinstance(value, datetime):
        raise ValueError(f"{definition.label} must be a date/time")
    elif definition.data_type == "boolean" and not isinstance(value, bool):
        raise ValueError(f"{definition.label} must be true or false")
    elif definition.data_type == "dropdown" and value not in definition.allowed_values:
        raise ValueError(f"{definition.label} has an unsupported value")
    elif definition.data_type == "multi_select":
        if not isinstance(value, list) or any(item not in definition.allowed_values for item in value):
            raise ValueError(f"{definition.label} has an unsupported value")
    elif definition.data_type == "user_selector" and (not isinstance(value, str) or resolve_model_id(db, User, value) is None):
        raise ValueError(f"{definition.label} must reference a valid user")
    elif definition.data_type == "url":
        parsed = urlparse(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{definition.label} must be an HTTP(S) URL")
    if definition.visible_categories and str(category_id) not in {str(item) for item in definition.visible_categories}:
        raise ValueError(f"{definition.label} is not applicable to this category")
