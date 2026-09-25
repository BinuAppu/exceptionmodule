from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from app.core.errors import ConflictError, DomainError
from app.core.security import public_reference
from app.models import (
    AiAnalysis,
    ApprovalAction,
    ApprovalAssignment,
    Comment,
    ExceptionCategory,
    ExceptionRequest,
    RequestFieldDefinition,
    RequestFieldValue,
    RequestStatus,
    RiskLevel,
    User,
)
from app.schemas.common import AuditContext
from app.schemas.requests import RequestCreate, RequestUpdate
from app.services.audit import record_audit, timeline_for_request
from app.services.authz import Principal
from app.services.authorization import (
    require_owner,
    resolve_model_id,
    scoped_requests_query,
    validate_custom_field,
)

REQUEST_SORT_COLUMNS = {
    "created": ExceptionRequest.created_at,
    "updated": ExceptionRequest.updated_at,
    "expiry": ExceptionRequest.expiry_date,
    "risk": RiskLevel.score,
    "title": ExceptionRequest.title,
    "status": ExceptionRequest.status,
}


def _context(request, principal: Principal) -> AuditContext:
    return AuditContext(
        actor_id=str(principal.user.id),
        actor_label=principal.user.email,
        source_ip=getattr(request.state, "client_ip", None) or (request.client.host if request.client else None),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        request_id=getattr(request.state, "request_id", None),
        correlation_id=request.state.correlation_id,
    )


def _set_custom_fields(
    db: DbSession,
    request: ExceptionRequest,
    values: dict[str, Any],
    actor: User,
    category_id,
) -> None:
    definitions = {
        definition.field_key: definition
        for definition in db.scalars(select(RequestFieldDefinition).where(RequestFieldDefinition.is_active.is_(True)))
    }
    unknown = set(values) - set(definitions)
    if unknown:
        raise DomainError("One or more custom fields are invalid", code="invalid_custom_field")
    existing = {
        value.field_id: value
        for value in db.scalars(select(RequestFieldValue).where(RequestFieldValue.request_id == request.id))
    }
    for key, value in values.items():
        definition = definitions[key]
        validate_custom_field(db, definition, value, category_id=category_id)
        field_value = existing.get(definition.id)
        if field_value:
            field_value.value = value
            field_value.updated_by_id = actor.id
        else:
            db.add(
                RequestFieldValue(
                    request_id=request.id,
                    field_id=definition.id,
                    value=value,
                    created_by_id=actor.id,
                    updated_by_id=actor.id,
                )
            )


def create_request(
    db: DbSession,
    principal: Principal,
    payload: RequestCreate,
    context: AuditContext,
) -> ExceptionRequest:
    category = db.get(ExceptionCategory, resolve_model_id(db, ExceptionCategory, payload.category_id))
    if not category.is_active:
        raise DomainError("The selected category is inactive", code="category_inactive")
    risk = db.get(RiskLevel, resolve_model_id(db, RiskLevel, payload.risk_level_id))
    if not risk.is_active:
        raise DomainError("The selected risk level is inactive", code="risk_level_inactive")
    remediation_owner = (
        db.get(User, resolve_model_id(db, User, payload.remediation_owner_id))
        if payload.remediation_owner_id
        else principal.user
    )
    now_year = datetime.now(UTC).year
    request = ExceptionRequest(
        public_id=public_reference(f"EXC-{now_year}"),
        requester_id=principal.user.id,
        created_by_id=principal.user.id,
        last_modified_by_id=principal.user.id,
        title=payload.title,
        description=payload.description,
        business_justification=payload.business_justification,
        category_id=category.id,
        exception_type=payload.exception_type,
        department=payload.department,
        manager_id=principal.user.manager_id,
        application_name=payload.application_name,
        application_service_id=payload.application_service_id,
        application_owner=payload.application_owner,
        business_owner=payload.business_owner,
        technology_owner=payload.technology_owner,
        environment=payload.environment,
        asset_system=payload.asset_system,
        cloud_account=payload.cloud_account,
        data_classification_code=payload.data_classification_code,
        information_sensitivity=payload.information_sensitivity,
        regulatory_impact=payload.regulatory_impact,
        control_excepted=payload.control_excepted,
        current_control=payload.current_control,
        requested_exception=payload.requested_exception,
        reason_control_cannot_follow=payload.reason_control_cannot_follow,
        risk_description=payload.risk_description,
        business_impact=payload.business_impact,
        security_impact=payload.security_impact,
        compensating_controls=payload.compensating_controls,
        remediation_plan=payload.remediation_plan,
        remediation_owner_id=remediation_owner.id,
        remediation_target_date=payload.remediation_target_date,
        requested_start_date=payload.requested_start_date,
        requested_expiry_date=payload.requested_expiry_date,
        requested_duration_days=(payload.requested_expiry_date - payload.requested_start_date).days + 1,
        original_expiry_date=payload.requested_expiry_date,
        expiry_date=payload.requested_expiry_date,
        risk_level_id=risk.id,
        additional_comments=payload.additional_comments,
    )
    db.add(request)
    db.flush()
    _set_custom_fields(db, request, payload.custom_fields, principal.user, category.id)
    record_audit(
        db,
        context,
        action="request.created",
        object_type="exception_request",
        object_id=request.public_id,
        new_value={"status": RequestStatus.DRAFT, "version": request.version, "category_id": str(category.id)},
    )
    return request


def update_request(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    payload: RequestUpdate,
    context: AuditContext,
) -> ExceptionRequest:
    require_owner(principal, request)
    if request.status not in {RequestStatus.DRAFT, RequestStatus.CLARIFICATION_REQUIRED}:
        raise ConflictError("Submitted request content is locked")
    if request.version != payload.expected_version:
        raise ConflictError()
    changes = payload.model_dump(exclude_unset=True, exclude={"expected_version", "custom_fields"})
    allowed_fields = {column.name for column in ExceptionRequest.__table__.columns}
    old_values: dict[str, Any] = {}
    for field, value in changes.items():
        if field not in allowed_fields:
            continue
        if field == "category_id":
            value = resolve_model_id(db, ExceptionCategory, value)
        elif field == "risk_level_id":
            value = resolve_model_id(db, RiskLevel, value)
        elif field == "remediation_owner_id" and value:
            value = resolve_model_id(db, User, value)
        old_values[field] = getattr(request, field)
        setattr(request, field, value)
    if (
        request.requested_expiry_date < request.requested_start_date
        or request.remediation_progress > 100
    ):
        raise DomainError("Request dates or progress are invalid", code="invalid_request_data")
    request.requested_duration_days = (request.requested_expiry_date - request.requested_start_date).days + 1
    if request.status == RequestStatus.DRAFT:
        request.original_expiry_date = request.requested_expiry_date
    request.expiry_date = request.requested_expiry_date
    request.last_modified_by_id = principal.user.id
    if payload.custom_fields is not None:
        _set_custom_fields(db, request, payload.custom_fields, principal.user, request.category_id)
    record_audit(
        db,
        context,
        action="request.updated",
        object_type="exception_request",
        object_id=request.public_id,
        old_value=old_values,
        new_value=changes,
    )
    return request


def add_comment(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    body: str,
    context: AuditContext,
) -> Comment:
    if request.status == RequestStatus.DRAFT:
        raise ConflictError("Comments are available after submission; use additional comments on the draft")
    comment = Comment(request_id=request.id, author_id=principal.user.id, body=body)
    db.add(comment)
    db.flush()
    record_audit(
        db,
        context,
        action="request.comment_added",
        object_type="exception_request",
        object_id=request.public_id,
        new_value={"comment_id": str(comment.id), "body": body},
    )
    return comment


def list_requests(
    db: DbSession,
    principal: Principal,
    *,
    search: str | None,
    status: list[str],
    category_id: str | None,
    risk_level_id: str | None,
    requester_id: str | None,
    application: str | None,
    expiring_before: date | None,
    sort: str,
    direction: str,
    page: int,
    page_size: int,
) -> tuple[list[ExceptionRequest], int]:
    query = scoped_requests_query(principal)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                ExceptionRequest.public_id.ilike(term),
                ExceptionRequest.title.ilike(term),
                ExceptionRequest.application_name.ilike(term),
                ExceptionRequest.asset_system.ilike(term),
                ExceptionRequest.requester.email.ilike(term),
            )
        )
    if status:
        query = query.where(ExceptionRequest.status.in_(status))
    if category_id:
        query = query.where(ExceptionRequest.category_id == resolve_model_id(db, ExceptionCategory, category_id))
    if risk_level_id:
        query = query.where(ExceptionRequest.risk_level_id == resolve_model_id(db, RiskLevel, risk_level_id))
    if requester_id:
        query = query.where(ExceptionRequest.requester_id == resolve_model_id(db, User, requester_id))
    if application:
        query = query.where(ExceptionRequest.application_name.ilike(f"%{application.strip()}%"))
    if expiring_before:
        query = query.where(ExceptionRequest.expiry_date <= expiring_before)
    sort_column = REQUEST_SORT_COLUMNS.get(sort, ExceptionRequest.created_at)
    if sort == "risk":
        query = query.join(RiskLevel, RiskLevel.id == ExceptionRequest.risk_level_id)
    ordering = sort_column.asc() if direction == "asc" else sort_column.desc()
    count_query = select(func.count()).select_from(query.order_by(None).subquery())
    total = int(db.scalar(count_query) or 0)
    requests = list(db.scalars(query.order_by(ordering).offset((page - 1) * page_size).limit(page_size)))
    return requests, total


def request_summary(request: ExceptionRequest) -> dict[str, Any]:
    return {
        "public_id": request.public_id,
        "title": request.title,
        "exception_type": request.exception_type,
        "category_name": request.category.name,
        "requester_id": str(request.requester_id),
        "requester_name": request.requester.display_name,
        "department": request.department,
        "application_name": request.application_name,
        "environment": request.environment,
        "data_classification_code": request.data_classification_code,
        "risk_level": request.risk_level.code,
        "status": request.status,
        "current_stage_key": request.current_stage_key,
        "requested_start_date": request.requested_start_date,
        "expiry_date": request.expiry_date,
        "extension_count": request.extension_count,
        "version": request.version,
        "created_at": request.created_at,
        "updated_at": request.updated_at,
    }


def request_detail(
    db: DbSession, request: ExceptionRequest, principal: Principal
) -> dict[str, Any]:
    actions = list(
        db.scalars(
            select(ApprovalAction)
            .where(ApprovalAction.request_id == request.id)
            .order_by(ApprovalAction.acted_at.asc())
        )
    )
    action_by_assignment: dict[Any, ApprovalAction] = {action.assignment_id: action for action in actions}
    approvals = []
    for assignment in sorted(request.approvals, key=lambda item: item.created_at):
        action = action_by_assignment.get(assignment.id)
        original = db.get(User, assignment.delegated_from_id) if assignment.delegated_from_id else None
        approvals.append(
            {
                "id": str(assignment.id),
                "stage_key": assignment.stage_key,
                "stage_name": assignment.stage_name,
                "approver_id": str(assignment.approver_id),
                "approver_name": assignment.approver.display_name if assignment.approver else "Unknown",
                "delegated_from_id": str(assignment.delegated_from_id) if assignment.delegated_from_id else None,
                "delegated_from_name": original.display_name if original else None,
                "status": assignment.status,
                "due_at": assignment.due_at,
                "completed_at": assignment.completed_at,
                "decision": action.decision if action else None,
                "decision_comment": action.comment if action else None,
            }
        )
    comments = [
        {
            "id": str(comment.id),
            "author_id": str(comment.author_id),
            "author_name": comment.author.display_name if comment.author else "Unknown",
            "kind": comment.kind,
            "body": comment.body,
            "is_clarification_response": comment.is_clarification_response,
            "created_at": comment.created_at,
        }
        for comment in sorted(request.comments, key=lambda item: item.created_at)
    ]
    attachments = [
        {
            "id": str(attachment.id),
            "original_filename": attachment.original_filename,
            "content_type": attachment.content_type,
            "size_bytes": attachment.size_bytes,
            "sha256": attachment.sha256,
            "scan_status": attachment.scan_status,
            "evidence_type": attachment.evidence_type,
            "provided_by": str(attachment.provided_by) if attachment.provided_by else None,
            "provided_at": attachment.provided_at,
            "created_at": attachment.created_at,
        }
        for attachment in request.attachments
        if attachment.deleted_at is None
    ]
    custom_values = list(db.scalars(select(RequestFieldValue).where(RequestFieldValue.request_id == request.id)))
    custom_fields = {value.field.field_key: value.value for value in custom_values}
    analyses = [
        {
            "id": str(analysis.id),
            "feature": analysis.feature,
            "status": analysis.status,
            "prompt_version": analysis.prompt_version,
            "risk_level": analysis.risk_level,
            "confidence": analysis.confidence,
            "output": analysis.output,
            "created_at": analysis.created_at,
            "completed_at": analysis.completed_at,
            "disclaimer": "AI-generated assistance — human approval required.",
        }
        for analysis in db.scalars(
            select(AiAnalysis)
            .where(AiAnalysis.request_id == request.id)
            .order_by(AiAnalysis.created_at.desc())
        )
    ]
    timeline = [
        {
            "id": str(event.id),
            "timestamp": event.occurred_at,
            "actor": event.actor_label,
            "action": event.action,
            "result": event.result,
            "summary": event.action.replace(".", " ").replace("_", " ").title(),
            "event_hash": event.event_hash,
        }
        for event in timeline_for_request(db, request.public_id)
    ]
    current_assignment = next(
        (
            assignment
            for assignment in request.approvals
            if assignment.approver_id == principal.user.id
            and assignment.status in {"pending", "clarification"}
        ),
        None,
    )
    can_edit = request.status == RequestStatus.DRAFT and (
        request.requester_id == principal.user.id or principal.has_role("admin")
    )
    result = request_summary(request)
    result.update(
        {
            "can_edit": can_edit,
            "can_decide_assignment_id": str(current_assignment.id) if current_assignment else None,
            "description": request.description,
            "business_justification": request.business_justification,
            "manager_id": str(request.manager_id) if request.manager_id else None,
            "manager_name": request.manager.display_name if request.manager else None,
            "application_service_id": request.application_service_id,
            "application_owner": request.application_owner,
            "business_owner": request.business_owner,
            "technology_owner": request.technology_owner,
            "asset_system": request.asset_system,
            "cloud_account": request.cloud_account,
            "information_sensitivity": request.information_sensitivity,
            "regulatory_impact": request.regulatory_impact,
            "control_excepted": request.control_excepted,
            "current_control": request.current_control,
            "requested_exception": request.requested_exception,
            "reason_control_cannot_follow": request.reason_control_cannot_follow,
            "risk_description": request.risk_description,
            "business_impact": request.business_impact,
            "security_impact": request.security_impact,
            "compensating_controls": request.compensating_controls,
            "remediation_plan": request.remediation_plan,
            "remediation_owner_id": str(request.remediation_owner_id) if request.remediation_owner_id else None,
            "remediation_owner_name": db.get(User, request.remediation_owner_id).display_name
            if request.remediation_owner_id
            else None,
            "remediation_target_date": request.remediation_target_date,
            "remediation_status": request.remediation_status,
            "remediation_progress": request.remediation_progress,
            "remediation_closure_date": request.remediation_closure_date,
            "requested_duration_days": request.requested_duration_days,
            "additional_comments": request.additional_comments,
            "original_expiry_date": request.original_expiry_date,
            "submitted_at": request.submitted_at,
            "activated_at": request.activated_at,
            "expired_at": request.expired_at,
            "closed_at": request.closed_at,
            "approvals": approvals,
            "comments": comments,
            "attachments": attachments,
            "custom_fields": custom_fields,
            "ai_analyses": analyses,
            "audit_timeline": timeline,
        }
    )
    return result


def pending_approvals(
    db: DbSession, principal: Principal, *, page: int, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    query = (
        select(ApprovalAssignment, ExceptionRequest)
        .join(ExceptionRequest, ExceptionRequest.id == ApprovalAssignment.request_id)
        .where(
            ApprovalAssignment.approver_id == principal.user.id,
            ApprovalAssignment.status.in_(["pending", "clarification"]),
        )
        .order_by(ApprovalAssignment.due_at.asc())
    )
    rows = list(db.execute(query).all())
    total = len(rows)
    start = (page - 1) * page_size
    result = []
    for assignment, request in rows[start : start + page_size]:
        result.append(
            {
                "assignment_id": str(assignment.id),
                "request_id": request.public_id,
                "title": request.title,
                "stage_name": assignment.stage_name,
                "status": assignment.status,
                "due_at": assignment.due_at,
                "risk_level": request.risk_level.code,
                "category": request.category.name,
                "requester_name": request.requester.display_name,
                "application_name": request.application_name,
                "data_classification_code": request.data_classification_code,
                "delegated": assignment.delegated_from_id is not None,
            }
        )
    return result, total


def dashboard_metrics(db: DbSession, principal: Principal) -> dict[str, Any]:
    today = datetime.now(UTC).date()
    base = scoped_requests_query(principal)
    ids = [request.public_id for request in db.scalars(base.with_only_columns(ExceptionRequest.public_id))]
    if not ids:
        return {
            "total": 0,
            "drafts": 0,
            "pending": 0,
            "active": 0,
            "expiring_30_days": 0,
            "expired": 0,
            "extensions": 0,
            "status_counts": [],
            "risk_counts": [],
            "category_counts": [],
        }
    status_rows = db.execute(
        select(ExceptionRequest.status, func.count())
        .where(ExceptionRequest.public_id.in_(ids))
        .group_by(ExceptionRequest.status)
    ).all()
    risk_rows = db.execute(
        select(RiskLevel.name, func.count())
        .join(ExceptionRequest, ExceptionRequest.risk_level_id == RiskLevel.id)
        .where(ExceptionRequest.public_id.in_(ids))
        .group_by(RiskLevel.name)
    ).all()
    category_rows = db.execute(
        select(ExceptionCategory.name, func.count())
        .join(ExceptionRequest, ExceptionRequest.category_id == ExceptionCategory.id)
        .where(ExceptionRequest.public_id.in_(ids))
        .group_by(ExceptionCategory.name)
    ).all()
    def count_status(*states: str) -> int:
        return sum(int(count) for state, count in status_rows if state in states)
    soon_limit = today.fromordinal(today.toordinal() + 30)
    return {
        "total": len(ids),
        "drafts": count_status(RequestStatus.DRAFT),
        "pending": count_status(
            RequestStatus.SUBMITTED,
            RequestStatus.PENDING_MANAGER,
            RequestStatus.PENDING_DELIVERY,
            RequestStatus.PENDING_APPROVER,
            RequestStatus.CLARIFICATION_REQUIRED,
        ),
        "active": count_status(RequestStatus.ACTIVE),
        "expiring_30_days": int(
            db.scalar(
                select(func.count(ExceptionRequest.id)).where(
                    ExceptionRequest.public_id.in_(ids),
                    ExceptionRequest.status == RequestStatus.ACTIVE,
                    ExceptionRequest.expiry_date >= today,
                    ExceptionRequest.expiry_date <= soon_limit,
                )
            )
            or 0
        ),
        "expired": count_status(RequestStatus.EXPIRED),
        "extensions": count_status(RequestStatus.EXTENSION_REQUESTED, RequestStatus.EXTENSION_PENDING_APPROVAL),
        "status_counts": [{"status": state, "count": count} for state, count in status_rows],
        "risk_counts": [{"risk": risk, "count": count} for risk, count in risk_rows],
        "category_counts": [{"category": category, "count": count} for category, count in category_rows],
    }
