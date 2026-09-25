from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import AuthorizationError, ConflictError, DomainError, NotFoundError
from app.core.security import generate_opaque_token, hash_token
from app.models import (
    ApprovalAction,
    ApprovalAssignment,
    ApprovalWorkflow,
    ApproverGroupMember,
    Attachment,
    Comment,
    Delegation,
    ExceptionRequest,
    RequestFieldDefinition,
    RequestFieldValue,
    RemediationUpdate,
    StageKind,
    SystemConfig,
    User,
    WorkflowStage,
)
from app.models import RequestStatus
from app.schemas.common import AuditContext
from app.schemas.requests import ClarificationResponseRequest
from app.services.audit import record_audit
from app.services.authz import Principal
from app.services.calendar import add_business_days
from app.services.outbox import enqueue_job, queue_notification

STATE_TRANSITIONS: dict[str, set[str]] = {
    RequestStatus.DRAFT: {RequestStatus.SUBMITTED, RequestStatus.CANCELLED},
    RequestStatus.SUBMITTED: {
        RequestStatus.PENDING_MANAGER,
        RequestStatus.PENDING_DELIVERY,
        RequestStatus.PENDING_APPROVER,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.PENDING_MANAGER: {
        RequestStatus.MANAGER_APPROVED,
        RequestStatus.MANAGER_REJECTED,
        RequestStatus.CLARIFICATION_REQUIRED,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.MANAGER_APPROVED: {
        RequestStatus.PENDING_DELIVERY,
        RequestStatus.PENDING_APPROVER,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.PENDING_DELIVERY: {
        RequestStatus.DELIVERY_APPROVED,
        RequestStatus.DELIVERY_REJECTED,
        RequestStatus.CLARIFICATION_REQUIRED,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.DELIVERY_APPROVED: {
        RequestStatus.PENDING_APPROVER,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.PENDING_APPROVER: {
        RequestStatus.APPROVED,
        RequestStatus.REJECTED,
        RequestStatus.CLARIFICATION_REQUIRED,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.CLARIFICATION_REQUIRED: {
        RequestStatus.PENDING_MANAGER,
        RequestStatus.PENDING_DELIVERY,
        RequestStatus.PENDING_APPROVER,
        RequestStatus.WITHDRAWN,
    },
    RequestStatus.APPROVED: {RequestStatus.ACTIVE, RequestStatus.EXPIRED, RequestStatus.CLOSED},
    RequestStatus.ACTIVE: {
        RequestStatus.EXTENSION_REQUESTED,
        RequestStatus.EXTENSION_PENDING_APPROVAL,
        RequestStatus.EXPIRED,
        RequestStatus.CLOSED,
    },
    RequestStatus.EXTENSION_REQUESTED: {RequestStatus.EXTENSION_PENDING_APPROVAL, RequestStatus.WITHDRAWN},
    RequestStatus.EXTENSION_PENDING_APPROVAL: {
        RequestStatus.ACTIVE,
        RequestStatus.APPROVED,
        RequestStatus.EXTENSION_REQUESTED,
    },
    RequestStatus.EXPIRED: {RequestStatus.CLOSED},
    RequestStatus.MANAGER_REJECTED: {RequestStatus.CLOSED},
    RequestStatus.DELIVERY_REJECTED: {RequestStatus.CLOSED},
    RequestStatus.REJECTED: {RequestStatus.CLOSED},
    RequestStatus.CANCELLED: set(),
    RequestStatus.WITHDRAWN: {RequestStatus.CLOSED},
    RequestStatus.CLOSED: set(),
}


def transition(request: ExceptionRequest, new_status: str) -> None:
    if new_status == request.status:
        return
    if new_status not in STATE_TRANSITIONS.get(request.status, set()):
        raise DomainError(
            f"Transition from {request.status} to {new_status} is not allowed",
            code="invalid_state_transition",
            status_code=409,
        )
    request.status = new_status


def configured_value(db: DbSession, key: str, default: Any) -> Any:
    row = db.scalar(
        select(SystemConfig).where(
            SystemConfig.config_key == key,
            SystemConfig.is_active.is_(True),
        )
    )
    return row.value if row else default


def duration_policy(
    db: DbSession, request: ExceptionRequest, settings: Settings
) -> tuple[int, int, int]:
    default_days = configured_value(db, "exception.default_duration_days", settings.default_exception_days)
    maximum_days = configured_value(db, "exception.maximum_duration_days", settings.maximum_exception_days)
    minimum_days = configured_value(db, "exception.minimum_duration_days", settings.minimum_exception_days)
    if request.category:
        default_days = request.category.default_duration_days or default_days
        maximum_days = request.category.maximum_duration_days or maximum_days
    if not minimum_days <= default_days <= maximum_days:
        raise DomainError("Duration configuration is inconsistent", code="configuration_error", status_code=500)
    return int(minimum_days), int(default_days), int(maximum_days)


def validate_duration(db: DbSession, request: ExceptionRequest, settings: Settings) -> int:
    minimum, _, maximum = duration_policy(db, request, settings)
    duration = (request.requested_expiry_date - request.requested_start_date).days + 1
    if duration < minimum or duration > maximum:
        raise DomainError(
            f"Requested duration must be between {minimum} and {maximum} days",
            code="duration_out_of_range",
        )
    request.requested_duration_days = duration
    return duration


def validate_required_custom_fields(db: DbSession, request: ExceptionRequest) -> None:
    definitions = list(
        db.scalars(
            select(RequestFieldDefinition).where(
                RequestFieldDefinition.is_active.is_(True),
                RequestFieldDefinition.is_required.is_(True),
            )
        )
    )
    values = {
        value.field_id: value.value
        for value in db.scalars(select(RequestFieldValue).where(RequestFieldValue.request_id == request.id))
    }
    for definition in definitions:
        if definition.visible_categories and str(request.category_id) not in {
            str(item) for item in definition.visible_categories
        }:
            continue
        if values.get(definition.id) in {None, "", []}:
            raise DomainError(f"Required field '{definition.label}' is missing", code="required_field_missing")


def resolve_workflow(db: DbSession, request: ExceptionRequest) -> ApprovalWorkflow:
    query = select(ApprovalWorkflow).where(
        ApprovalWorkflow.is_active.is_(True),
        (ApprovalWorkflow.category_id == request.category_id)
        | (ApprovalWorkflow.category_id.is_(None) & (ApprovalWorkflow.exception_type == request.exception_type))
        | (
            ApprovalWorkflow.category_id.is_(None)
            & ApprovalWorkflow.exception_type.is_(None)
            & (ApprovalWorkflow.risk_level_id == request.risk_level_id)
        )
        | (
            ApprovalWorkflow.category_id.is_(None)
            & ApprovalWorkflow.exception_type.is_(None)
            & ApprovalWorkflow.risk_level_id.is_(None)
            & ApprovalWorkflow.is_default.is_(True)
        ),
    )
    workflow = db.scalar(query.order_by(ApprovalWorkflow.is_default.asc()).limit(1))
    if workflow is None or not workflow.stages:
        raise DomainError("No active approval workflow matches this request", code="workflow_not_configured")
    return workflow


def _status_for_stage(stage: WorkflowStage) -> str:
    return {
        StageKind.MANAGER: RequestStatus.PENDING_MANAGER,
        StageKind.DELIVERY_HEAD: RequestStatus.PENDING_DELIVERY,
        StageKind.EXCEPTION_APPROVER: RequestStatus.PENDING_APPROVER,
        StageKind.FINAL: RequestStatus.PENDING_APPROVER,
    }[stage.kind]


def _delegated_manager(db: DbSession, request: ExceptionRequest, now: datetime) -> tuple[User | None, User | None]:
    manager = request.manager or request.requester.manager
    delegator_id = manager.id if manager else request.requester_id
    query = select(Delegation).where(
        Delegation.delegator_id == delegator_id,
        Delegation.is_active.is_(True),
        Delegation.start_at <= now,
        Delegation.end_at > now,
    )
    for delegation in db.scalars(query):
        if delegation.scope_type == "all" or (
            delegation.scope_type == "category" and delegation.scope_value == str(request.category_id)
        ):
            delegate = db.get(User, delegation.delegate_id)
            if delegate and delegate.status == "active":
                return delegate, manager
    return manager, None


def _stage_approvers(
    db: DbSession, request: ExceptionRequest, stage: WorkflowStage
) -> list[tuple[User, User | None]]:
    if stage.kind == StageKind.MANAGER:
        approver, original = _delegated_manager(db, request, datetime.now(UTC))
        return [(approver, original)] if approver else []
    candidates: list[User] = []
    if stage.approver_group_id:
        candidates.extend(
            db.scalars(
                select(User)
                .join(ApproverGroupMember, ApproverGroupMember.user_id == User.id)
                .where(
                    ApproverGroupMember.group_id == stage.approver_group_id,
                    ApproverGroupMember.is_active.is_(True),
                    User.status == "active",
                )
            )
        )
    if stage.backup_approver_id:
        backup = db.get(User, stage.backup_approver_id)
        if backup and backup.status == "active":
            candidates.append(backup)
    unique: dict[uuid.UUID, User] = {user.id: user for user in candidates}
    return [(user, None) for user in unique.values() if user.id != request.requester_id]


def _create_stage_assignments(
    db: DbSession,
    request: ExceptionRequest,
    stage: WorkflowStage,
    settings: Settings,
    context: AuditContext,
) -> list[ApprovalAssignment]:
    approvers = _stage_approvers(db, request, stage)
    if not approvers:
        if stage.required:
            raise DomainError(
                f"No eligible approver is assigned to required stage '{stage.name}'",
                code="approver_unavailable",
                status_code=409,
            )
        return []
    due_at = add_business_days(db, datetime.now(UTC), stage.sla_business_days, settings)
    assignments: list[ApprovalAssignment] = []
    for approver, original in approvers:
        raw_token = generate_opaque_token(40)
        assignment = ApprovalAssignment(
            request_id=request.id,
            workflow_stage_id=stage.id,
            stage_key=stage.stage_key,
            stage_name=stage.name,
            approver_id=approver.id,
            assigned_by_id=context.actor_id,
            delegated_from_id=original.id if original and original.id != approver.id else None,
            status="pending",
            due_at=due_at,
            token_hash=hash_token(raw_token),
            token_expires_at=min(due_at, datetime.now(UTC) + timedelta(hours=72)),
        )
        db.add(assignment)
        db.flush()
        assignments.append(assignment)
        queue_notification(
            db,
            user=approver,
            request_id=request.public_id,
            notification_type="approval_required",
            subject=f"Approval required: {request.public_id}",
            body=f"An exception request is awaiting your decision. Sign in to review {request.public_id}.",
            action_url=f"/approvals/pending?request={request.public_id}&action_token={raw_token}",
            idempotency_key=f"approval-required:{assignment.id}",
            correlation_id=context.correlation_id,
        )
    return assignments


def _next_stage(workflow: ApprovalWorkflow, current_key: str) -> WorkflowStage | None:
    sequence = next((stage.sequence for stage in workflow.stages if stage.stage_key == current_key), None)
    if sequence is None:
        return None
    return next((stage for stage in workflow.stages if stage.sequence == sequence + 1), None)


def _route_next_stage(
    db: DbSession, request: ExceptionRequest, settings: Settings, context: AuditContext
) -> None:
    if request.workflow is None:
        raise DomainError("Request has no workflow snapshot", code="workflow_missing")
    current = request.current_stage_key
    stage = _next_stage(request.workflow, current) if current else request.workflow.stages[0]
    while stage is not None:
        assignments = _create_stage_assignments(db, request, stage, settings, context)
        if assignments:
            request.current_stage_key = stage.stage_key
            transition(request, _status_for_stage(stage))
            return
        if not stage.required:
            stage = _next_stage(request.workflow, stage.stage_key)
            continue
        break
    # A workflow with no final stage still requires a final approval stage in production.
    if request.status not in {RequestStatus.APPROVED, RequestStatus.ACTIVE}:
        raise DomainError("Workflow has no final approval stage", code="workflow_invalid", status_code=500)


def submit_request(
    db: DbSession,
    request: ExceptionRequest,
    actor: User,
    settings: Settings,
    context: AuditContext,
) -> None:
    if request.requester_id != actor.id:
        raise AuthorizationError()
    if request.status not in {RequestStatus.DRAFT, RequestStatus.CLARIFICATION_REQUIRED}:
        raise ConflictError("Only a draft or clarified request can be submitted")
    validate_duration(db, request, settings)
    validate_required_custom_fields(db, request)
    workflow = resolve_workflow(db, request)
    request.workflow = workflow
    request.workflow_id = workflow.id
    request.manager = request.manager or request.requester.manager
    request.submitted_at = datetime.now(UTC)
    request.last_modified_by_id = actor.id
    transition(request, RequestStatus.SUBMITTED)
    _route_next_stage(db, request, settings, context)
    enqueue_job(
        db,
        "schedule_expiration",
        {"request_id": str(request.id)},
        deduplication_key=f"expiration-schedule:{request.id}:{request.version}",
        run_at=datetime.combine(request.requested_expiry_date, datetime.min.time(), tzinfo=UTC),
        correlation_id=context.correlation_id,
    )
    queue_notification(
        db,
        user=actor,
        request_id=request.public_id,
        notification_type="request_submitted",
        subject=f"Submitted: {request.public_id}",
        body="Your request was submitted. Track its status in Exception-Manager.",
        action_url=f"/requests/{request.public_id}",
        idempotency_key=f"submitted:{request.id}:{request.version}",
        correlation_id=context.correlation_id,
    )
    record_audit(
        db,
        context,
        action="request.submitted",
        object_type="exception_request",
        object_id=request.public_id,
        old_value={"status": "draft"},
        new_value={"status": request.status, "stage": request.current_stage_key, "version": request.version},
    )


def _consume_action_token(assignment: ApprovalAssignment, action_token: str | None) -> None:
    if action_token is None:
        return
    if (
        assignment.token_hash is None
        or assignment.token_expires_at is None
        or assignment.token_consumed_at is not None
        or assignment.token_expires_at.replace(tzinfo=assignment.token_expires_at.tzinfo or UTC) <= datetime.now(UTC)
        or assignment.token_hash != hash_token(action_token)
    ):
        raise AuthorizationError("Approval action link is invalid, expired, or already used")
    assignment.token_consumed_at = datetime.now(UTC)


def _assert_separation_of_duties(db: DbSession, request: ExceptionRequest, actor: User, stage: WorkflowStage) -> None:
    if actor.id == request.requester_id:
        raise AuthorizationError("Separation of duties prevents requesters from approving their own request")
    if stage.kind == StageKind.FINAL:
        previous_actor_ids = set(
            db.scalars(
                select(ApprovalAction.actor_id).where(
                    ApprovalAction.request_id == request.id,
                    ApprovalAction.decision == "approve",
                )
            )
        )
        if actor.id in previous_actor_ids:
            raise AuthorizationError("Final approval must be performed by a different approver")


def decide_approval(
    db: DbSession,
    request: ExceptionRequest,
    assignment_id: uuid.UUID,
    principal: Principal,
    payload,
    settings: Settings,
    context: AuditContext,
    *,
    action_token: str | None = None,
) -> ApprovalAction:
    existing = db.scalar(
        select(ApprovalAction).where(ApprovalAction.idempotency_key == payload.idempotency_key)
    )
    if existing:
        same_command = (
            existing.actor_id == principal.user.id
            and existing.assignment_id == assignment_id
            and existing.decision == payload.decision
            and (existing.comment or "") == (payload.comment or "").strip()
            and (existing.rejection_reason or "") == (payload.reason or "").strip()
        )
        if not same_command:
            raise ConflictError("Idempotency key was already used")
        return existing
    if request.version != payload.expected_version:
        raise ConflictError()
    assignment = db.scalar(
        select(ApprovalAssignment).where(ApprovalAssignment.id == assignment_id).with_for_update()
    )
    if assignment is None or assignment.request_id != request.id:
        raise NotFoundError("Pending approval was not found")
    if assignment.approver_id != principal.user.id or assignment.status != "pending":
        raise AuthorizationError("This approval is not assigned to you or is no longer pending")
    stage = db.get(WorkflowStage, assignment.workflow_stage_id) if assignment.workflow_stage_id else None
    if principal.user.id == request.requester_id:
        raise AuthorizationError("Separation of duties prevents requesters from approving their own request")
    if stage:
        _assert_separation_of_duties(db, request, principal.user, stage)
    if payload.decision == "reject" and not (payload.reason or "").strip():
        raise DomainError("A rejection reason is required", code="rejection_reason_required")
    _consume_action_token(assignment, action_token)
    action = ApprovalAction(
        assignment_id=assignment.id,
        request_id=request.id,
        actor_id=principal.user.id,
        delegated_from_id=assignment.delegated_from_id,
        decision=payload.decision,
        comment=(payload.comment or "").strip() or None,
        rejection_reason=(payload.reason or "").strip() or None,
        request_version=request.version,
        idempotency_key=payload.idempotency_key,
    )
    db.add(action)
    db.flush()
    if payload.decision == "reject":
        assignment.status = "rejected"
        assignment.completed_at = datetime.now(UTC)
        if assignment.stage_key == "extension":
            restored_status = (
                RequestStatus.ACTIVE
                if request.activated_at and datetime.now(UTC).date() <= request.expiry_date
                else RequestStatus.APPROVED
            )
            request.pending_extension_expiry_date = None
            request.pending_extension_reason = None
            transition(request, restored_status)
        else:
            transition(
                request,
                {
                    StageKind.MANAGER: RequestStatus.MANAGER_REJECTED,
                    StageKind.DELIVERY_HEAD: RequestStatus.DELIVERY_REJECTED,
                }.get(stage.kind if stage else "", RequestStatus.REJECTED),
            )
            request.current_stage_key = None
    elif payload.decision == "request_clarification":
        assignment.status = "clarification"
        request.current_stage_key = assignment.stage_key
        transition(request, RequestStatus.CLARIFICATION_REQUIRED)
    else:
        assignment.status = "approved"
        assignment.completed_at = datetime.now(UTC)
        if assignment.stage_key == "extension":
            previous_status = (
                RequestStatus.ACTIVE
                if request.activated_at and datetime.now(UTC).date() <= request.expiry_date
                else RequestStatus.APPROVED
            )
            if request.pending_extension_expiry_date is None or request.pending_extension_reason is None:
                raise DomainError("Extension decision has no pending proposal", code="extension_missing")
            request.expiry_date = request.pending_extension_expiry_date
            request.requested_expiry_date = request.pending_extension_expiry_date
            request.pending_extension_expiry_date = None
            request.pending_extension_reason = None
            request.extension_count += 1
            transition(request, previous_status)
            enqueue_job(
                db,
                "schedule_expiration",
                {"request_id": str(request.id)},
                deduplication_key=f"expiration-schedule:{request.id}:{request.version}",
                run_at=datetime.combine(request.expiry_date, datetime.min.time(), tzinfo=UTC),
                correlation_id=context.correlation_id,
            )
        else:
            approved_count = int(
                db.scalar(
                    select(func.count(ApprovalAction.id)).where(
                        ApprovalAction.assignment_id.in_(
                            select(ApprovalAssignment.id).where(
                                ApprovalAssignment.request_id == request.id,
                                ApprovalAssignment.stage_key == assignment.stage_key,
                            )
                        ),
                        ApprovalAction.decision == "approve",
                    )
                )
                or 0
            )
            required = stage.minimum_approvals if stage else 1
            maximum = stage.maximum_approvals if stage else None
            pending_siblings = int(
                db.scalar(
                    select(func.count(ApprovalAssignment.id)).where(
                        ApprovalAssignment.request_id == request.id,
                        ApprovalAssignment.stage_key == assignment.stage_key,
                        ApprovalAssignment.status == "pending",
                        ApprovalAssignment.id != assignment.id,
                    )
                )
                or 0
            )
            stage_complete = approved_count >= required and (
                maximum is None or approved_count >= maximum or pending_siblings == 0
            )
            if not stage_complete:
                record_audit(
                    db,
                    context,
                    action="approval.cast",
                    object_type="exception_request",
                    object_id=request.public_id,
                    new_value={
                        "assignment": str(assignment.id),
                        "decision": "approve",
                        "approved_count": approved_count,
                        "required": required,
                        "maximum": maximum,
                    },
                )
                return action
            if maximum is not None and approved_count > maximum:
                raise DomainError(
                    "The approval maximum for this stage was exceeded",
                    code="approval_maximum_exceeded",
                )
            for sibling in db.scalars(
                select(ApprovalAssignment).where(
                    ApprovalAssignment.request_id == request.id,
                    ApprovalAssignment.stage_key == assignment.stage_key,
                    ApprovalAssignment.status == "pending",
                )
            ):
                sibling.status = "not_required"
            transition(
                request,
                {
                    StageKind.MANAGER: RequestStatus.MANAGER_APPROVED,
                    StageKind.DELIVERY_HEAD: RequestStatus.DELIVERY_APPROVED,
                }.get(stage.kind if stage else "", RequestStatus.APPROVED),
            )
            if request.status == RequestStatus.APPROVED:
                request.current_stage_key = None
                enqueue_job(
                    db,
                    "activate_request",
                    {"request_id": str(request.id)},
                    deduplication_key=f"activate:{request.id}:{request.version}",
                    run_at=datetime.combine(request.requested_start_date, datetime.min.time(), tzinfo=UTC),
                    correlation_id=context.correlation_id,
                    priority=10,
                )
            else:
                _route_next_stage(db, request, settings, context)
    record_audit(
        db,
        context,
        action=f"approval.{payload.decision}",
        object_type="exception_request",
        object_id=request.public_id,
        old_value={"assignment_status": "pending", "request_version": action.request_version},
        new_value={
            "status": request.status,
            "decision": payload.decision,
            "actor_id": str(principal.user.id),
            "delegated_from_id": str(assignment.delegated_from_id) if assignment.delegated_from_id else None,
            "version": request.version,
        },
    )
    return action


def respond_to_clarification(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    payload: ClarificationResponseRequest,
    context: AuditContext,
) -> Comment:
    if request.requester_id != principal.user.id:
        raise AuthorizationError()
    if request.status != RequestStatus.CLARIFICATION_REQUIRED or request.version != payload.expected_version:
        raise ConflictError()
    comment = Comment(
        request_id=request.id,
        author_id=principal.user.id,
        kind="clarification_response",
        body=payload.message,
        is_clarification_response=True,
    )
    db.add(comment)
    assignment = db.scalar(
        select(ApprovalAssignment)
        .where(
            ApprovalAssignment.request_id == request.id,
            ApprovalAssignment.status == "clarification",
        )
        .order_by(ApprovalAssignment.created_at.desc())
    )
    if assignment is None:
        raise ConflictError("The clarification assignment is no longer available")
    assignment.status = "pending"
    stage = db.get(WorkflowStage, assignment.workflow_stage_id) if assignment.workflow_stage_id else None
    if stage is None:
        raise ConflictError("The clarification stage is invalid")
    transition(request, _status_for_stage(stage))
    request.last_modified_by_id = principal.user.id
    record_audit(
        db,
        context,
        action="request.clarification_responded",
        object_type="exception_request",
        object_id=request.public_id,
        new_value={"status": request.status, "version": request.version},
    )
    return comment


def activate_due_request(db: DbSession, request_id: uuid.UUID, context: AuditContext) -> None:
    request = db.scalar(select(ExceptionRequest).where(ExceptionRequest.id == request_id).with_for_update())
    if request is None or request.status not in {RequestStatus.APPROVED, RequestStatus.ACTIVE}:
        return
    today = datetime.now(UTC).date()
    if today > request.expiry_date:
        transition(request, RequestStatus.EXPIRED)
        request.expired_at = datetime.now(UTC)
    elif today >= request.requested_start_date:
        transition(request, RequestStatus.ACTIVE)
        request.activated_at = request.activated_at or datetime.now(UTC)
    record_audit(
        db,
        context,
        action="request.activation_processed",
        object_type="exception_request",
        object_id=request.public_id,
        new_value={"status": request.status},
    )


def withdraw_request(
    db: DbSession, request: ExceptionRequest, principal: Principal, expected_version: int, reason: str, context: AuditContext
) -> None:
    if request.requester_id != principal.user.id and not principal.has_role("admin"):
        raise AuthorizationError()
    if request.version != expected_version:
        raise ConflictError()
    old_status = request.status
    transition(request, RequestStatus.CANCELLED if old_status == RequestStatus.DRAFT else RequestStatus.WITHDRAWN)
    request.current_stage_key = None
    for assignment in request.approvals:
        if assignment.status == "pending":
            assignment.status = "cancelled"
    db.add(
        Comment(
            request_id=request.id,
            author_id=principal.user.id,
            kind="withdrawal",
            body=reason,
        )
    )
    record_audit(
        db,
        context,
        action="request.withdrawn",
        object_type="exception_request",
        object_id=request.public_id,
        old_value={"status": old_status},
        new_value={"status": request.status, "reason": reason},
    )


def request_extension(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    expected_version: int,
    new_expiry: date,
    reason: str,
    settings: Settings,
    context: AuditContext,
) -> ApprovalAssignment:
    if request.requester_id != principal.user.id:
        raise AuthorizationError()
    if request.version != expected_version:
        raise ConflictError()
    if request.status not in {RequestStatus.APPROVED, RequestStatus.ACTIVE}:
        raise DomainError("Only an approved or active exception can be extended", code="extension_not_eligible")
    if datetime.now(UTC).date() > request.expiry_date:
        raise DomainError("Expired exceptions cannot be extended", code="exception_expired")
    max_extensions = int(configured_value(db, "exception.maximum_extensions", settings.maximum_extensions))
    max_period = int(configured_value(db, "exception.maximum_extension_days", settings.maximum_extension_days))
    if request.extension_count >= max_extensions:
        raise DomainError("The configured extension limit has been reached", code="extension_limit_reached")
    extension_days = (new_expiry - request.expiry_date).days
    if extension_days <= 0 or extension_days > max_period:
        raise DomainError(
            f"Extension must add between 1 and {max_period} days", code="extension_period_invalid"
        )
    previous = db.scalar(
        select(ApprovalAssignment)
        .where(
            ApprovalAssignment.request_id == request.id,
            ApprovalAssignment.status == "approved",
            ApprovalAssignment.stage_key.in_(["exception_approver", "final", "security"]),
        )
        .order_by(ApprovalAssignment.completed_at.desc())
    )
    if previous is None:
        raise DomainError("A previous final approver is required for extension review", code="extension_approver_missing")
    request.pending_extension_expiry_date = new_expiry
    request.pending_extension_reason = reason
    raw_token = generate_opaque_token(40)
    assignment = ApprovalAssignment(
        request_id=request.id,
        stage_key="extension",
        stage_name="Extension approval",
        approver_id=previous.approver_id,
        delegated_from_id=previous.delegated_from_id,
        status="pending",
        due_at=add_business_days(db, datetime.now(UTC), settings.default_approver_sla_business_days, settings),
        token_hash=hash_token(raw_token),
        token_expires_at=datetime.now(UTC) + timedelta(hours=72),
    )
    db.add(assignment)
    db.flush()
    transition(request, RequestStatus.EXTENSION_PENDING_APPROVAL)
    approver = db.get(User, previous.approver_id)
    if approver:
        queue_notification(
            db,
            user=approver,
            request_id=request.public_id,
            notification_type="extension_approval_required",
            subject=f"Extension approval required: {request.public_id}",
            body=f"An extension request is awaiting your decision. Sign in to review {request.public_id}.",
            action_url=f"/approvals/pending?request={request.public_id}&action_token={raw_token}",
            idempotency_key=f"extension-required:{assignment.id}",
            correlation_id=context.correlation_id,
        )
    record_audit(
        db,
        context,
        action="request.extension_requested",
        object_type="exception_request",
        object_id=request.public_id,
        old_value={"expiry_date": request.expiry_date.isoformat(), "extension_count": request.extension_count},
        new_value={"requested_expiry_date": new_expiry.isoformat(), "reason": reason},
    )
    return assignment


def update_remediation(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    status: str,
    progress: int,
    notes: str,
    evidence_attachment_id: str | None,
    context: AuditContext,
) -> RemediationUpdate:
    allowed = principal.user.id in {request.requester_id, request.remediation_owner_id} or principal.has_role("admin")
    if not allowed:
        raise AuthorizationError()
    if request.status not in {RequestStatus.APPROVED, RequestStatus.ACTIVE, RequestStatus.EXPIRED}:
        raise ConflictError("Remediation tracking is unavailable for this state")
    if progress < request.remediation_progress and status == "not_started":
        raise DomainError("Remediation progress cannot move backwards", code="invalid_remediation_progress")
    old = {"status": request.remediation_status, "progress": request.remediation_progress}
    request.remediation_status = status
    request.remediation_progress = progress
    if status == "completed":
        request.remediation_closure_date = datetime.now(UTC).date()
    validated_evidence_id = None
    if evidence_attachment_id:
        try:
            parsed_evidence_id = uuid.UUID(evidence_attachment_id)
        except ValueError as exc:
            raise DomainError("Evidence attachment is invalid", code="invalid_evidence_attachment") from exc
        evidence = db.scalar(
            select(Attachment).where(
                Attachment.id == parsed_evidence_id,
                Attachment.request_id == request.id,
                Attachment.scan_status == "clean",
                Attachment.deleted_at.is_(None),
            )
        )
        if evidence is None:
            raise DomainError(
                "Evidence must be a clean attachment on this request",
                code="invalid_evidence_attachment",
            )
        validated_evidence_id = evidence.id
    update = RemediationUpdate(
        request_id=request.id,
        actor_id=principal.user.id,
        from_status=old["status"],
        to_status=status,
        progress_percent=progress,
        notes=notes,
        evidence_attachment_id=validated_evidence_id,
    )
    db.add(update)
    record_audit(
        db,
        context,
        action="request.remediation_updated",
        object_type="exception_request",
        object_id=request.public_id,
        old_value=old,
        new_value={
            "status": status,
            "progress": progress,
            "evidence_attachment_id": str(validated_evidence_id) if validated_evidence_id else None,
        },
    )
    return update


def close_request(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    reason: str,
    remediation_completed: bool,
    evidence_attachment_id: str | None,
    context: AuditContext,
) -> None:
    if not (
        request.requester_id == principal.user.id
        or principal.user.id == request.remediation_owner_id
        or principal.has_role("admin")
    ):
        raise AuthorizationError()
    if request.status not in {
        RequestStatus.ACTIVE,
        RequestStatus.EXPIRED,
        RequestStatus.APPROVED,
        RequestStatus.WITHDRAWN,
        RequestStatus.REJECTED,
    }:
        raise ConflictError("This request cannot be closed in its current state")
    if remediation_completed and request.remediation_status != "completed":
        raise DomainError("Remediation must be completed before closing as remediated", code="remediation_incomplete")
    old = request.status
    transition(request, RequestStatus.CLOSED)
    request.closed_at = datetime.now(UTC)
    for assignment in request.approvals:
        if assignment.status == "pending":
            assignment.status = "cancelled"
    db.add(Comment(request_id=request.id, author_id=principal.user.id, kind="closure", body=reason))
    record_audit(
        db,
        context,
        action="request.closed",
        object_type="exception_request",
        object_id=request.public_id,
        old_value={"status": old},
        new_value={
            "status": request.status,
            "reason": reason,
            "remediation_completed": remediation_completed,
            "evidence_attachment_id": evidence_attachment_id,
        },
    )
