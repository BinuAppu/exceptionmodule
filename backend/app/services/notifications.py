from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.models import ExceptionRequest, Notification, RequestStatus, User
from app.schemas.common import AuditContext
from app.services.audit import record_audit
from app.services.outbox import queue_notification
from app.services.workflow import transition


def expire_due_requests(db: DbSession, settings: Settings, context: AuditContext) -> int:
    today = datetime.now(UTC).date()
    requests = list(
        db.scalars(
            select(ExceptionRequest)
            .where(
                ExceptionRequest.status.in_([RequestStatus.APPROVED, RequestStatus.ACTIVE]),
                ExceptionRequest.expiry_date < today,
            )
            .with_for_update(skip_locked=True)
        )
    )
    for request in requests:
        old = request.status
        transition(request, RequestStatus.EXPIRED)
        request.expired_at = datetime.now(UTC)
        record_audit(
            db,
            context,
            action="request.expired",
            object_type="exception_request",
            object_id=request.public_id,
            old_value={"status": old},
            new_value={"status": request.status, "expiry_date": request.expiry_date.isoformat()},
        )
        if request.requester:
            queue_notification(
                db,
                user=request.requester,
                request_id=request.public_id,
                notification_type="exception_expired",
                subject=f"Exception expired: {request.public_id}",
                body="The exception has expired and is no longer active. Sign in to review its status.",
                action_url=f"/requests/{request.public_id}",
                idempotency_key=f"expired:{request.id}",
                correlation_id=context.correlation_id,
            )
    return len(requests)


def send_expiration_reminders(db: DbSession, settings: Settings, context: AuditContext) -> int:
    today = datetime.now(UTC).date()
    reminders = sorted(set(int(day) for day in settings.default_expiration_reminders), reverse=True)
    sent = 0
    requests = list(
        db.scalars(
            select(ExceptionRequest).where(
                ExceptionRequest.status == RequestStatus.ACTIVE,
                ExceptionRequest.expiry_date >= today,
            )
        )
    )
    for request in requests:
        days_remaining = (request.expiry_date - today).days
        for days in reminders:
            if days_remaining == days:
                queue_notification(
                    db,
                    user=request.requester,
                    request_id=request.public_id,
                    notification_type="exception_expiring",
                    subject=f"Exception expires in {days} days: {request.public_id}",
                    body=f"Your exception expires on {request.expiry_date.isoformat()}. Review remediation or request an extension if eligible.",
                    action_url=f"/requests/{request.public_id}",
                    idempotency_key=f"expiration-reminder:{request.id}:{days}:{request.expiry_date.isoformat()}",
                    correlation_id=context.correlation_id,
                )
                sent += 1
        if days_remaining <= min(reminders, default=30):
            request.last_notification_at = datetime.now(UTC)
    return sent


def process_sla_and_escalations(db: DbSession, settings: Settings, context: AuditContext) -> int:
    from app.models import ApprovalAssignment, User, WorkflowStage

    now = datetime.now(UTC)
    assignments = list(
        db.scalars(
            select(ApprovalAssignment)
            .where(ApprovalAssignment.status == "pending", ApprovalAssignment.due_at <= now)
            .with_for_update(skip_locked=True)
        )
    )
    breached = 0
    for assignment in assignments:
        request = db.get(ExceptionRequest, assignment.request_id)
        # An idempotent breach event is represented by the assignment's current state/time;
        # escalation is performed at most once by checking audit history.
        if assignment.escalated_at:
            continue
        stage = db.get(WorkflowStage, assignment.workflow_stage_id) if assignment.workflow_stage_id else None
        backup = db.get(User, stage.backup_approver_id) if stage and stage.backup_approver_id else None
        record_audit(
            db,
            context,
            action="approval.sla_breached",
            object_type="exception_request",
            object_id=request.public_id,
            new_value={"assignment_id": str(assignment.id), "due_at": assignment.due_at.isoformat()},
        )
        assignment.escalated_at = now
        breached += 1
        if backup and backup.status == "active" and backup.id != request.requester_id:
            original = assignment.approver
            assignment.approver_id = backup.id
            assignment.delegated_from_id = original.id
            assignment.token_hash = None
            assignment.token_expires_at = None
            queue_notification(
                db,
                user=backup,
                request_id=request.public_id,
                notification_type="approval_escalated",
                subject=f"Escalated approval: {request.public_id}",
                body="An overdue approval was escalated to the configured backup approver. Sign in to review it.",
                action_url=f"/approvals/pending?request={request.public_id}",
                idempotency_key=f"sla-escalation:{assignment.id}",
                correlation_id=context.correlation_id,
            )
    return breached
