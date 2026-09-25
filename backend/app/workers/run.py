from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.correlation import correlation_id_context
from app.core.errors import DomainError
from app.db.session import SessionLocal, session_scope
from app.models import (
    BackgroundJob,
    Notification,
    SystemConfig,
)
from app.schemas.common import AuditContext
from app.services.ai import execute_log_analysis, execute_request_analysis
from app.services.audit import record_audit
from app.services.backups import execute_backup
from app.services.email import active_template, render_template, send_email
from app.services.files import complete_scan
from app.services.notifications import expire_due_requests, process_sla_and_escalations, send_expiration_reminders
from app.services.outbox import enqueue_job
from app.services.retention import archive_expired_audit_events
from app.services.workflow import activate_due_request

logger = logging.getLogger(__name__)


def _system_context(correlation_id: str) -> AuditContext:
    return AuditContext(
        actor_id=None,
        actor_label="system:worker",
        correlation_id=correlation_id,
        request_id=None,
        metadata={"component": "worker"},
    )


def claim_job(worker_id: str) -> uuid.UUID | None:
    now = datetime.now(UTC)
    with session_scope() as db:
        job = db.scalar(
            select(BackgroundJob)
            .where(
                BackgroundJob.status.in_(["queued", "retry"]),
                BackgroundJob.run_at <= now,
                (BackgroundJob.locked_until.is_(None) | (BackgroundJob.locked_until < now)),
            )
            .order_by(BackgroundJob.priority.asc(), BackgroundJob.run_at.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        job.status = "running"
        job.locked_by = worker_id
        job.locked_until = now + timedelta(minutes=10)
        job.attempts += 1
        job.last_error = None
        return job.id


def _send_notification(db, job: BackgroundJob, settings: Settings) -> None:
    notification = db.get(Notification, uuid.UUID(job.payload["notification_id"]))
    if notification is None or notification.status in {"sent", "cancelled"}:
        return
    request = notification.request
    values = {
        "request_id": request.public_id if request else "",
        "request_title": request.title if request else "",
        "requester_name": request.requester.display_name if request and request.requester else "",
        "manager_name": request.manager.display_name if request and request.manager else "",
        "approver_name": notification.user.display_name,
        "exception_type": request.exception_type if request else "",
        "expiry_date": request.expiry_date.isoformat() if request else "",
        "approval_url": notification.action_url or "",
        "application_name": request.application_name if request else "",
        "notification_message": notification.body,
    }
    event_map = {
        "approval_required": "manager_approval_required",
        "extension_approval_required": "extension_requested",
    }
    template = active_template(db, event_map.get(notification.notification_type, notification.notification_type))
    subject = render_template(template.subject_template, values) if template else notification.subject
    body = render_template(template.body_template, values) if template else notification.body
    send_email(
        db,
        to_address=notification.user.email,
        subject=subject,
        body=body,
        settings=settings,
    )
    notification.status = "sent"
    notification.sent_at = datetime.now(UTC)
    notification.attempt_count += 1
    notification.last_error = None


def process_job(job_id: uuid.UUID, settings: Settings) -> None:
    with session_scope() as db:
        job = db.get(BackgroundJob, job_id)
        if job is None or job.status != "running":
            return
        context = _system_context(job.correlation_id or str(job.id))
        payload: dict[str, Any] = job.payload
        if job.job_type == "send_notification":
            _send_notification(db, job, settings)
        elif job.job_type == "activate_request":
            activate_due_request(db, uuid.UUID(payload["request_id"]), context)
        elif job.job_type == "schedule_expiration":
            activate_due_request(db, uuid.UUID(payload["request_id"]), context)
            expire_due_requests(db, settings, context)
        elif job.job_type == "scan_attachment":
            complete_scan(db, uuid.UUID(payload["attachment_id"]), settings, context)
        elif job.job_type == "ai_request_analysis":
            execute_request_analysis(db, uuid.UUID(payload["analysis_id"]), settings, context)
        elif job.job_type == "ai_log_analysis":
            execute_log_analysis(
                db,
                uuid.UUID(payload["analysis_id"]),
                datetime.fromisoformat(payload["window_start"]),
                datetime.fromisoformat(payload["window_end"]),
                settings,
                context,
            )
        elif job.job_type == "expire_requests":
            expire_due_requests(db, settings, context)
        elif job.job_type == "expiration_reminders":
            send_expiration_reminders(db, settings, context)
        elif job.job_type == "sla_escalations":
            process_sla_and_escalations(db, settings, context)
        elif job.job_type == "database_backup":
            execute_backup(db, uuid.UUID(payload["backup_id"]), settings)
        elif job.job_type == "audit_retention":
            archive_expired_audit_events(db, settings, context)
        else:
            raise DomainError(f"Unsupported background job type '{job.job_type}'", code="unknown_job_type")
        job.status = "completed"
        job.completed_at = datetime.now(UTC)
        job.locked_by = None
        job.locked_until = None
        record_audit(
            db,
            context,
            action="job.completed",
            object_type="background_job",
            object_id=str(job.id),
            new_value={"job_type": job.job_type, "attempts": job.attempts},
        )


def fail_job(job_id: uuid.UUID, exc: Exception) -> None:
    with session_scope() as db:
        job = db.get(BackgroundJob, job_id)
        if job is None:
            return
        context = _system_context(job.correlation_id or str(job.id))
        safe_message = f"{type(exc).__name__}: {str(exc)[:900]}"
        job.last_error = safe_message
        job.locked_by = None
        job.locked_until = None
        if job.attempts >= job.max_attempts:
            job.status = "failed"
        else:
            job.status = "retry"
            job.run_at = datetime.now(UTC) + timedelta(seconds=job.next_backoff_seconds)
        record_audit(
            db,
            context,
            action="job.failed" if job.status == "failed" else "job.retry_scheduled",
            object_type="background_job",
            object_id=str(job.id),
            result="failure",
            failure_reason=safe_message,
            new_value={"job_type": job.job_type, "attempts": job.attempts, "next_run_at": job.run_at.isoformat()},
        )


def schedule_periodic_jobs(settings: Settings) -> None:
    now = datetime.now(UTC)
    five_minute_slot = now.strftime("%Y%m%d%H") + f"{(now.minute // 5) * 5:02d}"
    daily_slot = now.strftime("%Y%m%d")
    slots = {
        "expire_requests": (now, five_minute_slot),
        "expiration_reminders": (now, five_minute_slot),
        "sla_escalations": (now, five_minute_slot),
        "audit_retention": (now.replace(hour=2, minute=15, second=0, microsecond=0), daily_slot),
    }
    with session_scope() as db:
        for job_type, (run_at, bucket) in slots.items():
            if run_at <= now:
                run_at = now
            enqueue_job(
                db,
                job_type,
                {},
                deduplication_key=f"periodic:{job_type}:{bucket}",
                run_at=run_at,
                correlation_id=f"scheduler-{job_type}-{run_at:%Y%m%d%H%M}",
            )


def run_periodic_sweeps(settings: Settings) -> None:
    with session_scope() as db:
        context = _system_context(f"periodic-{datetime.now(UTC).isoformat()}")
        if db.scalar(select(BackgroundJob.id).where(BackgroundJob.job_type == "expire_requests", BackgroundJob.status == "queued")) is None:
            expire_due_requests(db, settings, context)
        if db.scalar(select(BackgroundJob.id).where(BackgroundJob.job_type == "expiration_reminders", BackgroundJob.status == "queued")) is None:
            send_expiration_reminders(db, settings, context)
        if db.scalar(select(BackgroundJob.id).where(BackgroundJob.job_type == "sla_escalations", BackgroundJob.status == "queued")) is None:
            process_sla_and_escalations(db, settings, context)


def run_forever(settings: Settings) -> None:
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    stopping = False

    def stop(_: int, __: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logger.info("worker_started", extra={"component": "worker", "operation": "start", "result": "success"})
    last_periodic = datetime.min.replace(tzinfo=UTC)
    while not stopping:
        schedule_periodic_jobs(settings)
        run_periodic_sweeps(settings)
        job_id = claim_job(worker_id)
        if job_id:
            correlation_id = correlation_id_context.get() or str(job_id)
            correlation_id_context.set(correlation_id)
            try:
                process_job(job_id, settings)
            except Exception as exc:  # Worker boundary logs and persists safe failure metadata.
                logger.exception("job_processing_failed", extra={"component": "worker", "error_type": type(exc).__name__})
                fail_job(job_id, exc)
        else:
            time.sleep(2)
        if (datetime.now(UTC) - last_periodic).total_seconds() > 300:
            last_periodic = datetime.now(UTC)
    logger.info("worker_stopped", extra={"component": "worker", "operation": "stop", "result": "success"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Exception-Manager durable background worker")
    parser.add_argument("--once", action="store_true", help="Process at most one available job")
    args = parser.parse_args()
    settings = get_settings()
    if args.once:
        schedule_periodic_jobs(settings)
        job_id = claim_job(f"once:{os.getpid()}")
        if job_id:
            try:
                process_job(job_id, settings)
            except Exception as exc:
                fail_job(job_id, exc)
        return
    run_forever(settings)


if __name__ == "__main__":
    main()
