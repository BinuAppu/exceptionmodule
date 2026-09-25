from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.models import BackgroundJob, Notification, User


def enqueue_job(
    db: DbSession,
    job_type: str,
    payload: dict[str, Any],
    *,
    deduplication_key: str | None = None,
    run_at: datetime | None = None,
    correlation_id: str,
    priority: int = 100,
) -> BackgroundJob | None:
    if deduplication_key:
        existing = db.scalar(
            select(BackgroundJob).where(BackgroundJob.deduplication_key == deduplication_key)
        )
        if existing:
            return existing
    job = BackgroundJob(
        job_type=job_type,
        payload=payload,
        deduplication_key=deduplication_key,
        run_at=run_at or datetime.now(UTC),
        correlation_id=correlation_id,
        priority=priority,
    )
    db.add(job)
    db.flush()
    return job


def queue_notification(
    db: DbSession,
    *,
    user: User,
    request_id: str | None,
    notification_type: str,
    subject: str,
    body: str,
    action_url: str | None,
    idempotency_key: str,
    correlation_id: str,
) -> Notification | None:
    existing = db.scalar(select(Notification).where(Notification.idempotency_key == idempotency_key))
    if existing:
        return existing
    notification = Notification(
        user_id=user.id,
        request_id=request_id,
        notification_type=notification_type,
        subject=subject,
        body=body,
        action_url=action_url,
        idempotency_key=idempotency_key,
    )
    db.add(notification)
    db.flush()
    enqueue_job(
        db,
        "send_notification",
        {"notification_id": str(notification.id)},
        deduplication_key=f"notification:{idempotency_key}",
        correlation_id=correlation_id,
    )
    return notification
