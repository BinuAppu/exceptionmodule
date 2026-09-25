from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.models import AuditArchive, AuditEvent, SystemConfig
from app.schemas.common import AuditContext
from app.services.audit import archive_candidate_ids, record_audit


def archive_expired_audit_events(
    db: DbSession, settings: Settings, context: AuditContext, *, batch_size: int = 1000
) -> int:
    retention_days = int(
        db.scalar(
            select(SystemConfig.value).where(
                SystemConfig.config_key == "audit.retention_days",
                SystemConfig.is_active.is_(True),
            )
        )
        or settings.audit_retention_days
    )
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    candidate_ids = archive_candidate_ids(db, cutoff, batch_size)
    if not candidate_ids:
        return 0
    events = list(db.scalars(select(AuditEvent).where(AuditEvent.id.in_(candidate_ids))))
    policy = f"retention_days={retention_days}"
    record_audit(
        db,
        context,
        action="audit.retention_archive_started",
        object_type="audit_retention_run",
        object_id=context.correlation_id,
        new_value={"event_count": len(events), "cutoff": cutoff.isoformat(), "policy": policy},
    )
    for event in events:
        payload = {
            "id": str(event.id),
            "occurred_at": event.occurred_at.isoformat(),
            "actor_id": event.actor_id,
            "actor_label": event.actor_label,
            "source_ip": event.source_ip,
            "user_agent": event.user_agent,
            "action": event.action,
            "object_type": event.object_type,
            "object_id": event.object_id,
            "old_value": event.old_value,
            "new_value": event.new_value,
            "result": event.result,
            "failure_reason": event.failure_reason,
            "correlation_id": event.correlation_id,
            "request_id": event.request_id,
            "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        }
        db.add(
            AuditArchive(
                source_event_id=event.id,
                event_payload=json.dumps(payload, separators=(",", ":"), default=str).encode(),
                event_hash=event.event_hash,
                original_occurred_at=event.occurred_at,
                archive_reference=f"database-audit-archive:{event.id}",
                policy_version=policy,
                retention_reason=f"Aged beyond configured retention of {retention_days} days",
            )
        )
    db.flush()
    # Bulk SQL is the only controlled archival deletion path. PostgreSQL's trigger additionally
    # requires this transaction-local capability; no API exposes UPDATE/DELETE on audits.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT set_config('app.audit_retention', 'on', true)"))
    db.execute(delete(AuditEvent).where(AuditEvent.id.in_(candidate_ids)).execution_options(synchronize_session=False))
    record_audit(
        db,
        context,
        action="audit.retention_archive_completed",
        object_type="audit_retention_run",
        object_id=context.correlation_id,
        new_value={"event_count": len(events), "archive_records": len(events)},
    )
    return len(events)
