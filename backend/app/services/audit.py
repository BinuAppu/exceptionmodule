from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, event, func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings, get_settings
from app.core.security import new_fernet, redact_secrets
from app.models import AuditArchive, AuditEvent
from app.schemas.common import AuditContext


def _canonical(value: Any) -> bytes:
    safe = redact_secrets(value)
    return json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def audit_digest(
    *,
    previous_hash: str | None,
    occurred_at: datetime,
    actor_id: str | None,
    action: str,
    object_type: str | None,
    object_id: str | None,
    result: str,
    correlation_id: str,
    old_value: Any,
    new_value: Any,
) -> str:
    payload = {
        "previous_hash": previous_hash,
        "occurred_at": occurred_at.isoformat(),
        "actor_id": actor_id,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "result": result,
        "correlation_id": correlation_id,
        "old_value": old_value,
        "new_value": new_value,
    }
    settings = get_settings()
    # Encryption is disabled for local keys unless explicitly set; this still yields a keyed digest in production.
    key = new_fernet(settings)._signing_key  # noqa: SLF001 - Fernet exposes no public signing key accessor
    import hmac

    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


def record_audit(
    db: DbSession,
    context: AuditContext,
    *,
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    old_value: Any = None,
    new_value: Any = None,
    result: str = "success",
    failure_reason: str | None = None,
) -> AuditEvent:
    """Append one tamper-evident audit event inside the caller's transaction."""
    if result not in {"success", "failure", "denied", "partial"}:
        raise ValueError("Invalid audit result")
    now = datetime.now(UTC)
    previous = db.scalar(
        select(AuditEvent).order_by(AuditEvent.occurred_at.desc(), AuditEvent.created_at.desc()).limit(1)
    )
    previous_hash = previous.event_hash if previous else None
    event_id = uuid.uuid4()
    event_hash = audit_digest(
        previous_hash=previous_hash,
        occurred_at=now,
        actor_id=context.actor_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        result=result,
        correlation_id=context.correlation_id,
        old_value=old_value,
        new_value=new_value,
    )
    audit = AuditEvent(
        id=event_id,
        occurred_at=now,
        actor_id=context.actor_id,
        actor_label=context.actor_label,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        action=action,
        object_type=object_type,
        object_id=object_id,
        old_value=redact_secrets(old_value) if old_value is not None else None,
        new_value=redact_secrets(new_value) if new_value is not None else None,
        result=result,
        failure_reason=failure_reason[:1000] if failure_reason else None,
        correlation_id=context.correlation_id,
        request_id=context.request_id,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    db.add(audit)
    db.flush()
    return audit


def timeline_for_request(db: DbSession, request_id: str, limit: int = 500) -> list[AuditEvent]:
    query: Select[tuple[AuditEvent]] = (
        select(AuditEvent)
        .where(AuditEvent.object_type == "exception_request", AuditEvent.object_id == request_id)
        .order_by(AuditEvent.occurred_at.asc())
        .limit(min(limit, 1000))
    )
    return list(db.scalars(query))


@event.listens_for(AuditEvent, "before_update")
def _prevent_audit_update(_: object, __: object) -> None:
    raise RuntimeError("Audit events are append-only")


@event.listens_for(AuditEvent, "before_delete")
def _prevent_audit_delete(_: object, __: object) -> None:
    raise RuntimeError("Audit events are append-only; use the controlled archival process")


def audit_counts(db: DbSession, start: datetime | None = None, end: datetime | None = None) -> dict[str, int]:
    query = select(func.count()).select_from(AuditEvent)
    if start:
        query = query.where(AuditEvent.occurred_at >= start)
    if end:
        query = query.where(AuditEvent.occurred_at < end)
    return {"total": int(db.scalar(query) or 0)}


def archive_candidate_ids(db: DbSession, cutoff: datetime, limit: int = 1000) -> list[uuid.UUID]:
    return list(
        db.scalars(
            select(AuditEvent.id)
            .where(AuditEvent.occurred_at < cutoff, AuditEvent.retention_archived_at.is_(None))
            .order_by(AuditEvent.occurred_at.asc())
            .limit(limit)
        )
    )
