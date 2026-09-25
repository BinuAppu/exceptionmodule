from __future__ import annotations

import math
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.errors import NotFoundError
from app.db.session import get_db
from app.models import Notification
from app.services.authz import Principal, get_current_principal

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
def get_notifications(
    unread_only: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    query = select(Notification).where(Notification.user_id == principal.user.id)
    if unread_only:
        query = query.where(Notification.read_at.is_(None))
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    items = list(
        db.scalars(
            query.order_by(Notification.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    return {
        "items": [
            {
                "id": str(item.id),
                "request_id": str(item.request_id) if item.request_id else None,
                "type": item.notification_type,
                "subject": item.subject,
                "body": item.body,
                "action_url": item.action_url,
                "status": item.status,
                "read_at": item.read_at,
                "created_at": item.created_at,
            }
            for item in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    }


@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    notification = db.get(Notification, notification_id)
    if notification is None or notification.user_id != principal.user.id:
        raise NotFoundError("Notification was not found")
    if notification.read_at is None:
        notification.read_at = datetime.now(UTC)
    db.commit()
    return {"message": "Notification marked as read"}
