from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.models import BusinessHoliday


def _calendar_dates(db: DbSession, settings: Settings, start: date, end: date) -> set[date]:
    rows = db.scalars(
        select(BusinessHoliday.holiday_date).where(
            BusinessHoliday.calendar_code == "global",
            BusinessHoliday.holiday_date.between(start, end),
        )
    )
    return set(rows)


def add_business_days(
    db: DbSession,
    start: datetime,
    business_days: int,
    settings: Settings,
    *,
    calendar_code: str = "global",
) -> datetime:
    if business_days < 0:
        raise ValueError("Business days cannot be negative")
    try:
        timezone = ZoneInfo(settings.business_timezone)
    except ZoneInfoNotFoundError as exc:
        raise DomainError("Configured business timezone is invalid", code="configuration_error") from exc
    local = start.astimezone(timezone)
    current_date = local.date()
    end_date = current_date + timedelta(days=max(370, business_days * 2 + 14))
    holidays = _calendar_dates(db, settings, current_date, end_date)
    remaining = business_days
    while remaining:
        current_date += timedelta(days=1)
        if current_date.weekday() in settings.business_weekdays and current_date not in holidays:
            remaining -= 1
    result = datetime.combine(current_date, time(hour=17), tzinfo=timezone)
    return result.astimezone(UTC)
