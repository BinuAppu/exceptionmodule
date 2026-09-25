"""Role-scoped operational reporting.

The report routes deliberately share this module so the JSON summary and CSV
export use exactly the same authorization scope and date boundaries.  The
module only returns non-sensitive request metadata; free-form request content
is never included in an export.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from statistics import median
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import Select, select
from sqlalchemy.orm import Session as DbSession

from app.core.errors import AuthenticationError, AuthorizationError, DomainError
from app.models import (
    ApprovalAction,
    ExceptionRequest,
    RequestStatus,
)
from app.services.authorization import scoped_requests_query
from app.services.authz import Principal

MAX_REPORT_RANGE_DAYS = 3660


@dataclass(frozen=True)
class ReportRange:
    start_date: date
    end_date: date
    start_at: datetime
    end_at_exclusive: datetime
    timezone_name: str = "UTC"


def validate_report_range(
    start_date: date, end_date: date, timezone_name: str = "UTC"
) -> ReportRange:
    """Validate a date-only range and return UTC half-open query bounds.

    The public API uses inclusive dates.  ``end_at_exclusive`` is the first
    instant of the following day, which includes every timestamp on the end
    date without relying on database-specific date functions.
    """

    if end_date < start_date:
        raise DomainError(
            "Report end date must not precede start date",
            code="invalid_report_range",
        )
    if (end_date - start_date).days > MAX_REPORT_RANGE_DAYS:
        raise DomainError(
            "Report date range is too large",
            code="report_range_too_large",
        )
    try:
        timezone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise DomainError(
            "The configured report timezone is invalid",
            code="invalid_report_timezone",
        ) from exc
    local_start = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone)
    try:
        exclusive_date = end_date + timedelta(days=1)
    except OverflowError:
        exclusive_at = datetime.max.replace(tzinfo=UTC)
    else:
        local_end = datetime.combine(exclusive_date, datetime.min.time(), tzinfo=timezone)
        exclusive_at = local_end.astimezone(UTC)
    return ReportRange(
        start_date=start_date,
        end_date=end_date,
        start_at=local_start.astimezone(UTC),
        end_at_exclusive=exclusive_at,
        timezone_name=timezone_name,
    )


def authorize_report_access(principal: Principal) -> None:
    """Require an authenticated principal with an explicit report scope."""

    if not principal.is_authenticated:
        raise AuthenticationError()
    if not (
        principal.has_role("admin")
        or principal.has_role("approver")
        or principal.has_permission("report.read_assigned")
    ):
        raise AuthorizationError("Approver or administrator access is required for reports")


def report_scope_label(principal: Principal) -> str:
    if principal.has_role("admin"):
        return "organization"
    if principal.has_role("approver"):
        return "owned_or_assigned"
    return "owned"


def scoped_report_query(
    principal: Principal, report_range: ReportRange
) -> Select[tuple[ExceptionRequest]]:
    """Return the same bounded request scope for every report operation."""

    return scoped_requests_query(principal).where(
        ExceptionRequest.created_at >= report_range.start_at,
        ExceptionRequest.created_at < report_range.end_at_exclusive,
    )


def report_requests(
    db: DbSession,
    principal: Principal,
    report_range: ReportRange,
    *,
    limit: int | None = None,
) -> list[ExceptionRequest]:
    query = scoped_report_query(principal, report_range).order_by(
        ExceptionRequest.created_at.asc(), ExceptionRequest.id.asc()
    )
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query))


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _approved(request: ExceptionRequest, rejected_ids: set[Any]) -> bool:
    # ``activated_at`` preserves the decision for requests that have since
    # moved to CLOSED.  The explicit states also cover a newly-created test or
    # migrated record that has not gone through the activation job yet.
    if request.id in rejected_ids:
        return False
    return request.activated_at is not None or request.status in {
        RequestStatus.APPROVED,
        RequestStatus.ACTIVE,
        RequestStatus.CLOSED,
    }


def _rejected(request: ExceptionRequest, rejected_ids: set[Any]) -> bool:
    return request.id in rejected_ids or request.status in {
        RequestStatus.REJECTED,
        RequestStatus.MANAGER_REJECTED,
        RequestStatus.DELIVERY_REJECTED,
    }


def _pending(request: ExceptionRequest) -> bool:
    return request.status in {
        RequestStatus.SUBMITTED,
        RequestStatus.PENDING_MANAGER,
        RequestStatus.MANAGER_APPROVED,
        RequestStatus.PENDING_DELIVERY,
        RequestStatus.DELIVERY_APPROVED,
        RequestStatus.PENDING_APPROVER,
        RequestStatus.CLARIFICATION_REQUIRED,
        RequestStatus.EXTENSION_REQUESTED,
        RequestStatus.EXTENSION_PENDING_APPROVAL,
    }


def _overdue_request_ids(
    requests: list[ExceptionRequest], now: datetime, timezone_name: str = "UTC"
) -> set[Any]:
    """Return unique requests with an overdue active/approval/remediation clock."""

    overdue: set[Any] = set()
    today = now.astimezone(ZoneInfo(timezone_name)).date()
    for request in requests:
        if (
            request.status in {RequestStatus.ACTIVE, RequestStatus.EXPIRED}
            and request.expiry_date < today
        ):
            overdue.add(request.id)
        if (
            request.remediation_target_date is not None
            and request.remediation_target_date < today
            and request.remediation_status != "completed"
        ):
            overdue.add(request.id)
        for assignment in request.approvals:
            due_at = _aware(assignment.due_at)
            if (
                assignment.status in {"pending", "clarification"}
                and due_at is not None
                and due_at < now
            ):
                overdue.add(request.id)
                break
    return overdue


def _month_start(value: date) -> date:
    return value.replace(day=1)


def _next_month(value: date) -> date:
    return (value.replace(day=28) + timedelta(days=4)).replace(day=1)


def build_report_summary(
    db: DbSession,
    principal: Principal,
    report_range: ReportRange,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the frontend report summary from one scoped result set."""

    requests = report_requests(db, principal, report_range)
    now = _aware(now) or datetime.now(UTC)
    scoped_ids = scoped_report_query(principal, report_range).with_only_columns(
        ExceptionRequest.id
    ).subquery()
    rejected_ids = set(
        db.scalars(
            select(ApprovalAction.request_id)
            .join(scoped_ids, ApprovalAction.request_id == scoped_ids.c.id)
            .where(ApprovalAction.decision == "reject")
        )
    )
    approval_times: dict[Any, datetime] = {}
    for action_request_id, acted_at in db.execute(
        select(ApprovalAction.request_id, ApprovalAction.acted_at)
        .join(scoped_ids, ApprovalAction.request_id == scoped_ids.c.id)
        .where(ApprovalAction.decision == "approve")
        .order_by(ApprovalAction.acted_at.asc())
    ):
        approval_times[action_request_id] = acted_at
    status_counts = Counter(request.status for request in requests)
    risk_counts = Counter(
        request.risk_level.code if request.risk_level is not None else "unknown"
        for request in requests
    )
    risk_order = {
        request.risk_level.code: (
            request.risk_level.display_order,
            request.risk_level.score,
            request.risk_level.code,
        )
        for request in requests
        if request.risk_level is not None
    }
    category_counts = Counter(
        request.category.name if request.category is not None else "Unknown"
        for request in requests
    )
    category_order = {
        request.category.name: (request.category.display_order, request.category.name)
        for request in requests
        if request.category is not None
    }
    department_counts = Counter(request.department or "Unknown" for request in requests)

    timezone = ZoneInfo(report_range.timezone_name)
    month = _month_start(report_range.start_date)
    monthly: list[dict[str, Any]] = []
    while month <= report_range.end_date:
        try:
            next_month = _next_month(month)
        except OverflowError:
            break
        month_requests = [
            request
            for request in requests
            if (created := _aware(request.created_at)) is not None
            and month <= created.astimezone(timezone).date() < next_month
        ]
        monthly.append(
            {
                "month": month.strftime("%Y-%m"),
                "count": len(month_requests),
                "approved": sum(
                    1 for request in month_requests if _approved(request, rejected_ids)
                ),
            }
        )
        month = next_month

    durations: list[float] = []
    for request in requests:
        submitted = _aware(request.submitted_at)
        activated = _aware(request.activated_at) or _aware(approval_times.get(request.id))
        if submitted is not None and activated is not None:
            seconds = (activated - submitted).total_seconds()
            if seconds >= 0:
                durations.append(seconds / 86_400)

    overdue = _overdue_request_ids(requests, now, report_range.timezone_name)
    return {
        "period_start": report_range.start_date.isoformat(),
        "period_end": report_range.end_date.isoformat(),
        "total_requests": len(requests),
        "approved": sum(1 for request in requests if _approved(request, rejected_ids)),
        "rejected": sum(1 for request in requests if _rejected(request, rejected_ids)),
        "pending": sum(1 for request in requests if _pending(request)),
        "overdue": len(overdue),
        "median_approval_days": round(float(median(durations)), 2) if durations else None,
        "status_breakdown": [
            {"status": status, "count": count}
            for status, count in sorted(status_counts.items())
        ],
        "risk_breakdown": [
            {"risk": risk, "count": count}
            for risk, count in sorted(
                risk_counts.items(), key=lambda item: risk_order.get(item[0], (10_000, 0, item[0]))
            )
        ],
        "category_breakdown": [
            {"category": category, "count": count}
            for category, count in sorted(
                category_counts.items(),
                key=lambda item: category_order.get(item[0], (10_000, item[0])),
            )
        ],
        "department_breakdown": [
            {"department": department, "count": count}
            for department, count in sorted(department_counts.items(), key=lambda item: item[0])
        ],
        "monthly_volume": monthly,
    }


def _csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, str | int | float):
        return value
    return str(value)


def _safe_csv_cell(value: Any) -> str | int | float:
    cell = _csv_value(value)
    if isinstance(cell, str) and cell.startswith(("=", "+", "-", "@")):
        return "'" + cell
    return cell


def report_csv(requests: list[ExceptionRequest]) -> str:
    """Serialize safe request metadata as a deterministic CSV document."""

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "request_id",
            "title",
            "status",
            "risk_level",
            "category",
            "department",
            "requester",
            "created_at",
            "submitted_at",
            "activated_at",
            "requested_start_date",
            "expiry_date",
        ]
    )
    for request in requests:
        writer.writerow(
            [
                _safe_csv_cell(request.public_id),
                _safe_csv_cell(request.title),
                _safe_csv_cell(request.status),
                _safe_csv_cell(request.risk_level.code if request.risk_level else ""),
                _safe_csv_cell(request.category.name if request.category else ""),
                _safe_csv_cell(request.department),
                _safe_csv_cell(request.requester.display_name if request.requester else ""),
                _safe_csv_cell(request.created_at),
                _safe_csv_cell(request.submitted_at),
                _safe_csv_cell(request.activated_at),
                _safe_csv_cell(request.requested_start_date),
                _safe_csv_cell(request.expiry_date),
            ]
        )
    return output.getvalue()


__all__ = [
    "MAX_REPORT_RANGE_DAYS",
    "ReportRange",
    "authorize_report_access",
    "build_report_summary",
    "report_csv",
    "report_requests",
    "report_scope_label",
    "scoped_report_query",
    "validate_report_range",
]
