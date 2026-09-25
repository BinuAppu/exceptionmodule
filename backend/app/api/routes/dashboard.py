from __future__ import annotations

import hashlib
import math
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.api.dependencies import audit_context
from app.db.session import get_db
from app.models import (
    ApprovalAssignment,
    Comment,
    DataClassification,
    ExceptionCategory,
    ExceptionRequest,
    ExportRecord,
    RequestFieldDefinition,
    RequestStatus,
    RequestTemplate,
    RiskLevel,
    User,
)
from app.schemas.common import AuditContext
from app.services.audit import record_audit
from app.services.authorization import scoped_requests_query
from app.services.authz import Principal, get_current_principal
from app.services.reporting import (
    authorize_report_access,
    build_report_summary,
    report_csv,
    report_requests,
    report_scope_label,
    validate_report_range,
)
from app.services.requests import dashboard_metrics, pending_approvals

router = APIRouter(tags=["dashboards and reports"])


def _category_option(category: ExceptionCategory) -> dict:
    return {
        "id": str(category.id),
        "code": category.code,
        "name": category.name,
        "description": category.description,
        "default_duration_days": category.default_duration_days,
        "maximum_duration_days": category.maximum_duration_days,
        "display_order": category.display_order,
        "is_active": category.is_active,
        "system": category.is_system,
        "version": category.version,
        # Keep the normalized name and the admin/frontend ``active`` alias.
        "active": category.is_active,
    }


def _risk_option(level: RiskLevel) -> dict:
    return {
        "id": str(level.id),
        "code": level.code,
        "name": level.name,
        "score": level.score,
        "color": level.color,
        "description": level.description,
        "display_order": level.display_order,
        "is_active": level.is_active,
        "value": level.code,
        "label": level.name,
    }


def _classification_option(classification: DataClassification) -> dict:
    return {
        "id": str(classification.id),
        "code": classification.code,
        "name": classification.name,
        "rank": classification.rank,
        "allow_ai": classification.allow_ai,
        "allow_export": classification.allow_export,
        "is_active": classification.is_active,
    }


def _field_option(field: RequestFieldDefinition) -> dict:
    field_type = {
        "long_text": "textarea",
        "dropdown": "select",
        "boolean": "checkbox",
    }.get(field.data_type, field.data_type)
    options: list[dict[str, str]] = []
    for value in field.allowed_values or []:
        if isinstance(value, dict):
            option_value = value.get("value", value.get("label", ""))
            option_label = value.get("label", option_value)
        else:
            option_value = value
            option_label = value
        options.append({"label": str(option_label), "value": str(option_value)})
    return {
        "id": str(field.id),
        "key": field.field_key,
        "field_key": field.field_key,
        "label": field.label,
        "description": field.description,
        "field_type": field_type,
        "data_type": field.data_type,
        "required": field.is_required,
        "is_required": field.is_required,
        "default_value": field.default_value,
        "validation": field.validation_schema or {},
        "placeholder": field.placeholder,
        "options": options,
        "allowed_values": field.allowed_values or [],
        # An empty visibility list means all categories in the normalized
        # model; the string ``all`` is the legacy form contract.
        "applies_to": [str(item) for item in (field.visible_categories or ["all"])],
        "visible_categories": field.visible_categories or [],
        "visible_roles": field.visible_roles or [],
        "editable_after_submission": field.editable_after_submission,
        "order": field.display_order,
        "display_order": field.display_order,
        "active": field.is_active,
        "is_active": field.is_active,
        "version": field.version,
    }


def _known_departments(db: DbSession) -> list[str]:
    """Return known departments from active users and existing requests.

    User profiles are the primary source.  Existing request values are a
    compatibility fallback for local/imported accounts whose profile has not
    yet been populated; only non-empty values are exposed.
    """

    values: list[str] = []
    values.extend(
        str(value).strip()
        for value in db.scalars(
            select(User.department).where(
                User.department.is_not(None),
                User.status == "active",
            )
        ).all()
        if value is not None
    )
    values.extend(
        str(value).strip()
        for value in db.scalars(
            select(ExceptionRequest.department).where(ExceptionRequest.department.is_not(None))
        ).all()
        if value is not None
    )
    normalized = {
        str(value).strip().casefold(): str(value).strip()
        for value in values
        if value is not None and str(value).strip()
    }
    return [normalized[key] for key in sorted(normalized)]


@router.get("/request-form-options")
def get_request_form_options(
    response: Response,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    """Return only active, non-secret reference data for the request form.

    The endpoint is deliberately read-only and authenticated.  Reference
    values are intentionally organization-wide, but inactive records and
    private request content are never returned.
    """
    response.headers["Cache-Control"] = "no-store, private"

    categories = [
        _category_option(category)
        for category in db.scalars(
            select(ExceptionCategory)
            .where(ExceptionCategory.is_active.is_(True))
            .order_by(ExceptionCategory.display_order.asc(), ExceptionCategory.name.asc())
        )
    ]
    risk_levels = [
        _risk_option(level)
        for level in db.scalars(
            select(RiskLevel)
            .where(RiskLevel.is_active.is_(True))
            .order_by(RiskLevel.display_order.asc(), RiskLevel.score.asc(), RiskLevel.name.asc())
        )
    ]
    classifications = list(
        db.scalars(
            select(DataClassification)
            .where(DataClassification.is_active.is_(True))
            .order_by(DataClassification.rank.asc(), DataClassification.code.asc())
        )
    )
    fields = [
        _field_option(field)
        for field in db.scalars(
            select(RequestFieldDefinition)
            .where(
                RequestFieldDefinition.is_active.is_(True),
                RequestFieldDefinition.is_system.is_(False),
            )
            .order_by(
                RequestFieldDefinition.display_order.asc(), RequestFieldDefinition.label.asc()
            )
        )
    ]
    from app.services.admin import template_to_dict

    templates = [
        template_to_dict(template)
        for template in db.scalars(
            select(RequestTemplate)
            .where(RequestTemplate.is_active.is_(True))
            .order_by(RequestTemplate.name.asc())
        )
    ]
    return {
        "categories": categories,
        "risk_levels": risk_levels,
        # The form contract consumes classification codes; retain the richer
        # records separately for clients that need rank/export policy.
        "data_classifications": [classification.code for classification in classifications],
        "data_classification_options": [_classification_option(item) for item in classifications],
        "custom_fields": fields,
        "departments": _known_departments(db),
        "templates": templates,
        "request_templates": templates,
        # These reference collections are not modeled in the current backend;
        # empty arrays preserve the frontend contract without inventing data.
        "systems": [],
        "controls": [],
    }


def _report_timezone(request: Request) -> str:
    settings = getattr(request.app.state, "settings", None)
    return str(getattr(settings, "business_timezone", "UTC") or "UTC")


@router.get("/reports/summary")
def get_report_summary(
    request: Request,
    response: Response,
    start_date: date = Query(..., description="Inclusive first report date (YYYY-MM-DD)"),
    end_date: date = Query(..., description="Inclusive last report date (YYYY-MM-DD)"),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    authorize_report_access(principal)
    report_range = validate_report_range(start_date, end_date, _report_timezone(request))
    result = build_report_summary(db, principal, report_range)
    response.headers["Cache-Control"] = "no-store, private"
    return result


@router.get("/reports/export")
def export_report(
    request: Request,
    start_date: date = Query(..., description="Inclusive first report date (YYYY-MM-DD)"),
    end_date: date = Query(..., description="Inclusive last report date (YYYY-MM-DD)"),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> Response:
    authorize_report_access(principal)
    report_range = validate_report_range(start_date, end_date, _report_timezone(request))
    requests = report_requests(db, principal, report_range, limit=100_001)
    # A bounded export prevents a single request from materializing an
    # unbounded report.  The summary endpoint remains exact for its response.
    if len(requests) > 100_000:
        from app.core.errors import DomainError

        raise DomainError(
            "The report contains too many rows for a synchronous export; narrow the date range",
            code="report_export_too_large",
        )
    content = report_csv(requests)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    export = ExportRecord(
        requested_by_id=principal.user.id,
        export_type="exception_report",
        scope={
            "start_date": report_range.start_date.isoformat(),
            "end_date": report_range.end_date.isoformat(),
            "access_scope": report_scope_label(principal),
        },
        status="completed",
        row_count=len(requests),
        sha256=digest,
        correlation_id=context.correlation_id,
    )
    db.add(export)
    db.flush()
    record_audit(
        db,
        context,
        action="report.exported",
        object_type="report_export",
        object_id=str(export.id),
        new_value={
            "start_date": report_range.start_date.isoformat(),
            "end_date": report_range.end_date.isoformat(),
            "format": "csv",
            "row_count": len(requests),
            "access_scope": report_scope_label(principal),
            "sha256": digest,
        },
    )
    db.commit()
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                "attachment; filename=\"exception-report-"
                f"{report_range.start_date.isoformat()}-to-{report_range.end_date.isoformat()}.csv\""
            ),
            "Cache-Control": "no-store, private",
        },
    )


@router.get("/dashboard")
def get_dashboard(
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    metrics = dashboard_metrics(db, principal)
    if principal.has_role("approver") or principal.has_role("admin"):
        now = datetime.now(UTC)
        pending_count = int(
            db.scalar(
                select(func.count(ApprovalAssignment.id)).where(
                    ApprovalAssignment.approver_id == principal.user.id,
                    ApprovalAssignment.status.in_(["pending", "clarification"]),
                )
            )
            or 0
        )
        sla_breaches = int(
            db.scalar(
                select(func.count(ApprovalAssignment.id)).where(
                    ApprovalAssignment.approver_id == principal.user.id,
                    ApprovalAssignment.status.in_(["pending", "clarification"]),
                    ApprovalAssignment.due_at < now,
                )
            )
            or 0
        )
        metrics["pending_approvals"] = pending_count
        metrics["sla_breaches"] = sla_breaches
    return metrics


@router.get("/approvals")
def get_approvals(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    if not (principal.has_role("approver") or principal.has_role("admin")):
        from app.core.errors import AuthorizationError

        raise AuthorizationError("Approver access is required")
    items, total = pending_approvals(db, principal, page=page, page_size=page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    }


def _authorized_ids(db: DbSession, principal: Principal) -> list[str]:
    return list(db.scalars(scoped_requests_query(principal).with_only_columns(ExceptionRequest.public_id)))


@router.get("/admin/metrics")
def get_admin_metrics(
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    if not principal.has_role("admin"):
        from app.core.errors import AuthorizationError

        raise AuthorizationError("Administrator access is required")
    now = datetime.now(UTC)
    today = now.date()
    ids = _authorized_ids(db, principal)
    if not ids:
        return {
            "volume": {},
            "workflow": {},
            "risk": [],
            "expiration": {},
            "remediation": {},
            "trends": {},
        }
    base = ExceptionRequest.public_id.in_(ids)
    month_start = today.replace(day=1)
    year_start = today.replace(month=1, day=1)
    total = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base)) or 0)
    this_month = int(
        db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.created_at >= month_start)) or 0
    )
    this_year = int(
        db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.created_at >= year_start)) or 0
    )
    active = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.status == RequestStatus.ACTIVE)) or 0)
    expired = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.status == RequestStatus.EXPIRED)) or 0)
    pending_states = [
        RequestStatus.SUBMITTED,
        RequestStatus.PENDING_MANAGER,
        RequestStatus.PENDING_DELIVERY,
        RequestStatus.PENDING_APPROVER,
        RequestStatus.EXTENSION_PENDING_APPROVAL,
    ]
    pending = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.status.in_(pending_states))) or 0)
    clarifications = int(
        db.scalar(
            select(func.count(Comment.id))
            .join(ExceptionRequest, ExceptionRequest.id == Comment.request_id)
            .where(base, Comment.kind == "clarification_response")
        )
        or 0
    )
    submitted = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.submitted_at.is_not(None))) or 0)
    approved_rows = list(db.execute(select(ExceptionRequest.submitted_at, ExceptionRequest.activated_at).where(base, ExceptionRequest.activated_at.is_not(None))))
    durations = [
        (activated - submitted).total_seconds() / 3600
        for submitted, activated in approved_rows
        if submitted and activated
    ]
    average_hours = sum(durations) / len(durations) if durations else 0
    sla_breaches = int(
        db.scalar(
            select(func.count(ApprovalAssignment.id))
            .join(ExceptionRequest, ExceptionRequest.id == ApprovalAssignment.request_id)
            .where(base, ApprovalAssignment.status == "pending", ApprovalAssignment.due_at < now)
        )
        or 0
    )
    risk_rows = db.execute(
        select(RiskLevel.name, func.count(ExceptionRequest.id))
        .join(ExceptionRequest, ExceptionRequest.risk_level_id == RiskLevel.id)
        .where(base)
        .group_by(RiskLevel.name)
    ).all()
    department_rows = db.execute(
        select(ExceptionRequest.department, func.count(ExceptionRequest.id))
        .where(base)
        .group_by(ExceptionRequest.department)
        .order_by(func.count(ExceptionRequest.id).desc())
    ).all()

    def expiring(days: int) -> int:
        return int(
            db.scalar(
                select(func.count(ExceptionRequest.id)).where(
                    base,
                    ExceptionRequest.status == RequestStatus.ACTIVE,
                    ExceptionRequest.expiry_date >= today,
                    ExceptionRequest.expiry_date <= today + timedelta(days=days),
                )
            )
            or 0
        )

    with_plan = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.remediation_plan != "")) or 0)
    overdue = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.remediation_target_date < today, ExceptionRequest.remediation_status != "completed")) or 0)
    completed = int(db.scalar(select(func.count(ExceptionRequest.id)).where(base, ExceptionRequest.remediation_status == "completed")) or 0)
    trends = []
    for offset in range(11, -1, -1):
        month = (today.replace(day=1) - timedelta(days=offset * 30)).replace(day=1)
        next_month = (month + timedelta(days=32)).replace(day=1)
        rows = db.execute(
            select(ExceptionRequest.status, func.count(ExceptionRequest.id))
            .where(base, ExceptionRequest.created_at >= month, ExceptionRequest.created_at < next_month)
            .group_by(ExceptionRequest.status)
        ).all()
        trends.append(
            {
                "month": month.strftime("%Y-%m"),
                "total": sum(count for _, count in rows),
                "approved_or_active": sum(count for state, count in rows if state in {RequestStatus.APPROVED, RequestStatus.ACTIVE, RequestStatus.CLOSED}),
                "rejected": sum(count for state, count in rows if state in {RequestStatus.REJECTED, RequestStatus.MANAGER_REJECTED, RequestStatus.DELIVERY_REJECTED}),
            }
        )
    return {
        "volume": {
            "total": total,
            "this_month": this_month,
            "this_year": this_year,
            "active": active,
            "expired": expired,
        },
        "workflow": {
            "pending_approvals": pending,
            "average_approval_hours": round(average_hours, 1),
            "sla_breaches": sla_breaches,
            "clarification_rate_percent": round((clarifications / submitted * 100) if submitted else 0, 1),
        },
        "risk": [{"risk": name, "count": count} for name, count in risk_rows],
        "business_units": [{"department": department, "count": count} for department, count in department_rows],
        "expiration": {
            "in_30_days": expiring(30),
            "in_14_days": expiring(14),
            "in_7_days": expiring(7),
            "expired": expired,
        },
        "remediation": {
            "with_plans": with_plan,
            "overdue": overdue,
            "completion_rate_percent": round((completed / with_plan * 100) if with_plan else 0, 1),
        },
        "trends": {"monthly": trends},
    }
