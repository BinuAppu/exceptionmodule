from __future__ import annotations

import csv
import io
import json
import math
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.api.dependencies import audit_context, require_reauthentication
from app.core.errors import AuthorizationError, DomainError, NotFoundError
from app.core.security import verify_password
from app.db.session import get_db
from app.schemas.admin import (
    AiConfigurationUpdate,
    AuditExportCreate,
    BackupCreate,
    CategoryCreate,
    CategoryUpdate,
    ConfigUpdate,
    DelegationCreate,
    EmailPreviewRequest,
    EmailTemplateUpsert,
    FieldCreate,
    FieldUpdate,
    RequestTemplateCreate,
    RequestTemplateUpdate,
    RetentionRun,
    SecurityConfigUpdate,
    UserAdminUpdate,
    WorkflowUpsert,
)
from app.schemas.common import AuditContext
from app.schemas.sso import SSOConfigurationResponse, SSOConfigurationUpdate, SSOValidationResult
from app.services.admin import (
    create_category,
    create_delegation,
    create_field,
    create_template,
    create_workflow,
    delete_template,
    duplicate_template,
    template_to_dict,
    update_ai_configuration,
    update_category,
    update_config,
    update_field,
    update_template,
    update_user,
    upsert_email_template,
)
from app.services.ai import ai_configuration, queue_log_analysis
from app.services.audit import record_audit
from app.services.authz import Principal, get_current_principal, require_role
from app.services.backups import create_backup_record
from app.services.email import render_template, validate_template
from app.services.outbox import enqueue_job
from app.services.sso import (
    get_effective_sso_config,
    sanitized_sso_configuration,
    update_sso_configuration,
    validate_sso_configuration,
)

router = APIRouter(prefix="/admin", tags=["administration"], dependencies=[Depends(require_role("admin"))])


@router.get("/overview")
def admin_overview(
    request: Request,
    db: DbSession = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> dict:
    settings = request.app.state.settings
    sso = get_effective_sso_config(db, settings)
    return {
        "environment": settings.environment,
        "version": settings.app_version,
        "authentication": {
            "sso_enabled": bool(sso.enabled and not sso.bootstrap),
            "sso_provider": sso.provider if sso.enabled and not sso.bootstrap else None,
            "sso_display_name": sso.display_name if sso.enabled and not sso.bootstrap else None,
            "local_break_glass_account_exists": True,
        },
        "integrations": {
            "smtp_configured": bool(settings.smtp_host),
            "malware_scanner": settings.attachment_scan_mode,
            "azure_openai": ai_configuration(db, settings),
        },
        "security": {
            "csrf_protection": True,
            "secure_cookie": settings.session_cookie_secure,
            "session_idle_minutes": settings.session_idle_minutes,
            "audit_append_only": True,
        },
    }


@router.get("/users")
def list_users(
    search: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: DbSession = Depends(get_db),
) -> dict:
    from app.models import User

    query = select(User)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            User.display_name.ilike(term) | User.email_normalized.ilike(term) | User.public_id.ilike(term)
        )
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    users = list(db.scalars(query.order_by(User.display_name.asc()).offset((page - 1) * page_size).limit(page_size)))
    return {
        "items": [
            {
                "id": str(user.id),
                "public_id": user.public_id,
                "email": user.email,
                "display_name": user.display_name,
                "department": user.department,
                "job_title": user.job_title,
                "manager_id": str(user.manager_id) if user.manager_id else None,
                "status": user.status,
                "roles": sorted(role.role.code for role in user.user_roles),
                "is_break_glass": user.is_break_glass,
                "last_login_at": user.last_login_at,
                "version": user.version,
            }
            for user in users
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    }


@router.patch("/users/{user_id}")
def patch_user(
    user_id: str,
    payload: UserAdminUpdate,
    request: Request,
    x_reauthentication_password: str | None = Header(default=None, alias="X-Reauthentication-Password"),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    reauthenticated = False
    if x_reauthentication_password and principal.user.password_hash:
        reauthenticated = verify_password(principal.user.password_hash, x_reauthentication_password)
        if not reauthenticated:
            raise AuthorizationError("Re-authentication password is invalid")
    user = update_user(
        db,
        uuid.UUID(user_id),
        payload,
        principal,
        request.app.state.settings,
        context,
        reauthenticated=reauthenticated,
    )
    db.commit()
    return {"id": str(user.id), "public_id": user.public_id, "status": user.status, "version": user.version}


@router.get("/sso", response_model=SSOConfigurationResponse)
def get_sso_configuration(
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
) -> dict:
    """Return only the sanitized, flat runtime SSO configuration."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return sanitized_sso_configuration(db, request.app.state.settings)


@router.put("/sso", response_model=SSOConfigurationResponse)
def put_sso_configuration(
    payload: SSOConfigurationUpdate,
    request: Request,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required for SSO configuration changes")
    result = update_sso_configuration(
        db,
        payload,
        principal,
        context,
        request.app.state.settings,
        request_base_url=str(request.base_url).rstrip("/"),
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return result


@router.post("/sso/validate", response_model=SSOValidationResult)
async def validate_sso(
    payload: SSOConfigurationUpdate,
    request: Request,
    response: Response,
) -> dict:
    # Validation is explicitly non-persisting.  It is still admin-only via
    # the router dependency, but it does not mutate configuration or require a
    # fresh password because no state is changed.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    result = await validate_sso_configuration(payload, request.app.state.settings)
    return result.model_dump()


@router.get("/configuration")
def list_configuration(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import SystemConfig

    rows = db.scalars(select(SystemConfig).order_by(SystemConfig.config_key))
    return [
        {
            "key": row.config_key,
            "value": row.value,
            "version": row.version,
            "active": row.is_active,
            "description": row.description,
            "updated_at": row.updated_at,
        }
        for row in rows
    ]


@router.put("/configuration/{key}")
def put_configuration(
    key: str,
    payload: ConfigUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if reauthenticated and not payload.reauthenticated:
        # The UI must explicitly acknowledge why a step-up operation is being performed.
        payload.reauthenticated = True
    config = update_config(db, key, payload, principal, context)
    db.commit()
    return {"key": config.config_key, "value": config.value, "version": config.version}


@router.put("/security")
def put_security_configuration(
    payload: SecurityConfigUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    updated = {}
    from app.models import SystemConfig

    for key, value in payload.values.items():
        config = db.scalar(select(SystemConfig).where(SystemConfig.config_key == key))
        if config is None or not key.startswith("security."):
            raise DomainError("Only registered security configuration keys can be changed here", code="invalid_configuration")
        if config.version != payload.expected_version:
            from app.core.errors import ConflictError

            raise ConflictError()
        from app.services.admin import validate_config_value

        old = config.value
        config.value = validate_config_value(key, value)
        config.version += 1
        config.changed_by_id = principal.user.id
        updated[key] = config.value
        record_audit(db, context, action="admin.security_configuration_updated", object_type="system_config", object_id=key, old_value={"value": old}, new_value={"value": value, "reason": payload.reason})
    db.commit()
    return {"updated": updated}


@router.get("/categories")
def list_categories(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import ExceptionCategory

    return [
        {
            "id": str(category.id),
            "code": category.code,
            "name": category.name,
            "description": category.description,
            "default_duration_days": category.default_duration_days,
            "maximum_duration_days": category.maximum_duration_days,
            "display_order": category.display_order,
            "active": category.is_active,
            "system": category.is_system,
            "version": category.version,
        }
        for category in db.scalars(select(ExceptionCategory).order_by(ExceptionCategory.display_order))
    ]


@router.post("/categories", status_code=201)
def post_category(
    payload: CategoryCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    category = create_category(db, payload, principal, context)
    db.commit()
    return {"id": str(category.id), "code": category.code, "name": category.name, "version": category.version}


@router.patch("/categories/{category_id}")
def patch_category(
    category_id: str,
    payload: CategoryUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    category = update_category(db, uuid.UUID(category_id), payload, principal, context)
    db.commit()
    return {"id": str(category.id), "version": category.version, "active": category.is_active}


@router.get("/fields")
def list_fields(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import RequestFieldDefinition

    return [
        {
            "id": str(field.id),
            "key": field.field_key,
            "label": field.label,
            "description": field.description,
            "data_type": field.data_type,
            "required": field.is_required,
            "default_value": field.default_value,
            "placeholder": field.placeholder,
            "validation": field.validation_schema,
            "allowed_values": field.allowed_values,
            "visible_roles": field.visible_roles,
            "visible_categories": field.visible_categories,
            "editable_after_submission": field.editable_after_submission,
            "display_order": field.display_order,
            "active": field.is_active,
            "version": field.version,
        }
        for field in db.scalars(select(RequestFieldDefinition).order_by(RequestFieldDefinition.display_order))
    ]


@router.post("/fields", status_code=201)
def post_field(
    payload: FieldCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    field = create_field(db, payload, principal, context)
    db.commit()
    return {"id": str(field.id), "key": field.field_key, "version": field.version}


@router.patch("/fields/{field_id}")
def patch_field(
    field_id: str,
    payload: FieldUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    field = update_field(db, uuid.UUID(field_id), payload, context)
    db.commit()
    return {"id": str(field.id), "version": field.version, "active": field.is_active}


@router.get("/templates")
def list_request_templates(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import RequestTemplate

    templates = db.scalars(
        select(RequestTemplate).order_by(
            RequestTemplate.is_active.desc(), RequestTemplate.name.asc()
        )
    )
    return [template_to_dict(template) for template in templates]


@router.post("/templates", status_code=201)
def post_template(
    payload: RequestTemplateCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    template = create_template(db, payload, principal, context)
    db.commit()
    return template_to_dict(template)


# Keep the action route before the collection-item route.  Although the paths
# have different segment counts, declaring it first makes the intended route
# order explicit and avoids future static/dynamic route collisions.
@router.post("/templates/{template_id}/duplicate", status_code=201)
def post_template_duplicate(
    template_id: str,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    from app.models import RequestTemplate

    try:
        parsed_id = uuid.UUID(template_id)
    except (TypeError, ValueError, AttributeError):
        raise NotFoundError("Request template was not found") from None
    source = db.get(RequestTemplate, parsed_id)
    if source is None:
        raise NotFoundError("Request template was not found")
    duplicate = duplicate_template(db, source, principal, context)
    db.commit()
    return template_to_dict(duplicate)


@router.get("/templates/{template_id}")
def get_template(
    template_id: str,
    db: DbSession = Depends(get_db),
) -> dict:
    from app.models import RequestTemplate

    try:
        parsed_id = uuid.UUID(template_id)
    except (TypeError, ValueError, AttributeError):
        raise NotFoundError("Request template was not found") from None
    template = db.get(RequestTemplate, parsed_id)
    if template is None:
        raise NotFoundError("Request template was not found")
    return template_to_dict(template)


@router.patch("/templates/{template_id}")
def patch_template(
    template_id: str,
    payload: RequestTemplateUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    from app.models import RequestTemplate

    try:
        parsed_id = uuid.UUID(template_id)
    except (TypeError, ValueError, AttributeError):
        raise NotFoundError("Request template was not found") from None
    template = db.get(RequestTemplate, parsed_id)
    if template is None:
        raise NotFoundError("Request template was not found")
    update_template(db, template, payload, context)
    db.commit()
    return template_to_dict(template)


@router.delete("/templates/{template_id}", status_code=204)
def delete_template_route(
    template_id: str,
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> Response:
    from app.models import RequestTemplate

    try:
        parsed_id = uuid.UUID(template_id)
    except (TypeError, ValueError, AttributeError):
        raise NotFoundError("Request template was not found") from None
    template = db.get(RequestTemplate, parsed_id)
    if template is None:
        raise NotFoundError("Request template was not found")
    delete_template(db, template, context)
    db.commit()
    return Response(status_code=204)


@router.get("/workflows")
def list_workflows(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import ApprovalWorkflow

    workflows = db.scalars(select(ApprovalWorkflow).order_by(ApprovalWorkflow.name, ApprovalWorkflow.version.desc()))
    return [
        {
            "id": str(workflow.id),
            "name": workflow.name,
            "version": workflow.version,
            "active": workflow.is_active,
            "default": workflow.is_default,
            "category_id": str(workflow.category_id) if workflow.category_id else None,
            "exception_type": workflow.exception_type,
            "stages": [
                {
                    "id": str(stage.id),
                    "name": stage.name,
                    "key": stage.stage_key,
                    "kind": stage.kind,
                    "sequence": stage.sequence,
                    "required": stage.required,
                    "sla_business_days": stage.sla_business_days,
                    "approver_group_id": str(stage.approver_group_id) if stage.approver_group_id else None,
                    "backup_approver_id": str(stage.backup_approver_id) if stage.backup_approver_id else None,
                    "minimum_approvals": stage.minimum_approvals,
                }
                for stage in workflow.stages
            ],
        }
        for workflow in workflows
    ]


@router.post("/workflows", status_code=201)
def post_workflow(
    payload: WorkflowUpsert,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    workflow = create_workflow(db, payload, principal, context)
    db.commit()
    return {"id": str(workflow.id), "version": workflow.version, "active": workflow.is_active}


@router.get("/email-templates")
def list_email_templates(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import EmailTemplate

    return [
        {
            "id": str(template.id),
            "event_key": template.event_key,
            "name": template.name,
            "locale": template.locale,
            "version": template.version,
            "subject_template": template.subject_template,
            "body_template": template.body_template,
            "allowed_variables": template.allowed_variables,
            "active": template.is_active,
            "validation_status": template.validation_status,
        }
        for template in db.scalars(select(EmailTemplate).order_by(EmailTemplate.event_key, EmailTemplate.version.desc()))
    ]


@router.post("/email-templates", status_code=201)
def post_email_template(
    payload: EmailTemplateUpsert,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    template = upsert_email_template(db, payload, principal, context)
    db.commit()
    return {"id": str(template.id), "version": template.version, "active": template.is_active}


@router.post("/email-templates/preview")
def preview_email_template(payload: EmailPreviewRequest) -> dict:
    variables = validate_template(payload.subject_template, payload.body_template)
    values = {variable: payload.sample_values.get(variable, f"Sample {variable}") for variable in variables}
    return {"subject": render_template(payload.subject_template, values), "body": render_template(payload.body_template, values)}


@router.get("/ai")
def get_ai_configuration(request: Request, db: DbSession = Depends(get_db)) -> dict:
    return ai_configuration(db, request.app.state.settings)


@router.put("/ai")
def put_ai_configuration(
    payload: AiConfigurationUpdate,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    result = update_ai_configuration(db, payload, principal, context, request.app.state.settings)
    db.commit()
    return result


@router.post("/ai/log-analysis", status_code=202)
def post_ai_log_analysis(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    analysis = queue_log_analysis(db, principal, request.app.state.settings, context)
    db.commit()
    return {"id": str(analysis.id), "status": analysis.status, "window_hours": 24}


@router.post("/delegations", status_code=201)
def post_delegation(
    payload: DelegationCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    delegation = create_delegation(db, payload, principal, context)
    db.commit()
    return {"id": str(delegation.id), "active": delegation.is_active}


@router.get("/audit")
def list_audit_events(
    action: str | None = None,
    actor_id: str | None = None,
    object_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    db: DbSession = Depends(get_db),
) -> dict:
    from app.models import AuditEvent

    query = select(AuditEvent)
    if action:
        query = query.where(AuditEvent.action == action)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)
    if object_id:
        query = query.where(AuditEvent.object_id == object_id)
    if start:
        query = query.where(AuditEvent.occurred_at >= start)
    if end:
        query = query.where(AuditEvent.occurred_at < end)
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    events = list(db.scalars(query.order_by(AuditEvent.occurred_at.desc()).offset((page - 1) * page_size).limit(page_size)))
    return {
        "items": [
            {
                "id": str(event.id),
                "timestamp": event.occurred_at,
                "actor_id": event.actor_id,
                "actor": event.actor_label,
                "source_ip": event.source_ip,
                "action": event.action,
                "object_type": event.object_type,
                "object_id": event.object_id,
                "result": event.result,
                "failure_reason": event.failure_reason,
                "correlation_id": event.correlation_id,
                "event_hash": event.event_hash,
            }
            for event in events
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    }


@router.post("/audit/export")
def export_audit_events(
    payload: AuditExportCreate,
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    principal: Principal = Depends(get_current_principal),
) -> StreamingResponse:
    from app.models import AuditEvent

    if payload.end_date < payload.start_date:
        raise DomainError("Export end date must not precede start date", code="invalid_export_range")
    events = list(
        db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.occurred_at >= datetime.combine(payload.start_date, datetime.min.time(), tzinfo=UTC),
                AuditEvent.occurred_at < datetime.combine(payload.end_date + timedelta(days=1), datetime.min.time(), tzinfo=UTC),
            )
            .order_by(AuditEvent.occurred_at.asc())
            .limit(100_000)
        )
    )
    record_audit(db, context, action="admin.audit_exported", object_type="audit_export", object_id=context.correlation_id, new_value={"start_date": payload.start_date.isoformat(), "end_date": payload.end_date.isoformat(), "format": payload.format, "row_count": len(events), "reason": payload.reason})
    db.commit()
    output = io.StringIO()
    if payload.format == "csv":
        writer = csv.writer(output)
        writer.writerow(["timestamp", "actor", "action", "object_type", "object_id", "result", "correlation_id", "event_hash"])
        for event in events:
            writer.writerow([event.occurred_at.isoformat(), event.actor_label, event.action, event.object_type, event.object_id, event.result, event.correlation_id, event.event_hash])
        media_type = "text/csv"
    else:
        for event in events:
            output.write(json.dumps({"id": str(event.id), "timestamp": event.occurred_at.isoformat(), "actor_id": event.actor_id, "action": event.action, "object_type": event.object_type, "object_id": event.object_id, "result": event.result, "correlation_id": event.correlation_id, "event_hash": event.event_hash}, default=str) + "\n")
        media_type = "application/x-ndjson"
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type=media_type, headers={"Content-Disposition": f'attachment; filename="audit-export-{datetime.now(UTC):%Y%m%d}"', "Cache-Control": "no-store"})


@router.post("/backups", status_code=202)
def post_backup(
    payload: BackupCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    record = create_backup_record(db, principal.user.id, context.correlation_id)
    record_audit(db, context, action="admin.backup_requested", object_type="backup", object_id=str(record.id), new_value={"reason": payload.reason})
    enqueue_job(db, "database_backup", {"backup_id": str(record.id)}, deduplication_key=f"backup:{record.id}", correlation_id=context.correlation_id, priority=10)
    db.commit()
    return {"id": str(record.id), "status": record.status}


@router.get("/backups")
def list_backups(db: DbSession = Depends(get_db)) -> list[dict]:
    from app.models import BackupRecord

    return [
        {
            "id": str(record.id),
            "type": record.backup_type,
            "status": record.status,
            "file_name": record.file_name,
            "size_bytes": record.size_bytes,
            "sha256": record.sha256,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "verification_status": record.verification_status,
        }
        for record in db.scalars(select(BackupRecord).order_by(BackupRecord.created_at.desc()).limit(100))
    ]


@router.post("/retention/run", status_code=202)
def post_retention_run(
    payload: RetentionRun,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
    reauthenticated: bool = Depends(require_reauthentication),
) -> dict:
    if not payload.reauthenticated or not reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required")
    job = enqueue_job(db, "audit_retention", {"reason": payload.reason}, deduplication_key=f"retention-manual:{context.correlation_id}", correlation_id=context.correlation_id)
    record_audit(db, context, action="admin.audit_retention_requested", object_type="background_job", object_id=str(job.id), new_value={"reason": payload.reason})
    db.commit()
    return {"job_id": str(job.id), "status": job.status}
