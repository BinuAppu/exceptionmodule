from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import AuthorizationError, ConflictError, DomainError, NotFoundError
from app.core.security import encrypt_secret
from app.models import (
    ApprovalWorkflow,
    ApproverGroup,
    ApproverGroupMember,
    EmailTemplate,
    ExceptionCategory,
    RequestFieldDefinition,
    RequestTemplate,
    RiskLevel,
    Role,
    SecretRecord,
    SystemConfig,
    User,
    UserRole,
    WorkflowStage,
)
from app.schemas.admin import (
    AiConfigurationUpdate,
    CategoryCreate,
    CategoryUpdate,
    ConfigUpdate,
    DelegationCreate,
    EmailTemplateUpsert,
    FieldCreate,
    FieldUpdate,
    RequestTemplateCreate,
    RequestTemplateUpdate,
    UserAdminUpdate,
    WorkflowUpsert,
)
from app.schemas.common import AuditContext
from app.services.ai import ai_configuration
from app.services.audit import record_audit
from app.services.authorization import resolve_model_id
from app.services.authz import Principal
from app.services.email import validate_template
from app.services.outbox import enqueue_job

CONFIG_VALIDATORS: dict[str, tuple[type, int, int]] = {
    "exception.default_duration_days": (int, 1, 3650),
    "exception.minimum_duration_days": (int, 1, 3650),
    "exception.maximum_duration_days": (int, 1, 3650),
    "exception.maximum_extension_days": (int, 1, 3650),
    "exception.maximum_extensions": (int, 0, 20),
    "audit.retention_days": (int, 90, 3650),
    "security.session_idle_minutes": (int, 5, 480),
    "security.session_absolute_minutes": (int, 15, 1440),
    "security.login_failure_threshold": (int, 3, 20),
    "security.login_lockout_minutes": (int, 1, 1440),
    "attachment.max_bytes": (int, 1_048_576, 104_857_600),
}

HIGH_IMPACT_CONFIG_KEYS = {
    "exception.default_duration_days",
    "exception.maximum_duration_days",
    "exception.maximum_extensions",
    "audit.retention_days",
    "security.session_idle_minutes",
    "security.session_absolute_minutes",
    "security.login_failure_threshold",
    "attachment.max_bytes",
    "ai.configuration",
}


def validate_config_value(key: str, value: Any) -> Any:
    if key in CONFIG_VALIDATORS:
        expected, minimum, maximum = CONFIG_VALIDATORS[key]
        if isinstance(value, bool) or not isinstance(value, expected):
            raise DomainError(f"Configuration '{key}' has an invalid type", code="invalid_configuration")
        if not minimum <= value <= maximum:
            raise DomainError(f"Configuration '{key}' is out of range", code="invalid_configuration")
    elif key == "notification.expiration_reminders":
        if not isinstance(value, list) or any(isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 365 for item in value):
            raise DomainError("Expiration reminders must be a list of 1–365 day values", code="invalid_configuration")
    elif key == "business.timezone":
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        try:
            ZoneInfo(str(value))
        except ZoneInfoNotFoundError as exc:
            raise DomainError("Business timezone is invalid", code="invalid_configuration") from exc
    elif key == "attachment.allowed_extensions":
        if not isinstance(value, list) or any(not isinstance(item, str) or not item.replace("-", "").isalnum() for item in value):
            raise DomainError("Allowed extensions are invalid", code="invalid_configuration")
    elif key == "risk.weights":
        if not isinstance(value, dict) or any(isinstance(item, bool) or not isinstance(item, (int, float)) or not 0 <= item <= 100 for item in value.values()):
            raise DomainError("Risk weights must be numeric values from 0 to 100", code="invalid_configuration")
    return value


def update_config(
    db: DbSession,
    key: str,
    payload: ConfigUpdate,
    principal: Principal,
    context: AuditContext,
) -> SystemConfig:
    config = db.scalar(select(SystemConfig).where(SystemConfig.config_key == key))
    if config is None:
        raise NotFoundError("Configuration key was not found")
    if config.version != payload.expected_version:
        raise ConflictError()
    if key in HIGH_IMPACT_CONFIG_KEYS and not payload.reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required for this configuration change")
    new_value = validate_config_value(key, payload.value)
    old = config.value
    config.value = new_value
    config.version += 1
    config.changed_by_id = principal.user.id
    record_audit(
        db,
        context,
        action="admin.configuration_updated",
        object_type="system_config",
        object_id=key,
        old_value={"value": old, "version": payload.expected_version},
        new_value={"value": new_value, "version": config.version, "reason": payload.reason},
    )
    return config


def update_user(
    db: DbSession,
    user_id: uuid.UUID,
    payload: UserAdminUpdate,
    principal: Principal,
    settings: Settings,
    context: AuditContext,
    *,
    reauthenticated: bool,
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User was not found")
    if user.version != payload.expected_version:
        raise ConflictError()
    if user.is_break_glass and payload.status == "disabled" and not settings.oidc_enabled:
        raise DomainError("Break-glass access cannot be disabled until enterprise SSO is verified", code="break_glass_required")
    if user.id == principal.user.id and payload.roles is not None and "admin" not in payload.roles:
        raise DomainError("Administrators cannot remove their own administrator role", code="self_escalation_guard")
    old = {
        "display_name": user.display_name,
        "department": user.department,
        "job_title": user.job_title,
        "manager_id": str(user.manager_id) if user.manager_id else None,
        "status": user.status,
        "roles": sorted(role.role.code for role in user.user_roles),
    }
    for field in ("display_name", "department", "job_title", "status"):
        value = getattr(payload, field)
        if value is not None:
            setattr(user, field, value)
    if "manager_id" in payload.model_fields_set:
        user.manager_id = resolve_model_id(db, User, payload.manager_id) if payload.manager_id else None
        if user.manager_id == user.id:
            raise DomainError("A user cannot manage themselves", code="invalid_manager")
    if payload.roles is not None:
        if not reauthenticated:
            raise AuthorizationError("Step-up re-authentication is required for role changes")
        roles = list(db.scalars(select(Role).where(Role.code.in_(payload.roles), Role.is_active.is_(True))))
        if len(roles) != len(set(payload.roles)):
            raise DomainError("One or more roles are invalid", code="invalid_role")
        if user.is_break_glass and set(payload.roles) != {"admin"}:
            raise DomainError("The break-glass identity must retain only the administrator role", code="break_glass_role_guard")
        db.execute(UserRole.__table__.delete().where(UserRole.user_id == user.id))
        for role in roles:
            db.add(UserRole(user_id=user.id, role_id=role.id, assigned_by_id=principal.user.id))
        db.flush()
        if "admin" in payload.roles:
            admin_users = int(
                db.scalar(
                    select(func.count(func.distinct(UserRole.user_id)))
                    .join(Role, Role.id == UserRole.role_id)
                    .where(Role.code == "admin")
                )
                or 0
            )
            # Existing admins + newly promoted users; a value of one is only safe when this is that user.
            if admin_users < 1:
                raise DomainError("At least one active administrator is required", code="last_admin_guard")
    if payload.status == "disabled":
        user.disabled_at = datetime.now(UTC)
        from app.models import Session

        for session in db.scalars(select(Session).where(Session.user_id == user.id, Session.revoked_at.is_(None))):
            session.revoked_at = datetime.now(UTC)
            session.revoked_reason = "administrator_disabled_user"
    elif payload.status == "active":
        user.disabled_at = None
    user.version += 1
    new = {
        "display_name": user.display_name,
        "department": user.department,
        "job_title": user.job_title,
        "manager_id": str(user.manager_id) if user.manager_id else None,
        "status": user.status,
        "roles": sorted(payload.roles) if payload.roles is not None else old["roles"],
    }
    record_audit(
        db,
        context,
        action="admin.user_updated",
        object_type="user",
        object_id=user.public_id,
        old_value=old,
        new_value={**new, "reason": payload.reason},
    )
    return user


def create_category(db: DbSession, payload: CategoryCreate, principal: Principal, context: AuditContext) -> ExceptionCategory:
    category = ExceptionCategory(
        code=payload.code,
        name=payload.name,
        description=payload.description,
        parent_id=resolve_model_id(db, ExceptionCategory, payload.parent_id) if payload.parent_id else None,
        default_duration_days=payload.default_duration_days,
        maximum_duration_days=payload.maximum_duration_days,
        risk_level_id=resolve_model_id(db, RiskLevel, payload.risk_level_id) if payload.risk_level_id else None,
        display_order=payload.display_order,
    )
    db.add(category)
    db.flush()
    record_audit(db, context, action="admin.category_created", object_type="exception_category", object_id=category.code, new_value={"name": category.name, "active": True})
    return category


def update_category(
    db: DbSession,
    category_id: uuid.UUID,
    payload: CategoryUpdate,
    principal: Principal,
    context: AuditContext,
) -> ExceptionCategory:
    category = db.get(ExceptionCategory, category_id)
    if category is None:
        raise NotFoundError("Category was not found")
    if category.version != payload.expected_version:
        raise ConflictError()
    old = {"name": category.name, "active": category.is_active, "default_days": category.default_duration_days, "maximum_days": category.maximum_duration_days}
    for field in ("name", "description", "default_duration_days", "maximum_duration_days", "is_active"):
        value = getattr(payload, field)
        if value is not None:
            setattr(category, field, value)
    if category.default_duration_days and category.maximum_duration_days and category.default_duration_days > category.maximum_duration_days:
        raise DomainError("Default duration cannot exceed category maximum", code="invalid_category")
    category.version += 1
    record_audit(db, context, action="admin.category_updated", object_type="exception_category", object_id=category.code, old_value=old, new_value={"name": category.name, "active": category.is_active, "default_days": category.default_duration_days, "maximum_days": category.maximum_duration_days, "reason": payload.reason})
    return category


def create_field(db: DbSession, payload: FieldCreate, principal: Principal, context: AuditContext) -> RequestFieldDefinition:
    definition = RequestFieldDefinition(
        field_key=payload.field_key,
        label=payload.label,
        description=payload.description,
        data_type=payload.data_type,
        is_required=payload.is_required,
        default_value=payload.default_value,
        placeholder=payload.placeholder,
        validation_schema=payload.validation_schema,
        allowed_values=payload.allowed_values,
        visible_roles=payload.visible_roles,
        visible_categories=payload.visible_categories,
        editable_after_submission=payload.editable_after_submission,
        display_order=payload.display_order,
    )
    db.add(definition)
    db.flush()
    record_audit(db, context, action="admin.field_created", object_type="request_field", object_id=definition.field_key, new_value={"label": definition.label, "type": definition.data_type})
    return definition


def update_field(db: DbSession, field_id: uuid.UUID, payload: FieldUpdate, context: AuditContext) -> RequestFieldDefinition:
    definition = db.get(RequestFieldDefinition, field_id)
    if definition is None:
        raise NotFoundError("Field was not found")
    if definition.is_system:
        raise DomainError("System fields cannot be modified", code="system_field_protected")
    if definition.version != payload.expected_version:
        raise ConflictError()
    old = {"label": definition.label, "required": definition.is_required, "active": definition.is_active, "order": definition.display_order}
    for field in ("label", "description", "is_required", "default_value", "placeholder", "validation_schema", "allowed_values", "visible_roles", "visible_categories", "editable_after_submission", "display_order", "is_active"):
        value = getattr(payload, field)
        if value is not None:
            setattr(definition, field, value)
    definition.version += 1
    record_audit(db, context, action="admin.field_updated", object_type="request_field", object_id=definition.field_key, old_value=old, new_value={"label": definition.label, "required": definition.is_required, "active": definition.is_active, "order": definition.display_order, "reason": payload.reason})
    return definition


def _template_category_id(db: DbSession, value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        category_id = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError):
        category = db.scalar(select(ExceptionCategory).where(ExceptionCategory.code == value))
    else:
        category = db.get(ExceptionCategory, category_id)
    if category is None:
        raise NotFoundError("Category was not found")
    if not category.is_active:
        raise DomainError("Templates may only target an active category", code="category_inactive")
    return category.id


def template_to_dict(template: RequestTemplate) -> dict[str, Any]:
    """Serialize the public template contract in one place."""

    return {
        "id": str(template.id),
        "name": template.name,
        "description": template.description,
        "category_id": str(template.category_id) if template.category_id else None,
        "is_active": template.is_active,
        "default_values": template.default_values or {},
        "version": template.version,
        "created_at": template.created_at,
        "updated_at": template.updated_at,
    }


def create_template(
    db: DbSession,
    payload: RequestTemplateCreate,
    principal: Principal,
    context: AuditContext,
) -> RequestTemplate:
    name = payload.name.strip()
    if len(name) < 2:
        raise DomainError(
            "Template name must contain at least two characters", code="invalid_template"
        )
    template = RequestTemplate(
        name=name,
        description=payload.description.strip() if payload.description else None,
        category_id=_template_category_id(db, payload.category_id),
        default_values=deepcopy(payload.default_values),
        is_active=payload.is_active,
        created_by_id=principal.user.id,
    )
    db.add(template)
    db.flush()
    record_audit(
        db,
        context,
        action="admin.request_template_created",
        object_type="request_template",
        object_id=str(template.id),
        new_value={
            "name": template.name,
            "category_id": str(template.category_id) if template.category_id else None,
            "active": template.is_active,
            "default_value_keys": sorted(template.default_values or {}),
        },
    )
    return template


def update_template(
    db: DbSession,
    template: RequestTemplate,
    payload: RequestTemplateUpdate,
    context: AuditContext,
) -> RequestTemplate:
    if payload.expected_version is not None and template.version != payload.expected_version:
        raise ConflictError()
    old = {
        "name": template.name,
        "description": template.description,
        "category_id": str(template.category_id) if template.category_id else None,
        "active": template.is_active,
        "default_value_keys": sorted(template.default_values or {}),
    }
    fields_set = payload.model_fields_set
    if "name" in fields_set and payload.name is not None:
        name = payload.name.strip()
        if len(name) < 2:
            raise DomainError(
            "Template name must contain at least two characters", code="invalid_template"
        )
        template.name = name
    if "description" in fields_set:
        template.description = payload.description.strip() if payload.description else None
    if "category_id" in fields_set:
        template.category_id = _template_category_id(db, payload.category_id)
    if "is_active" in fields_set and payload.is_active is not None:
        template.is_active = payload.is_active
    if "default_values" in fields_set and payload.default_values is not None:
        template.default_values = deepcopy(payload.default_values)
    template.version += 1
    record_audit(
        db,
        context,
        action="admin.request_template_updated",
        object_type="request_template",
        object_id=str(template.id),
        old_value=old,
        new_value={
            "name": template.name,
            "category_id": str(template.category_id) if template.category_id else None,
            "active": template.is_active,
            "default_value_keys": sorted(template.default_values or {}),
        },
    )
    return template


def duplicate_template(
    db: DbSession,
    source: RequestTemplate,
    principal: Principal,
    context: AuditContext,
) -> RequestTemplate:
    base_name = f"{source.name} (Copy)"[:160]
    candidate = base_name
    suffix = 2
    while db.scalar(select(RequestTemplate.id).where(RequestTemplate.name == candidate)):
        suffix_text = f" (Copy {suffix})"
        candidate = f"{source.name[: 160 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    duplicate = RequestTemplate(
        name=candidate,
        description=source.description,
        category_id=source.category_id,
        default_values=deepcopy(source.default_values or {}),
        is_active=source.is_active,
        created_by_id=principal.user.id,
    )
    db.add(duplicate)
    db.flush()
    record_audit(
        db,
        context,
        action="admin.request_template_duplicated",
        object_type="request_template",
        object_id=str(duplicate.id),
        new_value={
            "source_template_id": str(source.id),
            "name": duplicate.name,
            "category_id": str(duplicate.category_id) if duplicate.category_id else None,
            "active": duplicate.is_active,
        },
    )
    return duplicate


def delete_template(db: DbSession, template: RequestTemplate, context: AuditContext) -> None:
    old = {
        "name": template.name,
        "category_id": str(template.category_id) if template.category_id else None,
        "active": template.is_active,
    }
    template_id = str(template.id)
    db.delete(template)
    db.flush()
    record_audit(
        db,
        context,
        action="admin.request_template_deleted",
        object_type="request_template",
        object_id=template_id,
        old_value=old,
        new_value={"deleted": True},
    )


def upsert_email_template(
    db: DbSession, payload: EmailTemplateUpsert, principal: Principal, context: AuditContext
) -> EmailTemplate:
    variables = validate_template(payload.subject_template, payload.body_template, payload.allowed_variables)
    latest = db.scalar(
        select(EmailTemplate)
        .where(EmailTemplate.event_key == payload.event_key, EmailTemplate.locale == payload.locale)
        .order_by(EmailTemplate.version.desc())
    )
    template = EmailTemplate(
        event_key=payload.event_key,
        name=payload.name,
        locale=payload.locale,
        version=(latest.version + 1) if latest else 1,
        subject_template=payload.subject_template,
        body_template=payload.body_template,
        allowed_variables=sorted(variables),
        is_active=payload.activate,
        validation_status="valid",
        validated_at=datetime.now(UTC),
        created_by_id=principal.user.id,
    )
    db.add(template)
    if payload.activate:
        db.execute(
            EmailTemplate.__table__.update()
            .where(
                EmailTemplate.event_key == payload.event_key,
                EmailTemplate.locale == payload.locale,
                EmailTemplate.id != template.id,
            )
            .values(is_active=False)
        )
    db.flush()
    record_audit(db, context, action="admin.email_template_saved", object_type="email_template", object_id=f"{payload.event_key}:{payload.locale}:v{template.version}", new_value={"active": template.is_active, "variables": sorted(variables), "reason": payload.reason})
    return template


def create_workflow(
    db: DbSession, payload: WorkflowUpsert, principal: Principal, context: AuditContext
) -> ApprovalWorkflow:
    previous = db.scalar(
        select(ApprovalWorkflow).where(
            ApprovalWorkflow.name == payload.name,
            ApprovalWorkflow.is_active.is_(True),
        ).order_by(ApprovalWorkflow.version.desc())
    )
    workflow = ApprovalWorkflow(
        name=payload.name,
        version=(previous.version + 1) if previous else 1,
        category_id=resolve_model_id(db, ExceptionCategory, payload.category_id) if payload.category_id else None,
        exception_type=payload.exception_type,
        risk_level_id=resolve_model_id(db, RiskLevel, payload.risk_level_id) if payload.risk_level_id else None,
        is_default=payload.is_default,
        is_active=payload.activate,
        created_by_id=principal.user.id,
    )
    db.add(workflow)
    db.flush()
    for item in payload.stages:
        db.add(
            WorkflowStage(
                workflow_id=workflow.id,
                name=item.name,
                stage_key=item.stage_key,
                kind=item.kind,
                sequence=item.sequence,
                required=item.required,
                sla_business_days=item.sla_business_days,
                approver_group_id=resolve_model_id(db, ApproverGroup, item.approver_group_id) if item.approver_group_id else None,
                backup_approver_id=resolve_model_id(db, User, item.backup_approver_id) if item.backup_approver_id else None,
                minimum_approvals=item.minimum_approvals,
                maximum_approvals=item.maximum_approvals,
                settings=item.settings,
            )
        )
    if payload.activate and previous:
        previous.is_active = False
    record_audit(db, context, action="admin.workflow_published" if payload.activate else "admin.workflow_drafted", object_type="approval_workflow", object_id=str(workflow.id), new_value={"name": workflow.name, "version": workflow.version, "stage_count": len(payload.stages), "active": workflow.is_active, "reason": payload.reason})
    return workflow


def update_ai_configuration(
    db: DbSession, payload: AiConfigurationUpdate, principal: Principal, context: AuditContext, settings: Settings
) -> dict[str, Any]:
    current = db.scalar(
        select(SystemConfig).where(SystemConfig.config_key == "ai.configuration", SystemConfig.is_active.is_(True))
    )
    if current is None:
        raise NotFoundError("AI configuration was not found")
    if current.value.get("version", 1) != payload.expected_version:
        raise ConflictError()
    if not payload.reauthenticated:
        raise AuthorizationError("Step-up re-authentication is required for AI configuration changes")
    if payload.endpoint:
        from app.services.ai import _validate_endpoint

        _validate_endpoint(payload.endpoint, settings)
    value = {
        **current.value,
        "version": current.value.get("version", 1) + 1,
        "enabled": payload.enabled,
        "endpoint": payload.endpoint,
        "api_version": payload.api_version,
        "deployment": payload.deployment,
        "auth_mode": payload.auth_mode,
        "timeout_seconds": payload.timeout_seconds,
        "token_limit": payload.token_limit,
        "features": payload.features,
    }
    current.value = value
    current.version += 1
    current.changed_by_id = principal.user.id
    if payload.api_key:
        secret = db.scalar(select(SecretRecord).where(SecretRecord.name == "azure_openai_api_key"))
        if secret is None:
            secret = SecretRecord(name="azure_openai_api_key")
            db.add(secret)
        secret.encrypted_value = encrypt_secret(payload.api_key, settings)
        secret.provider = "database_encrypted"
        secret.changed_by_id = principal.user.id
        secret.is_active = True
        secret.rotated_at = datetime.now(UTC)
    record_audit(db, context, action="admin.ai_configuration_updated", object_type="ai_configuration", object_id="azure_openai", new_value={"enabled": payload.enabled, "endpoint": payload.endpoint, "deployment": payload.deployment, "auth_mode": payload.auth_mode, "features": payload.features, "secret_updated": bool(payload.api_key), "reason": payload.reason})
    return ai_configuration(db, settings)


def create_delegation(
    db: DbSession, payload: DelegationCreate, principal: Principal, context: AuditContext
):
    from app.models import Delegation

    delegator_id = resolve_model_id(db, User, payload.delegator_id)
    delegate_id = resolve_model_id(db, User, payload.delegate_id)
    now = datetime.now(UTC)
    if payload.start_at < now - timedelta(minutes=5):
        raise DomainError("Delegation cannot start in the past", code="invalid_delegation")
    delegation = Delegation(
        delegator_id=delegator_id,
        delegate_id=delegate_id,
        start_at=payload.start_at,
        end_at=payload.end_at,
        reason=payload.reason,
        scope_type=payload.scope_type,
        scope_value=payload.scope_value,
        created_by_id=principal.user.id,
    )
    db.add(delegation)
    db.flush()
    record_audit(db, context, action="admin.delegation_created", object_type="delegation", object_id=str(delegation.id), new_value={"delegator_id": str(delegator_id), "delegate_id": str(delegate_id), "start_at": payload.start_at.isoformat(), "end_at": payload.end_at.isoformat(), "scope": [payload.scope_type, payload.scope_value], "reason": payload.reason})
    return delegation
