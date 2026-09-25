from __future__ import annotations

import argparse
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import inspect, select

from app.core.config import get_settings
from app.core.security import hash_password, hash_token
from app.db.session import SessionLocal
from app.models import (
    ApprovalWorkflow,
    ApproverGroup,
    DataClassification,
    EmailTemplate,
    ExceptionCategory,
    ExceptionRequest,
    LocalRecoveryCode,
    Permission,
    RequestFieldDefinition,
    RequestTemplate,
    RiskLevel,
    Role,
    RolePermission,
    StageKind,
    SystemConfig,
    User,
    UserRole,
    WorkflowStage,
)

PERMISSIONS = {
    "user": [
        ("request.create", "Create and draft exception requests"),
        ("request.read_own", "Read owned exception requests"),
        ("request.edit_own", "Edit owned drafts"),
        ("request.submit", "Submit owned exception requests"),
        ("request.comment", "Comment on authorized requests"),
        ("attachment.upload", "Upload evidence to authorized requests"),
        ("attachment.download", "Download authorized clean attachments"),
        ("request.extend", "Request an extension for an owned exception"),
        ("request.remediate", "Update owned remediation plans"),
        ("request.close", "Close owned exceptions"),
    ],
    "approver": [
        ("approval.read", "Read assigned approval requests"),
        ("approval.decide", "Approve, reject, or request clarification"),
        ("approval.link", "Use authenticated approval action links"),
        ("ai.use", "Request advisory AI analysis"),
        ("request.read_assigned", "Read requests assigned for approval"),
        ("report.read_assigned", "Read reports limited to assigned records"),
    ],
    "admin": [
        ("*", "All system administration and data access"),
        ("sso.configuration.read", "Read sanitized runtime SSO configuration"),
        ("sso.configuration.write", "Create or rotate runtime SSO configuration"),
        ("sso.configuration.validate", "Validate runtime SSO settings without persisting them"),
    ],
}

CATEGORIES = [
    ("security_policy", "Security Policy Exception"),
    ("technology_standard", "Technology Standard Exception"),
    ("vulnerability_remediation", "Vulnerability Remediation Exception"),
    ("network", "Network Exception"),
    ("firewall", "Firewall Exception"),
    ("cloud_security", "Cloud Security Exception"),
    ("identity_access", "Identity/Access Exception"),
    ("data_protection", "Data Protection Exception"),
    ("encryption", "Encryption Exception"),
    ("logging_monitoring", "Logging/Monitoring Exception"),
    ("endpoint_security", "Endpoint Security Exception"),
    ("application_security", "Application Security Exception"),
    ("infrastructure", "Infrastructure Exception"),
    ("third_party_vendor", "Third-Party/Vendor Exception"),
    ("compliance", "Compliance Exception"),
    ("other", "Other"),
]

CONFIG_DEFAULTS = {
    "exception.default_duration_days": 90,
    "exception.minimum_duration_days": 1,
    "exception.maximum_duration_days": 365,
    "exception.maximum_extension_days": 90,
    "exception.maximum_extensions": 2,
    "notification.expiration_reminders": [30, 14, 7, 3, 1],
    "sla.manager_business_days": 3,
    "sla.delivery_business_days": 2,
    "sla.approver_business_days": 3,
    "audit.retention_days": 1095,
    "security.session_idle_minutes": 30,
    "security.session_absolute_minutes": 480,
    "security.login_failure_threshold": 5,
    "security.login_lockout_minutes": 15,
    "attachment.max_bytes": 10_485_760,
    "attachment.allowed_extensions": ["pdf", "jpg", "jpeg", "png", "txt", "eml"],
    "business.timezone": "UTC",
    "ai.configuration": {
        "enabled": False,
        "features": {
            "request_summary": True,
            "similar_exceptions": True,
            "risk_assessment": True,
            "log_analysis": False,
        },
        "send_restricted_data": False,
    },
    "risk.weights": {
        "data_sensitivity": 20,
        "production_environment": 15,
        "internet_exposure": 20,
        "privilege_impact": 15,
        "regulatory_impact": 15,
        "long_duration": 10,
        "weak_compensating_controls": 15,
        "asset_criticality": 15,
    },
}

TEMPLATES = [
    ("request_submitted", "Request submitted", "Submitted: {{request_id}}", "Your request {{request_id}} was submitted. Sign in to track its status."),
    ("manager_approval_required", "Manager approval required", "Approval required: {{request_id}}", "Hello {{approver_name}}, request {{request_id}} requires your decision. Review it securely: {{approval_url}}"),
    ("manager_approved", "Manager approved", "Manager approved: {{request_id}}", "The manager approved {{request_id}}."),
    ("manager_rejected", "Manager rejected", "Manager rejected: {{request_id}}", "The manager rejected {{request_id}}."),
    ("delivery_head_approval_required", "Delivery Head approval required", "Delivery approval required: {{request_id}}", "Request {{request_id}} requires Delivery Head approval."),
    ("approver_review_required", "Approver review required", "Security review required: {{request_id}}", "Request {{request_id}} requires exception review."),
    ("clarification_required", "Clarification required", "Clarification requested: {{request_id}}", "More information is required for {{request_id}}."),
    ("request_approved", "Request approved", "Exception approved: {{request_id}}", "Exception {{request_id}} was approved."),
    ("request_rejected", "Request rejected", "Exception rejected: {{request_id}}", "Exception {{request_id}} was rejected."),
    ("exception_activated", "Exception activated", "Exception active: {{request_id}}", "Exception {{request_id}} is active until {{expiry_date}}."),
    ("exception_expiring", "Exception nearing expiration", "Exception expires soon: {{request_id}}", "Exception {{request_id}} expires on {{expiry_date}}."),
    ("exception_expired", "Exception expired", "Exception expired: {{request_id}}", "Exception {{request_id}} has expired."),
    ("extension_requested", "Extension requested", "Extension approval required: {{request_id}}", "Extension request {{request_id}} requires approval."),
    ("extension_approved", "Extension approved", "Extension approved: {{request_id}}", "The extension for {{request_id}} was approved."),
    ("extension_rejected", "Extension rejected", "Extension rejected: {{request_id}}", "The extension for {{request_id}} was rejected."),
    ("sla_breached", "SLA breached", "Approval overdue: {{request_id}}", "Approval for {{request_id}} is overdue."),
    ("escalation", "Escalation", "Approval escalated: {{request_id}}", "Approval for {{request_id}} was escalated."),
    ("system_security_notification", "System/security notification", "Security notification: {{request_id}}", "{{notification_message}}"),
]

# Starter request templates are configuration, not policy shortcuts.  They are
# deliberately generic and can be edited or deactivated by an administrator.
REQUEST_TEMPLATES = [
    (
        "Standard exception request",
        "A neutral starting point for a routine technology exception.",
        None,
        {"data_classification_code": "Internal"},
    ),
    (
        "Security policy exception",
        "Starting defaults for a security policy exception review.",
        "security_policy",
        {"data_classification_code": "Confidential"},
    ),
]


def _role(db, code: str, name: str, description: str) -> Role:
    role = db.scalar(select(Role).where(Role.code == code))
    if role is None:
        role = Role(code=code, name=name, description=description)
        db.add(role)
        db.flush()
    return role


def seed_reference_data() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        if not inspect(db.get_bind()).has_table("roles"):
            raise RuntimeError("Database migrations have not been applied. Run Alembic before seeding.")
        roles = {
            code: _role(db, code, code.title(), description)
            for code, description in [
                ("user", "Employee who requests and manages owned exceptions"),
                ("approver", "Human reviewer assigned through approval workflows"),
                ("admin", "Enterprise application administrator"),
            ]
        }
        for role_code, permissions in PERMISSIONS.items():
            for code, description in permissions:
                permission = db.scalar(select(Permission).where(Permission.code == code))
                if permission is None:
                    permission = Permission(code=code, description=description)
                    db.add(permission)
                    db.flush()
                if not db.scalar(
                    select(RolePermission).where(
                        RolePermission.role_id == roles[role_code].id,
                        RolePermission.permission_id == permission.id,
                    )
                ):
                    db.add(RolePermission(role_id=roles[role_code].id, permission_id=permission.id))

        for code, name, score, color, description in [
            ("low", "Low", 10, "#188038", "Limited business/security impact with strong controls"),
            ("medium", "Medium", 40, "#b06000", "Material impact requiring managed compensating controls"),
            ("high", "High", 70, "#c5221f", "Significant security, business, or regulatory exposure"),
            ("critical", "Critical", 90, "#a50e0e", "Exceptional impact requiring executive/security attention"),
        ]:
            if db.scalar(select(RiskLevel).where(RiskLevel.code == code)) is None:
                db.add(
                    RiskLevel(
                        code=code,
                        name=name,
                        score=score,
                        color=color,
                        description=description,
                        display_order={"low": 1, "medium": 2, "high": 3, "critical": 4}[code],
                    )
                )
        db.flush()
        for code, name, rank, allow_ai, allow_export in [
            ("Public", "Public", 0, True, True),
            ("Internal", "Internal", 1, True, True),
            ("Confidential", "Confidential", 2, True, False),
            ("Restricted", "Restricted", 3, False, False),
            ("Highly Restricted", "Highly Restricted", 4, False, False),
        ]:
            if db.scalar(select(DataClassification).where(DataClassification.code == code)) is None:
                db.add(
                    DataClassification(
                        code=code,
                        name=name,
                        rank=rank,
                        allow_ai=allow_ai,
                        allow_export=allow_export,
                    )
                )
        medium_risk = db.scalar(select(RiskLevel).where(RiskLevel.code == "medium"))
        for order, (code, name) in enumerate(CATEGORIES, start=1):
            category = db.scalar(select(ExceptionCategory).where(ExceptionCategory.code == code))
            if category is None:
                db.add(
                    ExceptionCategory(
                        code=code,
                        name=name,
                        display_order=order,
                        risk_level_id=medium_risk.id,
                        is_system=True,
                    )
                )
        db.flush()

        group = db.scalar(select(ApproverGroup).where(ApproverGroup.code == "default_exception_approvers"))
        if group is None:
            group = ApproverGroup(
                code="default_exception_approvers",
                name="Default Exception Approvers",
                description="Administrators must explicitly assign human approvers; the group is intentionally empty at seed time.",
            )
            db.add(group)
            db.flush()
        workflow = db.scalar(
            select(ApprovalWorkflow).where(
                ApprovalWorkflow.name == "Default enterprise exception approval",
                ApprovalWorkflow.is_default.is_(True),
            )
        )
        if workflow is None:
            workflow = ApprovalWorkflow(
                name="Default enterprise exception approval",
                is_default=True,
                is_active=True,
            )
            db.add(workflow)
            db.flush()
            stages = [
                ("Manager approval", "manager", StageKind.MANAGER, 1, True, 3, None),
                (
                    "Delivery Head approval",
                    "delivery_head",
                    StageKind.DELIVERY_HEAD,
                    2,
                    False,
                    2,
                    None,
                ),
                (
                    "Technology/Security review",
                    "exception_approver",
                    StageKind.EXCEPTION_APPROVER,
                    3,
                    True,
                    3,
                    group.id,
                ),
                ("Final approval", "final", StageKind.FINAL, 4, True, 3, group.id),
            ]
            for name, key, kind, sequence, required, sla, approver_group_id in stages:
                db.add(
                    WorkflowStage(
                        workflow_id=workflow.id,
                        name=name,
                        stage_key=key,
                        kind=kind,
                        sequence=sequence,
                        required=required,
                        sla_business_days=sla,
                        approver_group_id=approver_group_id,
                        minimum_approvals=1,
                    )
                )

        for key, value in CONFIG_DEFAULTS.items():
            if db.scalar(select(SystemConfig).where(SystemConfig.config_key == key)) is None:
                db.add(SystemConfig(config_key=key, value=value, value_type="json"))
        for event_key, name, subject, body in TEMPLATES:
            if db.scalar(select(EmailTemplate).where(EmailTemplate.event_key == event_key)) is None:
                db.add(
                    EmailTemplate(
                        event_key=event_key,
                        name=name,
                        subject_template=subject,
                        body_template=body,
                        allowed_variables=sorted(
                            set(re.findall(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}", subject + body))
                        ),
                        is_active=True,
                        validation_status="valid",
                        validated_at=datetime.now(UTC),
                    )
                )
        for order, (key, label, data_type) in enumerate(
            [
                ("change_ticket", "Change / incident ticket", "text"),
                ("cost_center", "Cost center", "text"),
                ("vulnerability_reference", "Vulnerability reference", "url"),
            ],
            start=200,
        ):
            if db.scalar(select(RequestFieldDefinition).where(RequestFieldDefinition.field_key == key)) is None:
                db.add(
                    RequestFieldDefinition(
                        field_key=key,
                        label=label,
                        data_type=data_type,
                        is_required=False,
                        validation_schema={"min_length": 1, "max_length": 500},
                        display_order=order,
                    )
                )

        for name, description, category_code, default_values in REQUEST_TEMPLATES:
            if db.scalar(
                select(RequestTemplate).where(
                    RequestTemplate.name == name,
                    RequestTemplate.created_by_id.is_(None),
                )
            ) is None:
                category = (
                    db.scalar(select(ExceptionCategory).where(ExceptionCategory.code == category_code))
                    if category_code
                    else None
                )
                db.add(
                    RequestTemplate(
                        name=name,
                        description=description,
                        category_id=category.id if category else None,
                        default_values=default_values,
                        is_active=True,
                    )
                )

        # A single, explicit local break-glass identity. No ordinary local user is seeded.
        break_glass = db.scalar(select(User).where(User.is_break_glass.is_(True)))
        if break_glass is None:
            initial = settings.break_glass_initial_password
            if initial is None:
                raise RuntimeError(
                    "BREAK_GLASS_INITIAL_PASSWORD is required for first seed and must be supplied through a secret channel"
                )
            break_glass = User(
                public_id="USR-000001",
                email=settings.break_glass_username,
                email_normalized=settings.break_glass_username.casefold(),
                display_name="Break-glass Local Administrator",
                status="active",
                is_break_glass=True,
                password_hash=hash_password(initial.get_secret_value()),
                must_change_password=True,
            )
            db.add(break_glass)
            db.flush()
            db.add(UserRole(user_id=break_glass.id, role_id=roles["admin"].id))
            recovery_codes = [secrets.token_urlsafe(12) for _ in range(10)]
            for code in recovery_codes:
                db.add(LocalRecoveryCode(user_id=break_glass.id, code_hash=hash_token(code)))
            db.commit()
            print("Break-glass recovery codes (shown once; store in the approved offline vault):", file=sys.stderr)
            for code in recovery_codes:
                print(f"  {code}", file=sys.stderr)
        else:
            db.commit()
        print("Reference data seeded successfully.")


def seed_development_data() -> None:
    settings = get_settings()
    if settings.environment not in {"development", "test"} or not settings.seed_development_data:
        return
    with SessionLocal() as db:
        if db.scalar(select(ExceptionRequest).where(ExceptionRequest.public_id.like("EXC-DEMO-%"))):
            db.commit()
            return
        roles = {role.code: role for role in db.scalars(select(Role))}
        users: dict[str, User] = {}
        for code, name, email, role_code in [
            ("dev-user", "Development User", "user@example.invalid", "user"),
            ("dev-approver", "Development Approver", "approver@example.invalid", "approver"),
        ]:
            user = User(
                public_id=f"USR-DEMO-{len(users) + 1:03d}",
                identity_provider="development_idp",
                identity_subject=code,
                email=email,
                email_normalized=email,
                display_name=name,
                status="active",
            )
            db.add(user)
            db.flush()
            db.add(UserRole(user_id=user.id, role_id=roles[role_code].id))
            users[code] = user
        category = db.scalar(select(ExceptionCategory).where(ExceptionCategory.code == "security_policy"))
        risk = db.scalar(select(RiskLevel).where(RiskLevel.code == "medium"))
        user = users["dev-user"]
        user.manager = users["dev-approver"]
        today = datetime.now(UTC).date()
        sample_expiry = today + timedelta(days=28)
        db.add(
            ExceptionRequest(
                public_id="EXC-DEMO-000001",
                requester_id=user.id,
                created_by_id=user.id,
                last_modified_by_id=user.id,
                title="Demonstration security policy exception",
                description="Development-only sample data; not production content.",
                business_justification="Demonstrates the employee request dashboard and workflow.",
                category_id=category.id,
                exception_type="Demonstration",
                department="Engineering",
                manager_id=user.manager_id,
                application_name="Example Application",
                business_owner="Example Business Owner",
                technology_owner="Example Technology Owner",
                environment="Test",
                asset_system="example-test-001",
                data_classification_code="Internal",
                control_excepted="Example control",
                current_control="Example standard control",
                requested_exception="Time-limited demonstration only",
                reason_control_cannot_follow="Demonstration data is not connected to production controls.",
                risk_description="Demonstration risk only",
                business_impact="No production impact",
                security_impact="No production impact",
                compensating_controls="Development data is isolated and synthetic.",
                remediation_plan="Remove demonstration data before production deployment.",
                requested_start_date=today,
                requested_expiry_date=sample_expiry,
                requested_duration_days=28,
                original_expiry_date=sample_expiry,
                expiry_date=sample_expiry,
                risk_level_id=risk.id,
            )
        )
        db.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed safe Exception-Manager reference data")
    parser.add_argument("--development-samples", action="store_true")
    args = parser.parse_args()
    seed_reference_data()
    if args.development_samples:
        seed_development_data()
