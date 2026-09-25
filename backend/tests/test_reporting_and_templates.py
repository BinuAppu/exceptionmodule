from __future__ import annotations

from datetime import UTC, datetime

from app.models import (
    AuditEvent,
    DataClassification,
    ExceptionCategory,
    ExportRecord,
    RequestFieldDefinition,
    RequestStatus,
    RequestTemplate,
    RiskLevel,
)
from app.services.authz import get_current_principal
from conftest import assign_approver, make_principal, make_request, make_user
from sqlalchemy import select


def test_request_form_options_requires_authentication(app_client):
    client, _, _ = app_client
    client.app.dependency_overrides.pop(get_current_principal, None)

    response = client.get("/request-form-options")

    assert response.status_code == 401


def test_request_form_options_returns_only_active_reference_data(app_client):
    client, current, db = app_client
    user = make_user(db, "USR-OPTIONS", display_name="Options user", department="Finance")
    category = ExceptionCategory(code="active_category", name="Active category", is_active=True)
    inactive_category = ExceptionCategory(
        code="inactive_category", name="Inactive category", is_active=False
    )
    risk = RiskLevel(
        code="active_risk",
        name="Active risk",
        score=20,
        color="#000000",
        description="Active",
        is_active=True,
    )
    inactive_risk = RiskLevel(
        code="inactive_risk",
        name="Inactive risk",
        score=80,
        color="#000000",
        description="Inactive",
        is_active=False,
    )
    classification = DataClassification(
        code="Internal", name="Internal", rank=1, allow_ai=True, allow_export=True, is_active=True
    )
    inactive_classification = DataClassification(
        code="Restricted",
        name="Restricted",
        rank=3,
        allow_ai=False,
        allow_export=False,
        is_active=False,
    )
    field = RequestFieldDefinition(
        field_key="active_field",
        label="Active field",
        data_type="dropdown",
        allowed_values=[{"label": "One", "value": "one"}],
        is_active=True,
    )
    inactive_field = RequestFieldDefinition(
        field_key="inactive_field",
        label="Inactive field",
        data_type="text",
        is_active=False,
    )
    template = RequestTemplate(
        name="Active template",
        default_values={"risk": "low"},
        is_active=True,
        created_by_id=user.id,
    )
    inactive_template = RequestTemplate(
        name="Inactive template",
        default_values={},
        is_active=False,
        created_by_id=user.id,
    )
    db.add_all(
        [
            category,
            inactive_category,
            risk,
            inactive_risk,
            classification,
            inactive_classification,
            field,
            inactive_field,
            template,
            inactive_template,
        ]
    )
    db.commit()
    current["value"] = make_principal(user, {"user"})

    response = client.get("/request-form-options")

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload["categories"]] == [str(category.id)]
    assert payload["categories"][0]["active"] is True
    assert [item["id"] for item in payload["risk_levels"]] == [str(risk.id)]
    assert payload["data_classifications"] == ["Internal"]
    assert [item["key"] for item in payload["custom_fields"]] == ["active_field"]
    assert payload["custom_fields"][0]["active"] is True
    assert payload["custom_fields"][0]["version"] == field.version
    assert payload["custom_fields"][0]["options"] == [{"label": "One", "value": "one"}]
    assert [item["name"] for item in payload["templates"]] == ["Active template"]
    assert payload["departments"] == ["Finance"]


def test_report_summary_is_inclusive_and_approver_scoped(app_client):
    client, current, db = app_client
    approver = make_user(db, "USR-APPROVER", display_name="Approver")
    owner = make_user(db, "USR-OWNER", display_name="Owner", department="Operations")
    unrelated = make_user(db, "USR-UNRELATED", display_name="Unrelated", department="Finance")
    category = ExceptionCategory(code="report_category", name="Report category")
    risk = RiskLevel(
        code="medium",
        name="Medium",
        score=40,
        color="#000000",
        description="Medium risk",
    )
    db.add_all([category, risk])
    db.flush()
    first = make_request(
        db,
        public_id="EXC-REPORT-START",
        requester=owner,
        category=category,
        risk=risk,
        created_at=datetime(2026, 2, 1, 0, 0, tzinfo=UTC),
        status=RequestStatus.APPROVED,
        department="Operations",
    )
    second = make_request(
        db,
        public_id="EXC-REPORT-END",
        requester=unrelated,
        category=category,
        risk=risk,
        created_at=datetime(2026, 2, 2, 23, 59, 59, tzinfo=UTC),
        status=RequestStatus.PENDING_APPROVER,
        department="Finance",
    )
    make_request(
        db,
        public_id="EXC-REPORT-OUTSIDE",
        requester=unrelated,
        category=category,
        risk=risk,
        created_at=datetime(2026, 2, 3, 0, 0, tzinfo=UTC),
    )
    assign_approver(db, first, approver, due_at=datetime(2026, 2, 4, tzinfo=UTC))
    assign_approver(db, second, approver, due_at=datetime(2026, 2, 4, tzinfo=UTC))
    db.commit()
    current["value"] = make_principal(approver, {"approver"}, {"report.read_assigned"})

    response = client.get(
        "/reports/summary", params={"start_date": "2026-02-01", "end_date": "2026-02-02"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["period_start"] == "2026-02-01"
    assert payload["period_end"] == "2026-02-02"
    assert payload["total_requests"] == 2
    assert payload["approved"] == 1
    assert payload["pending"] == 1
    assert payload["department_breakdown"] == [
        {"department": "Finance", "count": 1},
        {"department": "Operations", "count": 1},
    ]

    admin = make_user(db, "USR-ADMIN", display_name="Admin")
    db.commit()
    current["value"] = make_principal(admin, {"admin"}, {"*"})
    admin_response = client.get(
        "/reports/summary", params={"start_date": "2026-02-01", "end_date": "2026-02-02"}
    )
    assert admin_response.status_code == 200
    assert admin_response.json()["total_requests"] == 2

    current["value"] = make_principal(owner, {"user"})
    denied = client.get(
        "/reports/summary", params={"start_date": "2026-02-01", "end_date": "2026-02-02"}
    )
    assert denied.status_code == 403

    current["value"] = make_principal(approver, {"approver"}, {"report.read_assigned"})
    invalid = client.get(
        "/reports/summary", params={"start_date": "2026-02-03", "end_date": "2026-02-01"}
    )
    assert invalid.status_code == 400


def test_report_export_is_scoped_and_audited(app_client):
    client, current, db = app_client
    approver = make_user(db, "USR-EXPORT-APPROVER", display_name="Export approver")
    owner = make_user(db, "USR-EXPORT-OWNER", display_name="Export owner")
    other = make_user(db, "USR-EXPORT-OTHER", display_name="Export other")
    category = ExceptionCategory(code="export_category", name="Export category")
    risk = RiskLevel(
        code="low",
        name="Low",
        score=10,
        color="#000000",
        description="Low risk",
    )
    db.add_all([category, risk])
    db.flush()
    visible = make_request(
        db,
        public_id="EXC-EXPORT-VISIBLE",
        requester=owner,
        category=category,
        risk=risk,
        created_at=datetime(2026, 3, 1, 12, tzinfo=UTC),
    )
    hidden = make_request(
        db,
        public_id="EXC-EXPORT-HIDDEN",
        requester=other,
        category=category,
        risk=risk,
        created_at=datetime(2026, 3, 1, 13, tzinfo=UTC),
    )
    assign_approver(db, visible, approver, due_at=datetime(2026, 3, 4, tzinfo=UTC))
    db.commit()
    current["value"] = make_principal(approver, {"approver"}, {"report.read_assigned"})

    response = client.get(
        "/reports/export", params={"start_date": "2026-03-01", "end_date": "2026-03-01"}
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "no-store" in response.headers["cache-control"]
    assert visible.public_id in response.text
    assert hidden.public_id not in response.text

    db.expire_all()
    export = db.scalar(select(ExportRecord))
    assert export is not None
    assert export.requested_by_id == approver.id
    assert export.row_count == 1
    assert export.scope["access_scope"] == "owned_or_assigned"
    audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "report.exported"))
    assert audit is not None
    assert audit.new_value["row_count"] == 1


def test_admin_template_crud_duplicate_and_delete(app_client):
    client, current, db = app_client
    admin_user = make_user(db, "USR-TEMPLATE-ADMIN", display_name="Template admin")
    category = ExceptionCategory(code="template_category", name="Template category")
    db.add(category)
    db.commit()
    current["value"] = make_principal(admin_user, {"admin"}, {"*"})

    created = client.post(
        "/admin/templates",
        json={
            "name": "Standard template",
            "description": "A reusable starting point",
            "category_id": str(category.id),
            "is_active": True,
            "default_values": {"risk_level": "medium"},
        },
    )
    assert created.status_code == 201
    template = created.json()
    assert template["name"] == "Standard template"
    assert template["category_id"] == str(category.id)
    assert template["default_values"] == {"risk_level": "medium"}

    listed = client.get("/admin/templates")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [template["id"]]
    fetched = client.get(f"/admin/templates/{template['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "Standard template"

    updated = client.patch(
        f"/admin/templates/{template['id']}",
        json={"name": "Updated template", "is_active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Updated template"
    assert updated.json()["is_active"] is False

    duplicated = client.post(f"/admin/templates/{template['id']}/duplicate")
    assert duplicated.status_code == 201
    assert duplicated.json()["name"] == "Updated template (Copy)"
    assert duplicated.json()["default_values"] == {"risk_level": "medium"}

    deleted = client.delete(f"/admin/templates/{template['id']}")
    assert deleted.status_code == 204
    remaining = client.get("/admin/templates").json()
    assert [item["id"] for item in remaining] == [duplicated.json()["id"]]
    assert remaining[0]["name"] == "Updated template (Copy)"
