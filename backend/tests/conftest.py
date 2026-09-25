from __future__ import annotations

from datetime import UTC, date, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.api.routes import admin, dashboard
from app.core.errors import DomainError, domain_error_handler
from app.db.session import get_db
from app.models import (
    ApprovalAssignment,
    ExceptionCategory,
    ExceptionRequest,
    RequestStatus,
    RiskLevel,
    User,
)
from app.models.base import Base
from app.services.authz import Principal, get_current_principal
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def app_client(db_session):
    app = FastAPI()
    app.state.settings = SimpleNamespace(session_cookie_name="em_session")
    app.include_router(dashboard.router)
    app.include_router(admin.router)
    app.add_exception_handler(DomainError, domain_error_handler)

    @app.middleware("http")
    async def request_context(request, call_next):
        request.state.correlation_id = "test-correlation-id"
        request.state.request_id = "test-request-id"
        return await call_next(request)

    session_factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    current_principal: dict[str, Principal | None] = {"value": None}

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_principal] = lambda: current_principal["value"]
    with TestClient(app) as client:
        yield client, current_principal, db_session


def make_principal(
    user: User,
    roles: set[str],
    permissions: set[str] | None = None,
) -> Principal:
    return Principal(
        user=user,
        roles=frozenset(roles),
        permissions=frozenset(permissions or ()),
        session_id=uuid4(),
    )


def make_user(
    db_session,
    public_id: str,
    *,
    display_name: str | None = None,
    department: str | None = "Engineering",
    status: str = "active",
) -> User:
    user = User(
        public_id=public_id,
        email=f"{public_id.lower()}@example.invalid",
        email_normalized=f"{public_id.lower()}@example.invalid",
        display_name=display_name or public_id,
        department=department,
        status=status,
    )
    db_session.add(user)
    db_session.flush()
    return user


def make_request(
    db_session,
    *,
    public_id: str,
    requester: User,
    category: ExceptionCategory,
    risk: RiskLevel,
    created_at: datetime,
    status: str = RequestStatus.DRAFT,
    department: str = "Engineering",
    expiry_date: date | None = None,
) -> ExceptionRequest:
    expiry_date = expiry_date or created_at.date()
    request = ExceptionRequest(
        public_id=public_id,
        requester_id=requester.id,
        title=f"Request {public_id}",
        description="A sufficiently detailed request description for tests.",
        business_justification="A sufficiently detailed business justification for tests.",
        category_id=category.id,
        exception_type="Test exception",
        department=department,
        application_name="Test application",
        business_owner="Business owner",
        technology_owner="Technology owner",
        environment="Test",
        asset_system="test-asset",
        data_classification_code="Internal",
        control_excepted="Test control",
        current_control="Current control",
        requested_exception="Requested exception",
        reason_control_cannot_follow="The normal control cannot be followed.",
        risk_description="Risk description",
        business_impact="Business impact",
        security_impact="Security impact",
        compensating_controls="Compensating controls",
        remediation_plan="Remediation plan",
        requested_start_date=created_at.date(),
        requested_expiry_date=expiry_date,
        requested_duration_days=max(1, (expiry_date - created_at.date()).days + 1),
        risk_level_id=risk.id,
        original_expiry_date=expiry_date,
        expiry_date=expiry_date,
        created_by_id=requester.id,
        last_modified_by_id=requester.id,
        status=status,
        created_at=created_at,
        updated_at=created_at,
    )
    db_session.add(request)
    db_session.flush()
    return request


def assign_approver(
    db_session,
    request: ExceptionRequest,
    approver: User,
    *,
    due_at: datetime | None = None,
) -> ApprovalAssignment:
    assignment = ApprovalAssignment(
        request_id=request.id,
        stage_key="review",
        stage_name="Review",
        approver_id=approver.id,
        status="pending",
        due_at=due_at or datetime.now(UTC),
    )
    db_session.add(assignment)
    db_session.flush()
    return assignment
