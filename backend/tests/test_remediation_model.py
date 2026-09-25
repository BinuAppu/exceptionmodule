from datetime import UTC, datetime

from app.models import ExceptionCategory, RemediationUpdate, RiskLevel
from conftest import make_request, make_user


def test_remediation_update_persists_timestamp_columns(db_session) -> None:
    user = make_user(db_session, "USR-REMEDIATION", display_name="Remediation Tester")
    category = ExceptionCategory(code="remediation_test", name="Remediation test")
    risk = RiskLevel(code="low", name="Low", score=10, description="Low risk")
    db_session.add_all([category, risk])
    db_session.flush()
    request = make_request(
        db_session,
        public_id="EXC-REMEDIATION",
        requester=user,
        category=category,
        risk=risk,
        created_at=datetime.now(UTC),
    )

    update = RemediationUpdate(
        request_id=request.id,
        actor_id=user.id,
        from_status="not_started",
        to_status="in_progress",
        progress_percent=25,
        notes="Initial remediation work started.",
    )
    db_session.add(update)
    db_session.commit()

    assert update.created_at is not None
    assert update.updated_at is not None
