from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.api.dependencies import audit_context
from app.core.errors import NotFoundError
from app.db.session import get_db
from app.models import ApprovalAssignment, Attachment
from app.schemas.common import AuditContext, Page
from app.schemas.requests import (
    ApprovalDecisionRequest,
    ClarificationResponseRequest,
    CloseRequest,
    CommentCreate,
    CommentResponse,
    ExtensionCreate,
    RemediationUpdateCreate,
    RequestCreate,
    RequestDetail,
    RequestSummary,
    RequestUpdate,
    SubmitRequest,
    WithdrawRequest,
)
from app.services.ai import queue_request_analysis
from app.services.audit import record_audit
from app.services.authz import Principal, get_current_principal
from app.services.authorization import get_authorized_request
from app.services.files import attachment_path, upload_attachment
from app.services.requests import (
    add_comment,
    create_request,
    list_requests,
    request_detail,
    request_summary,
    update_request,
)
from app.services.risk import assess_structured_risk
from app.services.workflow import (
    close_request,
    decide_approval,
    request_extension,
    respond_to_clarification,
    submit_request,
    update_remediation,
    withdraw_request,
)

router = APIRouter(prefix="/requests", tags=["exception requests"])


@router.get("", response_model=Page[RequestSummary])
def get_requests(
    search: str | None = Query(default=None, max_length=200),
    status: list[str] = Query(default=[]),
    category_id: str | None = None,
    risk_level_id: str | None = None,
    requester_id: str | None = None,
    application: str | None = Query(default=None, max_length=200),
    expiring_before: date | None = None,
    sort: str = "updated",
    direction: Literal["asc", "desc"] = "desc",
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> Page[RequestSummary]:
    requests, total = list_requests(
        db,
        principal,
        search=search,
        status=status,
        category_id=category_id,
        risk_level_id=risk_level_id,
        requester_id=requester_id,
        application=application,
        expiring_before=expiring_before,
        sort=sort,
        direction=direction,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size
    return Page[RequestSummary](
        items=[RequestSummary.model_validate(request_summary(item)) for item in requests],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("", response_model=RequestDetail, status_code=201)
def post_request(
    payload: RequestCreate,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = create_request(db, principal, payload, context)
    db.commit()
    return request_detail(db, record, principal)


@router.get("/{identifier}", response_model=RequestDetail)
def get_request(
    identifier: str,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(
        db, identifier, principal, audit_read=True, context=context
    )
    db.commit()
    return request_detail(db, record, principal)


@router.patch("/{identifier}", response_model=RequestDetail)
def patch_request(
    identifier: str,
    payload: RequestUpdate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    update_request(db, record, principal, payload, context)
    db.commit()
    return request_detail(db, record, principal)


@router.post("/{identifier}/submit", response_model=RequestDetail)
def post_submit(
    identifier: str,
    payload: SubmitRequest,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    if not payload.attestation:
        from app.core.errors import DomainError

        raise DomainError("Requester attestation is required", code="attestation_required")
    record = get_authorized_request(db, identifier, principal, lock=True)
    submit_request(db, record, principal.user, request.app.state.settings, context)
    db.commit()
    return request_detail(db, record, principal)


@router.post("/{identifier}/comments", response_model=CommentResponse, status_code=201)
def post_comment(
    identifier: str,
    payload: CommentCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    comment = add_comment(db, record, principal, payload.body, context)
    db.commit()
    return {
        "id": str(comment.id),
        "author_id": str(comment.author_id),
        "author_name": principal.user.display_name,
        "kind": comment.kind,
        "body": comment.body,
        "is_clarification_response": comment.is_clarification_response,
        "created_at": comment.created_at,
    }


@router.post("/{identifier}/clarification-response", response_model=RequestDetail)
def post_clarification_response(
    identifier: str,
    payload: ClarificationResponseRequest,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    respond_to_clarification(db, record, principal, payload, context)
    db.commit()
    return request_detail(db, record, principal)


@router.post("/{identifier}/withdraw", response_model=RequestDetail)
def post_withdraw(
    identifier: str,
    payload: WithdrawRequest,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    withdraw_request(db, record, principal, payload.expected_version, payload.reason, context)
    db.commit()
    return request_detail(db, record, principal)


@router.post("/{identifier}/extensions", response_model=RequestDetail, status_code=201)
def post_extension(
    identifier: str,
    payload: ExtensionCreate,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    request_extension(
        db,
        record,
        principal,
        payload.expected_version,
        payload.requested_expiry_date,
        payload.reason,
        request.app.state.settings,
        context,
    )
    db.commit()
    return request_detail(db, record, principal)


@router.post("/{identifier}/remediation", status_code=201)
def post_remediation(
    identifier: str,
    payload: RemediationUpdateCreate,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    update = update_remediation(
        db,
        record,
        principal,
        payload.status,
        payload.progress_percent,
        payload.notes,
        payload.evidence_attachment_id,
        context,
    )
    db.commit()
    return {"id": str(update.id), "status": update.to_status, "progress_percent": update.progress_percent}


@router.post("/{identifier}/close", response_model=RequestDetail)
def post_close(
    identifier: str,
    payload: CloseRequest,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    close_request(
        db,
        record,
        principal,
        payload.reason,
        payload.remediation_completed,
        payload.evidence_attachment_id,
        context,
    )
    db.commit()
    return request_detail(db, record, principal)


@router.get("/{identifier}/risk-preview")
def get_structured_risk(
    identifier: str,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
) -> dict:
    record = get_authorized_request(db, identifier, principal)
    score, level, factors = assess_structured_risk(db, record, request.app.state.settings)
    return {
        "score": score,
        "level": level,
        "factors": [factor.__dict__ for factor in factors],
        "explanation": "Configured organizational risk factors; this does not replace human approval.",
    }


@router.post("/{identifier}/ai-analyses", status_code=202)
def post_ai_analysis(
    identifier: str,
    feature: Literal["request_summary", "similar_exceptions", "risk_assessment"],
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    analysis = queue_request_analysis(
        db,
        record,
        principal,
        feature,
        request.app.state.settings,
        context,
    )
    db.commit()
    return {
        "id": str(analysis.id),
        "status": analysis.status,
        "feature": analysis.feature,
        "disclaimer": "AI-generated assistance — human approval required.",
    }


@router.post("/{identifier}/attachments", status_code=202)
def post_attachment(
    identifier: str,
    request: Request,
    file: UploadFile = File(...),
    evidence_type: str | None = Form(default=None, max_length=80),
    evidence_source: str | None = Form(default=None, max_length=160),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    record = get_authorized_request(db, identifier, principal, lock=True)
    attachment = upload_attachment(
        db,
        record,
        principal,
        file,
        request.app.state.settings,
        context,
        evidence_type=evidence_type,
        evidence_source=evidence_source,
    )
    db.commit()
    return {
        "id": str(attachment.id),
        "filename": attachment.original_filename,
        "scan_status": attachment.scan_status,
        "sha256": attachment.sha256,
    }


@router.get("/{identifier}/attachments/{attachment_id}/download")
def download_attachment(
    identifier: str,
    attachment_id: str,
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
):
    record = get_authorized_request(db, identifier, principal)
    attachment = db.scalar(
        select(Attachment).where(Attachment.id == attachment_id, Attachment.request_id == record.id)
    )
    if attachment is None:
        raise NotFoundError("Attachment was not found")
    path = attachment_path(db, attachment, request.app.state.settings)
    record_audit(
        db,
        context,
        action="attachment.downloaded",
        object_type="exception_request",
        object_id=record.public_id,
        new_value={"attachment_id": str(attachment.id), "sha256": attachment.sha256},
    )
    db.commit()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=attachment.original_filename,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store, private",
        },
    )


approvals_router = APIRouter(prefix="/approvals", tags=["approvals"])


@approvals_router.post("/{assignment_id}/decision", response_model=RequestDetail)
def post_approval_decision(
    assignment_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
    x_approval_action_token: str | None = Header(default=None, alias="X-Approval-Action-Token"),
    principal: Principal = Depends(get_current_principal),
    db: DbSession = Depends(get_db),
    context: AuditContext = Depends(audit_context),
) -> dict:
    import uuid

    assignment_id_uuid = uuid.UUID(assignment_id)
    assignment = db.get(ApprovalAssignment, assignment_id_uuid)
    if assignment is None:
        raise NotFoundError("Pending approval was not found")
    if assignment.approver_id != principal.user.id:
        raise NotFoundError("Pending approval was not found")
    record = get_authorized_request(db, str(assignment.request_id), principal, lock=True)
    decide_approval(
        db,
        record,
        assignment_id_uuid,
        principal,
        payload,
        request.app.state.settings,
        context,
        action_token=x_approval_action_token,
    )
    db.commit()
    return request_detail(db, record, principal)
