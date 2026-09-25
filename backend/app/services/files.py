from __future__ import annotations

import hashlib
import socket
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

import magic
from fastapi import UploadFile
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import AuthorizationError, DomainError, NotFoundError
from app.core.security import safe_filename
from app.models import Attachment, ExceptionRequest
from app.schemas.common import AuditContext
from app.services.audit import record_audit
from app.services.authz import Principal
from app.services.outbox import enqueue_job

DANGEROUS_MIME_PREFIXES = ("text/html", "image/svg", "application/x-", "application/java", "application/x-msdownload")
DANGEROUS_EXTENSIONS = {
    "html", "htm", "svg", "js", "mjs", "exe", "dll", "com", "bat", "cmd", "ps1",
    "jar", "msi", "scr", "hta", "vbs", "wsf", "cpl", "lnk",
}


def _quarantine_path(settings: Settings, stored_name: str) -> Path:
    directory = (settings.storage_root / "attachments" / "quarantine").resolve()
    directory.mkdir(parents=True, exist_ok=True)
    path = (directory / stored_name).resolve()
    if path.parent != directory:
        raise DomainError("Invalid storage path", code="invalid_file_path")
    return path


def _clean_path(settings: Settings, stored_name: str) -> Path:
    directory = (settings.storage_root / "attachments" / "clean").resolve()
    directory.mkdir(parents=True, exist_ok=True)
    path = (directory / stored_name).resolve()
    if path.parent != directory:
        raise NotFoundError("Attachment was not found")
    return path


def _validate_file_metadata(filename: str, content_type: str, detected_type: str, settings: Settings) -> None:
    clean_name = safe_filename(filename)
    extension = clean_name.rsplit(".", 1)[-1].casefold() if "." in clean_name else ""
    normalized_client_type = content_type.split(";", 1)[0].strip().casefold()
    normalized_detected_type = detected_type.split(";", 1)[0].strip().casefold()
    if extension in DANGEROUS_EXTENSIONS or normalized_detected_type.startswith(DANGEROUS_MIME_PREFIXES):
        raise DomainError("This file type is blocked by security policy", code="file_type_blocked")
    allowed_extensions = {item.casefold().lstrip(".") for item in settings.attachment_allowed_extensions}
    allowed_types = {item.casefold() for item in settings.attachment_allowed_mime_types}
    if extension not in allowed_extensions:
        raise DomainError("The file extension is not allowed", code="file_extension_blocked")
    if normalized_client_type not in allowed_types or normalized_detected_type not in allowed_types:
        raise DomainError("The file content does not match an allowed type", code="file_mime_mismatch")
    # Some detectors identify plain text as text/x-words; retain strict allowlisting.
    if normalized_client_type != normalized_detected_type and not {
        normalized_client_type,
        normalized_detected_type,
    } <= {"message/rfc822", "text/plain"}:
        raise DomainError("The file content type could not be verified", code="file_mime_mismatch")


def _write_upload(upload: UploadFile, destination: Path, max_bytes: int) -> tuple[int, str, str]:
    total = 0
    digest = hashlib.sha256()
    with destination.open("xb") as output:
        while chunk := upload.file.read(64 * 1024):
            total += len(chunk)
            if total > max_bytes:
                output.close()
                destination.unlink(missing_ok=True)
                raise DomainError("The attachment exceeds the configured size limit", code="file_too_large")
            digest.update(chunk)
            output.write(chunk)
    if total == 0:
        destination.unlink(missing_ok=True)
        raise DomainError("Empty files are not allowed", code="file_empty")
    return total, digest.hexdigest(), ""


def clamav_scan(path: Path, settings: Settings) -> tuple[bool, str, str | None]:
    """Scan using the ClamAV INSTREAM protocol without invoking a local process."""
    try:
        with socket.create_connection(
            (settings.clamav_host, settings.clamav_port), timeout=settings.clamav_timeout_seconds
        ) as connection:
            connection.settimeout(settings.clamav_timeout_seconds)
            with path.open("rb") as source:
                connection.sendall(b"zINSTREAM\0")
                while chunk := source.read(64 * 1024):
                    connection.sendall(len(chunk).to_bytes(4, "big") + chunk)
                connection.sendall((0).to_bytes(4, "big"))
                response = b""
                while chunk := connection.recv(4096):
                    response += chunk
        text = response.decode("utf-8", errors="replace").strip()
        if text.endswith("OK"):
            return True, text, "clamav"
        if "FOUND" in text:
            return False, text, "clamav"
        raise DomainError("Malware scanner did not return a definitive result", code="scanner_unavailable", status_code=503)
    except (OSError, socket.timeout) as exc:
        raise DomainError("Malware scanning is temporarily unavailable", code="scanner_unavailable", status_code=503) from exc


def upload_attachment(
    db: DbSession,
    request: ExceptionRequest,
    principal: Principal,
    upload: UploadFile,
    settings: Settings,
    context: AuditContext,
    *,
    evidence_type: str | None = None,
    evidence_source: str | None = None,
) -> Attachment:
    if request.requester_id != principal.user.id and not principal.has_role("admin"):
        assigned = any(item.approver_id == principal.user.id for item in request.approvals)
        if not assigned:
            raise AuthorizationError("You cannot add evidence to this request")
    if request.status == "draft":
        raise DomainError("Submit the request before adding attachments", code="request_not_submitted")
    safe_name = safe_filename(upload.filename)
    stored_name = f"{uuid.uuid4().hex}.blob"
    destination = _quarantine_path(settings, stored_name)
    size, digest, _ = _write_upload(upload, destination, settings.attachment_max_bytes)
    try:
        detected = magic.from_file(destination, mime=True)
    except Exception as exc:
        destination.unlink(missing_ok=True)
        raise DomainError("The file content could not be inspected", code="file_inspection_failed") from exc
    client_type = upload.content_type or "application/octet-stream"
    try:
        _validate_file_metadata(safe_name, client_type, detected, settings)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    attachment = Attachment(
        request_id=request.id,
        uploaded_by_id=principal.user.id,
        original_filename=safe_name,
        stored_filename=stored_name,
        content_type=detected,
        size_bytes=size,
        sha256=digest,
        scan_status="quarantined",
        evidence_type=evidence_type,
        evidence_source=evidence_source,
        provided_by=principal.user.id,
        provided_at=datetime.now(UTC),
    )
    db.add(attachment)
    db.flush()
    record_audit(
        db,
        context,
        action="attachment.uploaded",
        object_type="exception_request",
        object_id=request.public_id,
        new_value={
            "attachment_id": str(attachment.id),
            "filename": safe_name,
            "content_type": detected,
            "size_bytes": size,
            "sha256": digest,
            "scan_status": "quarantined",
        },
    )
    enqueue_job(
        db,
        "scan_attachment",
        {"attachment_id": str(attachment.id)},
        deduplication_key=f"scan-attachment:{attachment.id}",
        correlation_id=context.correlation_id,
        priority=20,
    )
    if settings.attachment_scan_mode == "disabled":
        # Only permitted in development/test; this explicit branch supports deterministic local tests.
        quarantine = _quarantine_path(settings, stored_name)
        clean = _clean_path(settings, stored_name)
        quarantine.replace(clean)
        attachment.scan_status = "clean"
        attachment.scan_engine = "disabled_test_mode"
        attachment.scan_result = "Test environment scan bypass"
    return attachment


def complete_scan(db: DbSession, attachment_id: uuid.UUID, settings: Settings, context: AuditContext) -> Attachment:
    attachment = db.scalar(select_attachment(db, attachment_id))
    if attachment is None:
        raise NotFoundError("Attachment was not found")
    if attachment.scan_status in {"clean", "infected", "rejected"}:
        return attachment
    quarantined = _quarantine_path(settings, attachment.stored_filename)
    clean = _clean_path(settings, attachment.stored_filename)
    if settings.attachment_scan_mode == "clamav":
        clean_result, result, engine_name = clamav_scan(quarantined, settings)
    else:
        clean_result, result, engine_name = True, "OK (development test mode)", "disabled"
    attachment.scan_result = result
    attachment.scan_engine = engine_name
    if clean_result:
        quarantined.replace(clean)
        attachment.scan_status = "clean"
        if attachment.content_type == "text/plain":
            data = clean.read_bytes()[:100_000]
            attachment.extracted_text = data.decode("utf-8", errors="replace")
    else:
        attachment.scan_status = "infected"
        quarantined.unlink(missing_ok=True)
    record_audit(
        db,
        context,
        action="attachment.scan_completed",
        object_type="exception_request",
        object_id=str(attachment.request_id),
        new_value={
            "attachment_id": str(attachment.id),
            "sha256": attachment.sha256,
            "scan_status": attachment.scan_status,
            "result": attachment.scan_result,
        },
    )
    return attachment


def select_attachment(db: DbSession, attachment_id):
    from sqlalchemy import select

    return db.scalar(select(Attachment).where(Attachment.id == attachment_id))


def attachment_path(db: DbSession, attachment: Attachment, settings: Settings) -> Path:
    if attachment.scan_status != "clean" or attachment.deleted_at:
        raise AuthorizationError("This attachment is not available")
    path = _clean_path(settings, attachment.stored_filename)
    if not path.is_file():
        raise NotFoundError("Attachment content is unavailable")
    return path
