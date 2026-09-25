from __future__ import annotations

import hashlib
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.security import new_fernet
from app.models import BackupRecord


def create_backup_record(db: DbSession, requested_by_id, correlation_id: str) -> BackupRecord:
    record = BackupRecord(
        requested_by_id=requested_by_id,
        correlation_id=correlation_id,
        status="queued",
    )
    db.add(record)
    db.flush()
    return record


def execute_backup(db: DbSession, record_id: uuid.UUID, settings: Settings) -> BackupRecord:
    record = db.get(BackupRecord, record_id)
    if record is None:
        raise DomainError("Backup record was not found")
    if record.status == "completed":
        return record
    directory = settings.backup_directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    file_name = f"exception-manager-{stamp}-{uuid.uuid4().hex[:8]}.dump.enc"
    destination = (directory / file_name).resolve()
    if destination.parent != directory:
        raise DomainError("Invalid backup destination", code="invalid_backup_path")
    record.status = "running"
    record.started_at = datetime.now(UTC)
    if not settings.database_url.startswith("postgresql"):
        record.status = "failed"
        record.failure_reason = "Database backup command supports PostgreSQL production databases only"
        record.completed_at = datetime.now(UTC)
        return record
    temp = destination.with_suffix(".partial")
    env = os.environ.copy()
    # SQLAlchemy parses the URL safely; the password is supplied via PGPASSWORD, never argv.
    parsed_url = make_url(settings.database_url)
    env["PGPASSWORD"] = parsed_url.password or ""
    command_url = parsed_url.set(drivername="postgresql", password=None).render_as_string(hide_password=False)
    try:
        with temp.open("xb") as output:
            process = subprocess.run(  # noqa: S603 - fixed executable and argument list; shell=False
                [
                    settings.backup_command,
                    "--format=custom",
                    "--no-password",
                    "--file",
                    str(temp),
                    command_url,
                ],
                env=env,
                shell=False,
                capture_output=True,
                timeout=3600,
                check=False,
            )
        if process.returncode != 0:
            raise DomainError("Database backup command failed", code="backup_failed")
        data = temp.read_bytes()
        encrypted = new_fernet(settings).encrypt(data) if settings.backup_encryption_key else data
        destination.write_bytes(encrypted)
        temp.unlink(missing_ok=True)
        record.file_name = file_name
        record.location_uri = str(destination)
        record.size_bytes = destination.stat().st_size
        record.sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
        record.status = "completed"
        record.completed_at = datetime.now(UTC)
        record.verification_status = "hash_recorded"
    except Exception as exc:
        temp.unlink(missing_ok=True)
        record.status = "failed"
        record.failure_reason = str(exc)[:2000]
        record.completed_at = datetime.now(UTC)
    return record


def verify_latest_backup(db: DbSession, settings: Settings) -> BackupRecord | None:
    record = db.query(BackupRecord).filter(BackupRecord.status == "completed").order_by(BackupRecord.completed_at.desc()).first()
    if record is None or not record.location_uri:
        return None
    path = Path(record.location_uri)
    if not path.is_file() or path.stat().st_size != record.size_bytes:
        record.verification_status = "failed"
        raise DomainError("Backup file is missing or its size changed", code="backup_verification_failed")
    if hashlib.sha256(path.read_bytes()).hexdigest() != record.sha256:
        record.verification_status = "failed"
        raise DomainError("Backup checksum verification failed", code="backup_verification_failed")
    record.verification_status = "verified"
    record.verified_at = datetime.now(UTC)
    return record
