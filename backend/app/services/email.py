from __future__ import annotations

import re
import smtplib
import socket
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import Settings
from app.core.errors import DomainError
from app.core.security import redact_secrets
from app.models import EmailTemplate

VARIABLE_PATTERN = re.compile(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}")
ALLOWED_VARIABLES = {
    "request_id",
    "request_title",
    "requester_name",
    "manager_name",
    "approver_name",
    "exception_type",
    "expiry_date",
    "approval_url",
    "application_name",
    "notification_message",
}


def validate_template(subject: str, body: str, allowed_variables: list[str] | None = None) -> set[str]:
    variables = {match.group(1) for match in VARIABLE_PATTERN.finditer(f"{subject}\n{body}")}
    allowed = set(allowed_variables if allowed_variables is not None else ALLOWED_VARIABLES)
    unsupported = variables - allowed
    if unsupported:
        raise DomainError(
            f"Template contains unsupported variables: {', '.join(sorted(unsupported))}",
            code="email_template_invalid",
        )
    if "<script" in body.casefold() or "javascript:" in body.casefold():
        raise DomainError("Active content is not allowed in email templates", code="email_template_unsafe")
    return variables


def render_template(template: str, values: dict[str, Any]) -> str:
    def replacement(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise DomainError(f"Template variable '{key}' has no value", code="email_template_invalid")
        return str(redact_secrets(values[key], max_length=10_000))

    return VARIABLE_PATTERN.sub(replacement, template)


def active_template(db: DbSession, event_key: str, locale: str = "en") -> EmailTemplate | None:
    return db.scalar(
        select(EmailTemplate)
        .where(
            EmailTemplate.event_key == event_key,
            EmailTemplate.locale == locale,
            EmailTemplate.is_active.is_(True),
            EmailTemplate.validation_status == "valid",
        )
        .order_by(EmailTemplate.version.desc())
        .limit(1)
    )


def send_email(
    db: DbSession,
    *,
    to_address: str,
    subject: str,
    body: str,
    settings: Settings,
) -> None:
    if not settings.smtp_host:
        raise DomainError("SMTP is not configured", code="smtp_not_configured", status_code=503)
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds) as smtp:
            smtp.ehlo()
            if settings.smtp_use_tls:
                smtp.starttls(context=ssl_context())
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, socket.timeout) as exc:
        raise DomainError("Email delivery failed", code="email_delivery_failed", status_code=503) from exc


def ssl_context():
    import ssl

    # Certificate and hostname verification remain enabled.
    return ssl.create_default_context()
