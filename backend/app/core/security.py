from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def hash_password(password: str) -> str:
    validate_password(password)
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def validate_password(password: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if len(password) < settings.password_minimum_length:
        raise ValueError(f"Password must be at least {settings.password_minimum_length} characters")
    if len(password) > 256:
        raise ValueError("Password must not exceed 256 characters")
    classes = (
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    )
    if sum(classes) < 3:
        raise ValueError("Password must include at least three character classes")


def generate_opaque_token(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def public_reference(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def safe_filename(filename: str | None, fallback: str = "file") -> str:
    if not filename:
        return fallback
    normalized = unicodedata.normalize("NFKC", filename).replace("\\", "/")
    normalized = normalized.rsplit("/", 1)[-1]
    normalized = _CONTROL_CHARS.sub("", normalized).strip(" .")
    normalized = re.sub(r"[^A-Za-z0-9._ -]", "_", normalized)
    return normalized[:180] or fallback


def new_fernet(settings: Settings | None = None) -> Fernet:
    settings = settings or get_settings()
    key = settings.resolved_encryption_key()
    if len(key) != 32:
        raise ValueError("Encryption key must decode to exactly 32 bytes")
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(value: str, settings: Settings | None = None) -> str:
    return new_fernet(settings).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str, settings: Settings | None = None) -> str:
    try:
        return new_fernet(settings).decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise AuthenticationError("Stored credential could not be decrypted") from exc


def utc_now() -> datetime:
    return datetime.now(UTC)


def aware_utc_now() -> datetime:
    return datetime.now(UTC)


def session_expiry(settings: Settings) -> tuple[datetime, datetime]:
    now = aware_utc_now()
    return now + timedelta(minutes=settings.session_idle_minutes), now + timedelta(
        minutes=settings.session_absolute_minutes
    )


def redact_secrets(value: Any, *, max_length: int = 100_000) -> Any:
    """Best-effort secret/PII minimization for AI and structured logs."""
    if len(str(value)) > max_length:
        raise ValueError("Content exceeds permitted processing length")
    if isinstance(value, dict):
        return {str(k)[:100]: redact_secrets(v, max_length=max_length) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(v, max_length=max_length) for v in value[:500]]
    if not isinstance(value, str):
        return value
    patterns = [
        (r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)((?:api[_-]?key|password|secret|token|private[_-]?key)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"\b(?:sk-|eyJ)[A-Za-z0-9._-]{16,}\b", "[REDACTED]"),
        (r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_PAN]"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ]
    result = value
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.DOTALL)
    return result
