from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.core.errors import DomainError
from app.models import RateLimitBucket


class RateLimitExceeded(DomainError):
    def __init__(self, retry_after_seconds: int = 60):
        super().__init__(
            "Too many requests. Please wait and try again.",
            code="rate_limited",
            status_code=429,
        )
        self.retry_after_seconds = retry_after_seconds


def client_ip(request) -> str:
    # Proxy headers are trusted only when explicitly configured at the edge.
    return getattr(request.state, "client_ip", None) or (request.client.host if request.client else "unknown")


def _bucket_key(scope: str, identity: str) -> str:
    return hashlib.sha256(f"{scope}:{identity}".encode()).hexdigest()


def enforce_rate_limit(
    db: DbSession,
    *,
    scope: str,
    identity: str,
    limit: int,
    window_seconds: int = 60,
    block_seconds: int | None = None,
) -> None:
    now = datetime.now(UTC)
    key = _bucket_key(scope, identity)
    bucket = db.scalar(select(RateLimitBucket).where(RateLimitBucket.bucket_key == key))
    if bucket is None:
        bucket = RateLimitBucket(
            bucket_key=key,
            request_count=1,
            window_started_at=now,
        )
        db.add(bucket)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise RateLimitExceeded(block_seconds or window_seconds) from None
        return
    if bucket.blocked_until and bucket.blocked_until.replace(tzinfo=bucket.blocked_until.tzinfo or UTC) > now:
        retry = max(1, int((bucket.blocked_until - now).total_seconds()))
        raise RateLimitExceeded(retry)
    if (now - bucket.window_started_at.replace(tzinfo=bucket.window_started_at.tzinfo or UTC)).total_seconds() >= window_seconds:
        bucket.request_count = 1
        bucket.window_started_at = now
        bucket.blocked_until = None
    else:
        bucket.request_count += 1
    if bucket.request_count > limit:
        bucket.blocked_until = now + timedelta(seconds=block_seconds or window_seconds)
        db.flush()
        raise RateLimitExceeded(block_seconds or window_seconds)
    db.flush()
