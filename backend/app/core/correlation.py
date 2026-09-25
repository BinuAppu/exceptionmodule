from __future__ import annotations

import contextvars
import uuid

correlation_id_context: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def get_correlation_id() -> str:
    return correlation_id_context.get()
