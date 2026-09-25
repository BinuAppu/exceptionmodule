from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)
    pages: int = Field(ge=0)


class MessageResponse(BaseModel):
    message: str


class IdempotentRequest(BaseModel):
    idempotency_key: str | None = Field(default=None, min_length=16, max_length=100)


class ErrorBody(BaseModel):
    code: str
    message: str
    reference_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class AuditContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    actor_id: str | None = None
    actor_label: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    correlation_id: str
    metadata: dict[str, Any] = Field(default_factory=dict)
