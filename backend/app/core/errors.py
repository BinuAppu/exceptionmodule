from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse


class DomainError(Exception):
    """Expected business error safe to expose as a concise API message."""

    def __init__(self, message: str, *, code: str = "domain_error", status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class NotFoundError(DomainError):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, code="not_found", status_code=status.HTTP_404_NOT_FOUND)


class ConflictError(DomainError):
    def __init__(self, message: str = "The resource changed; refresh and try again"):
        super().__init__(message, code="version_conflict", status_code=status.HTTP_409_CONFLICT)


class AuthorizationError(DomainError):
    def __init__(self, message: str = "You are not authorized to perform this action"):
        super().__init__(message, code="forbidden", status_code=status.HTTP_403_FORBIDDEN)


class AuthenticationError(DomainError):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, code="authentication_required", status_code=status.HTTP_401_UNAUTHORIZED)


def _correlation_id(request: Request) -> str:
    return getattr(request.state, "correlation_id", "unknown")


async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Preserve FastAPI's safe 401/403 headers while normalizing response bodies.
    detail: Any = exc.detail
    message = detail if isinstance(detail, str) else "Request could not be completed"
    headers = getattr(exc, "headers", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "request_rejected",
                "message": message,
                "reference_id": _correlation_id(request),
            }
        },
        headers=headers,
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # The exception is emitted only to structured server logs, never to the client.
    import logging

    logging.getLogger("exception_manager.api").exception(
        "Unhandled request error", extra={"correlation_id": _correlation_id(request)}
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "Something went wrong while processing your request.",
                "reference_id": _correlation_id(request),
            }
        },
    )
