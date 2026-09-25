from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.correlation import correlation_id_context, new_correlation_id

RequestHandler = Callable[[Request], Awaitable[Response]]


class CorrelationAndSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        incoming = request.headers.get("X-Correlation-ID", "")
        correlation_id = incoming if incoming.isalnum() and len(incoming) <= 64 else new_correlation_id()
        token = correlation_id_context.set(correlation_id)
        request.state.correlation_id = correlation_id
        request.state.request_id = new_correlation_id()
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            correlation_id_context.reset(token)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store" if "/api/auth" in request.url.path else response.headers.get("Cache-Control", "no-cache")
        if request.url.path.startswith("/api"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
            )
        response.headers["X-Runtime-Seconds"] = f"{time.perf_counter() - started:.4f}"
        return response
