from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import admin, auth, dashboard, notifications, requests
from app.core.config import get_settings
from app.core.errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DomainError,
    NotFoundError,
    domain_error_handler,
    http_error_handler,
    unhandled_error_handler,
)
from app.core.logging import configure_logging
from app.core.middleware import CorrelationAndSecurityMiddleware
from app.db.session import engine

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)
frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.storage_root.mkdir(parents=True, exist_ok=True)
    (settings.storage_root / "attachments" / "quarantine").mkdir(parents=True, exist_ok=True)
    (settings.storage_root / "attachments" / "clean").mkdir(parents=True, exist_ok=True)
    settings.backup_directory.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Enterprise technology exception management API",
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if settings.environment == "production" else "/openapi.json",
    lifespan=lifespan,
)

app.state.settings = settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Correlation-ID", "X-Approval-Action-Token", "X-Reauthentication-Password"],
    expose_headers=["X-Correlation-ID", "X-Request-ID"],
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(CorrelationAndSecurityMiddleware)

app.add_exception_handler(DomainError, domain_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(AuthenticationError, domain_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(AuthorizationError, domain_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(NotFoundError, domain_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(ConflictError, domain_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(Exception, unhandled_error_handler)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Field identifiers are safe; input values and internal exception context are not returned.
    fields = []
    for error in exc.errors():
        location = [str(item) for item in error.get("loc", []) if item not in {"body", "query", "path"}]
        fields.append({"field": ".".join(location), "message": error.get("msg", "Invalid value")})
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "One or more fields are invalid.",
                "fields": fields,
                "reference_id": getattr(request.state, "correlation_id", "unknown"),
            }
        },
    )


@app.get("/", include_in_schema=False, response_model=None)
def root() -> Response:
    index_path = frontend_dist / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return JSONResponse(
        content={
            "application": settings.app_name,
            "version": settings.app_version,
            "api": settings.api_prefix,
        }
    )


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready", include_in_schema=False)
def ready() -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        logger.exception("readiness_database_failed", extra={"component": "health", "result": "failure"})
        checks["database"] = "failed"
    probe = settings.storage_root / ".readiness"
    try:
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks["storage"] = "ok"
    except Exception:
        checks["storage"] = "failed"
    status_code = 200 if all(value == "ok" for value in checks.values()) else 503
    return JSONResponse(status_code=status_code, content={"status": "ready" if status_code == 200 else "not_ready", "checks": checks})


for api_router in (auth.router, dashboard.router, requests.router, requests.approvals_router, notifications.router, admin.router):
    app.include_router(api_router, prefix=settings.api_prefix)

# Serve a built single-page application when explicitly present. Production images may instead use a dedicated CDN/edge.
if frontend_dist.is_dir():
    from fastapi.staticfiles import StaticFiles
    from starlette.exceptions import HTTPException as StarletteHTTPException

    class SPAStaticFiles(StaticFiles):
        async def get_response(self, path: str, scope):
            try:
                return await super().get_response(path, scope)
            except StarletteHTTPException as exc:
                # The mounted scope includes a leading slash. Without normalizing it,
                # unknown /api routes were incorrectly rewritten to index.html with a
                # 200 response, which the browser then treated as API data and crashed on.
                request_path = scope.get("path", "").lstrip("/")
                if exc.status_code != 404 or request_path.startswith("api/"):
                    raise
                return await super().get_response("index.html", scope)

    app.mount("/", SPAStaticFiles(directory=frontend_dist, html=True), name="frontend")
