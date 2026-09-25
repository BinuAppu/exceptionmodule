from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.base import Base

# Import all model metadata before migrations or test table creation.
from app.models import entities as _entities  # noqa: F401


def _prepare_sqlite_path(database_url: str) -> None:
    prefix = "sqlite:///"
    if database_url.startswith(prefix) and database_url != "sqlite:///:memory:":
        Path(database_url.removeprefix(prefix)).parent.mkdir(parents=True, exist_ok=True)


def build_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    url = settings.database_url
    if url.startswith("sqlite"):
        _prepare_sqlite_path(url)
        connect_args = {"check_same_thread": False}
        if url in {"sqlite:///:memory:", "sqlite://"}:
            from sqlalchemy.pool import StaticPool

            return create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        return create_engine(url, connect_args=connect_args)

    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
    )


settings = get_settings()
engine = build_engine(settings)
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
