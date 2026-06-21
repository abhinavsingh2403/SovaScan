"""SQLAlchemy database setup: engine, session, and base model."""

import logging
from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from sovascan.config import get_settings

logger = logging.getLogger("sovascan.models")


class Base(DeclarativeBase):
    """Declarative base class for all SQLAlchemy models."""

    pass


def _build_engine() -> Any:
    """Build a SQLAlchemy engine from application settings.

    Returns:
        Engine: A configured SQLAlchemy engine.
    """
    settings = get_settings()
    url = settings.database_url_for_engine
    connect_args: dict[str, Any] = {}

    # SQLite-specific: allow multi-thread access
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        url,
        connect_args=connect_args,
        echo=settings.DEBUG,
        pool_pre_ping=True,
    )
    return engine


engine = _build_engine()

SessionLocal: sessionmaker[Session] = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def init_db() -> None:
    """Create all database tables defined by the Base metadata.

    This is safe to call multiple times — SQLAlchemy's ``create_all``
    is a no-op for tables that already exist.
    """
    # Import models so they register with Base.metadata
    from sovascan.models import finding as _finding_mod  # noqa: F401
    from sovascan.models import scan as _scan_mod  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created / verified")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session.

    The session is automatically closed after the request completes,
    regardless of whether an exception occurred.

    Yields:
        Session: An active SQLAlchemy session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
