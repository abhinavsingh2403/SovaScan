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
    from sovascan.models import api_key as _api_key_mod  # noqa: F401
    from sovascan.models import finding as _finding_mod  # noqa: F401
    from sovascan.models import scan as _scan_mod  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created / verified")

    # Seed default developer keys if they do not exist
    from sovascan.models.api_key import ApiKey
    db = SessionLocal()
    try:
        import hashlib
        default_keys_data = [
            ("1", "GitHub-CI-Prod", "ss_live_mock_github_ci_key_abcde"),
            ("2", "Local-Developer-Key", "ss_live_mock_local_dev_key_12345")
        ]
        for key_id, name, raw_key in default_keys_data:
            key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            existing = db.query(ApiKey).filter(ApiKey.id == key_id).first()
            if not existing:
                dev_key = ApiKey(
                    id=key_id,
                    name=name,
                    key_hash=key_hash,
                    is_active=True
                )
                db.add(dev_key)
                logger.info(f"Seeded API Key: {name}")
            else:
                existing.name = name
                existing.key_hash = key_hash
                existing.is_active = True
        db.commit()
    except Exception as e:
        logger.warning(f"Failed to seed default API keys: {e}")
        db.rollback()
    finally:
        db.close()


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
