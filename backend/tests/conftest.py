"""Pytest fixtures and configuration."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sovascan.models import Base
from sovascan.models.base import get_db
from sovascan.server import app

# Use file-based SQLite for testing to avoid connection-sharing table loss
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_temp.db"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)


@pytest.fixture(name="db_session")
def fixture_db_session():
    """Create in-memory SQLite database session."""
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    # Seed default key for testing authentication
    import hashlib
    from sovascan.models.api_key import ApiKey
    default_key = "ss_live_mock_local_dev_key_12345"
    key_hash = hashlib.sha256(default_key.encode("utf-8")).hexdigest()
    dev_key = ApiKey(
        id="2",
        name="Local-Developer-Key",
        key_hash=key_hash,
        is_active=True
    )
    db.add(dev_key)
    db.commit()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(name="client")
def fixture_client(db_session):
    """FastAPI test client with database dependency override."""
    from sovascan.api import websocket
    original_session_maker = websocket.SessionMaker
    # Override SessionMaker to use test database for background threads
    websocket.SessionMaker = TestingSessionLocal

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        test_client.headers = {"X-API-Key": "ss_live_mock_local_dev_key_12345"}
        yield test_client
    app.dependency_overrides.clear()
    websocket.SessionMaker = original_session_maker
