import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sovascan.models.api_key import ApiKey

def test_api_key_authentication_required(client: TestClient) -> None:
    """Verify that requests without a valid X-API-Key header fail with 401 Unauthorized."""
    # Temporarily remove default header configured in client fixture
    old_headers = client.headers.copy()
    client.headers.clear()

    try:
        # Request findings
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401
        assert "Provide X-API-Key in header" in resp.json()["detail"]

        # Request with invalid key
        client.headers = {"X-API-Key": "ss_live_invalidkeyhere"}
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401
        assert "Invalid or revoked API Key" in resp.json()["detail"]
    finally:
        client.headers = old_headers


def test_api_key_crud_lifecycle(client: TestClient, db_session: Session) -> None:
    """Verify that API Keys can be generated, used, listed, and deleted successfully."""
    # 1. Create key
    resp = client.post("/api/v1/auth/api-keys", json={"name": "Production-Integration"})
    assert resp.status_code == 200
    data = resp.json()
    assert "key" in data
    assert data["name"] == "Production-Integration"
    plaintext_key = data["key"]
    key_id = data["id"]

    # 2. Verify key hash is in database but plaintext key is NOT
    db_key = db_session.query(ApiKey).filter(ApiKey.id == key_id).first()
    assert db_key is not None
    assert db_key.key_hash != plaintext_key

    # 3. List keys - assert created key is returned but does NOT show plaintext key
    list_resp = client.get("/api/v1/auth/api-keys")
    assert list_resp.status_code == 200
    keys_list = list_resp.json()
    assert len(keys_list) >= 2 # Seeded + new key
    matching_key = next((k for k in keys_list if k["id"] == key_id), None)
    assert matching_key is not None
    assert "key" not in matching_key

    # 4. Use newly generated key to call protected endpoint successfully
    old_headers = client.headers.copy()
    client.headers = {"X-API-Key": plaintext_key}
    try:
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 200
    finally:
        client.headers = old_headers

    # 5. Revoke/delete the key
    del_resp = client.delete(f"/api/v1/auth/api-keys/{key_id}")
    assert del_resp.status_code == 200

    # 6. Verify key no longer works
    client.headers = {"X-API-Key": plaintext_key}
    try:
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401
    finally:
        client.headers = old_headers
