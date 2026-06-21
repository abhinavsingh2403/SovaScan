"""Tests for SovaScan FastAPI endpoints."""

from pathlib import Path

from fastapi.testclient import TestClient

# A real, always-present directory to scan against now that the API route
# runs the actual ScanOrchestrator instead of a mock. The orchestrator only
# needs *a* valid path on disk — it doesn't need to find anything interesting
# for these tests, just to complete without raising.
SCAN_TARGET = str(Path(__file__).resolve().parent)


def test_health(client: TestClient) -> None:
    """Test the API health-check endpoint."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_create_scan(client: TestClient) -> None:
    """Test initiating a scan via the API."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "full",
        "options": {}
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["target"] == SCAN_TARGET
    assert data["status"] in ("completed", "running", "pending")


def test_get_scan(client: TestClient) -> None:
    """Test fetching scan status/details."""
    # First create a scan
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "full"
    }
    create_resp = client.post("/api/v1/scan", json=payload)
    scan_id = create_resp.json()["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id


def test_list_findings(client: TestClient) -> None:
    """Test listing scan findings."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "full"
    }
    create_resp = client.post("/api/v1/scan", json=payload)
    scan_id = create_resp.json()["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "total" in data


def test_get_sbom(client: TestClient) -> None:
    """Test generating SBOM for a scan."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "dependencies"
    }
    create_resp = client.post("/api/v1/scan", json=payload)
    scan_id = create_resp.json()["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}/sbom")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "cyclonedx"
    assert "packages" in data


def test_compliance_report(client: TestClient) -> None:
    """Test generating a compliance framework report."""
    resp = client.get("/api/v1/compliance/pci-dss")
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "pci-dss"
    assert "score" in data
    assert "passed" in data
    assert "failed" in data


def test_dashboard_summary(client: TestClient) -> None:
    """Test dashboard stats aggregation."""
    # Make sure at least one scan exists
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "full"
    }
    client.post("/api/v1/scan", json=payload)

    resp = client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "total_findings" in data
    assert "severity_distribution" in data
    assert "risk_score" in data


def test_create_scan_rejects_missing_path(client: TestClient) -> None:
    """A target path that doesn't exist on disk should fail clearly, not silently mock data."""
    payload = {
        "target": "/this/path/does/not/exist/anywhere",
        "scan_type": "full",
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 400


def test_create_scan_rejects_remote_url(client: TestClient) -> None:
    """Remote URL targets aren't supported yet by the orchestrator and should 400, not fake success."""
    payload = {
        "target": "https://github.com/example/repo",
        "scan_type": "full",
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 400
