"""Tests for SovaScan FastAPI endpoints."""

from fastapi.testclient import TestClient


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
        "target": "C:/Users/ss/Documents/SovaScan",
        "scan_type": "full",
        "options": {}
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["target"] == "C:/Users/ss/Documents/SovaScan"
    assert data["status"] in ("completed", "running", "pending")


def test_get_scan(client: TestClient) -> None:
    """Test fetching scan status/details."""
    # First create a scan
    payload = {
        "target": "C:/Users/ss/Documents/SovaScan",
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
        "target": "C:/Users/ss/Documents/SovaScan",
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
        "target": "C:/Users/ss/Documents/SovaScan",
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
        "target": "C:/Users/ss/Documents/SovaScan",
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
