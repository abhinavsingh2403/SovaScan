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
    for fw in ("pci-dss", "rbi-csf", "iso-27001"):
        resp = client.get(f"/api/v1/compliance/{fw}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == fw
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


def test_apply_fix_updates_file(client: TestClient, tmp_path: Path) -> None:
    """Test that applying an auto-fix physically modifies the file on disk."""
    # 1. Create a dummy settings file with a misconfiguration
    config_file = tmp_path / "settings.conf"
    config_file.write_text("DEBUG = True\n", encoding="utf-8")

    # 2. Trigger a scan of the temp path containing this file
    payload = {
        "target": str(tmp_path),
        "scan_type": "misconfig"
    }
    scan_resp = client.post("/api/v1/scan", json=payload)
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Retrieve findings
    findings_resp = client.get(f"/api/v1/scan/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    assert len(findings) > 0

    # Find the misconfig finding
    misconfig_finding = findings[0]
    finding_id = misconfig_finding["id"]

    # 4. Trigger auto-fix
    fix_payload = {
        "finding_id": finding_id,
        "auto_apply": True
    }
    fix_resp = client.post(f"/api/v1/fix/{finding_id}", json=fix_payload)
    assert fix_resp.status_code == 200
    assert fix_resp.json()["status"] == "applied"

    # 5. Verify the file contents changed on disk
    updated_content = config_file.read_text(encoding="utf-8")
    assert "DEBUG = False" in updated_content


def test_bulk_fix_endpoints(client: TestClient, tmp_path: Path) -> None:
    """Test bulk auto-fixing all findings in a scan and globally."""
    # 1. Create a dummy settings file with multiple misconfigurations
    config_file = tmp_path / "settings.conf"
    config_file.write_text("DEBUG = True\ndev_mode = 1\n", encoding="utf-8")

    # 2. Trigger a scan
    payload = {
        "target": str(tmp_path),
        "scan_type": "misconfig"
    }
    scan_resp = client.post("/api/v1/scan", json=payload)
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    # 3. Trigger bulk scan-specific fix-all
    fix_all_resp = client.post(f"/api/v1/scan/{scan_id}/fix-all")
    assert fix_all_resp.status_code == 200
    data = fix_all_resp.json()
    assert data["scan_id"] == scan_id
    assert data["applied_count"] > 0

    # 4. Verify file was patched
    updated_content = config_file.read_text(encoding="utf-8")
    assert "DEBUG = False" in updated_content


