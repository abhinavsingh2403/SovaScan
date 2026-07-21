"""Tests for SovaScan FastAPI endpoints."""

import time
from pathlib import Path

from fastapi.testclient import TestClient

# A real, always-present directory to scan against now that the API route
# runs the actual ScanOrchestrator instead of a mock. The orchestrator only
# needs *a* valid path on disk — it doesn't need to find anything interesting
# for these tests, just to complete without raising.
SCAN_TARGET = str(Path(__file__).resolve().parent)


def _create_scan_and_wait(client: TestClient, payload: dict, timeout: float = 30.0) -> dict:
    """Helper to initiate a scan, verify 202 Accepted, and poll until completion."""
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 202
    data = resp.json()
    scan_id = data["id"]

    start_time = time.time()
    while time.time() - start_time < timeout:
        get_resp = client.get(f"/api/v1/scan/{scan_id}")
        assert get_resp.status_code == 200
        scan_data = get_resp.json()
        if scan_data["status"] in ("completed", "failed"):
            return scan_data
        time.sleep(0.1)

    raise TimeoutError(f"Scan {scan_id} did not complete within {timeout} seconds")


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
    assert resp.status_code == 202
    data = resp.json()
    assert "id" in data
    assert data["target"] == SCAN_TARGET
    assert data["status"] == "pending"


def test_get_scan(client: TestClient) -> None:
    """Test fetching scan status/details after completion."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "secrets"
    }
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == scan_id
    assert data["status"] == "completed"


def test_list_findings(client: TestClient) -> None:
    """Test listing scan findings after completed scan."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "secrets"
    }
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "total" in data


def test_get_sbom(client: TestClient) -> None:
    """Test generating SBOM for a completed scan."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "dependencies"
    }
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    resp = client.get(f"/api/v1/scan/{scan_id}/sbom")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "cyclonedx"
    assert "packages" in data


def test_compliance_report(client: TestClient) -> None:
    """Test generating a compliance framework report."""
    for fw in ("nist-csf", "soc-2", "owasp-10"):
        resp = client.get(f"/api/v1/compliance/{fw}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == fw
        assert "score" in data
        assert "passed" in data
        assert "failed" in data


def test_dashboard_summary(client: TestClient) -> None:
    """Test dashboard stats aggregation."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "secrets"
    }
    _create_scan_and_wait(client, payload)

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


def test_create_scan_accepts_remote_url(client: TestClient) -> None:
    """Remote URL targets are supported by the orchestrator and should return 202."""
    payload = {
        "target": "https://github.com/example/repo",
        "scan_type": "full",
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 202


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
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

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


def test_apply_fix_custom_replacement(client: TestClient, tmp_path: Path) -> None:
    """Test that a custom_replacement value is applied on disk and reflected in the patch."""
    # 1. Create a config file with a misconfiguration
    config_file = tmp_path / "settings.conf"
    config_file.write_text("DEBUG = True\n", encoding="utf-8")

    # 2. Trigger a misconfig scan
    payload = {
        "target": str(tmp_path),
        "scan_type": "misconfig"
    }
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    # 3. Retrieve findings
    findings_resp = client.get(f"/api/v1/scan/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    assert len(findings) > 0

    misconfig_finding = findings[0]
    finding_id = misconfig_finding["id"]

    # 4. Apply fix with custom_replacement
    fix_payload = {
        "finding_id": finding_id,
        "auto_apply": True,
        "custom_replacement": "DEBUG = False  # Custom Fix Applied",
    }
    fix_resp = client.post(f"/api/v1/fix/{finding_id}", json=fix_payload)
    assert fix_resp.status_code == 200
    fix_data = fix_resp.json()
    assert fix_data["status"] == "applied"
    assert "DEBUG = False  # Custom Fix Applied" in fix_data["patch"]

    # 5. Verify the file on disk contains the custom text
    updated_content = config_file.read_text(encoding="utf-8")
    assert "DEBUG = False  # Custom Fix Applied" in updated_content


def test_apply_fix_context_replacement(client: TestClient, tmp_path: Path) -> None:
    """Test that applying a fix with context_replacement updates the file block on disk."""
    # 1. Create a config file with a multi-line settings content
    config_file = tmp_path / "settings.conf"
    original_lines = [
        "PORT = 8080\n",
        "DEBUG = True\n",
        "CORS = '*'\n"
    ]
    config_file.write_text("".join(original_lines), encoding="utf-8")

    # 2. Trigger a misconfig scan
    payload = {
        "target": str(tmp_path),
        "scan_type": "misconfig"
    }
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    # 3. Retrieve findings
    findings_resp = client.get(f"/api/v1/scan/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    assert len(findings) > 0
    
    # Find a debug-mode finding (SOVA-WEB-001)
    target_finding = None
    for f in findings:
        if f["rule_id"] == "SOVA-WEB-001":
            target_finding = f
            break
    assert target_finding is not None
    finding_id = target_finding["id"]

    # 4. Fetch context first to get start/end lines
    context_resp = client.get(f"/api/v1/findings/{finding_id}/context")
    assert context_resp.status_code == 200
    context_data = context_resp.json()
    start_line = context_data["start_line"]
    end_line = context_data["end_line"]

    # 5. Apply context replacement
    replacement_text = "PORT = 8080\nDEBUG = False  # Changed Context\nCORS = '*'\n"
    fix_payload = {
        "finding_id": finding_id,
        "auto_apply": True,
        "context_replacement": replacement_text,
        "context_start_line": start_line,
        "context_end_line": end_line
    }
    fix_resp = client.post(f"/api/v1/fix/{finding_id}", json=fix_payload)
    assert fix_resp.status_code == 200

    # 6. Verify the file contents changed on disk to our custom block
    updated_content = config_file.read_text(encoding="utf-8")
    assert "DEBUG = False  # Changed Context" in updated_content


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
    scan_data = _create_scan_and_wait(client, payload)
    scan_id = scan_data["id"]

    # 3. Trigger bulk scan-specific fix-all
    fix_all_resp = client.post(f"/api/v1/scan/{scan_id}/fix-all")
    assert fix_all_resp.status_code == 200
    data = fix_all_resp.json()
    assert data["scan_id"] == scan_id
    assert data["applied_count"] > 0

    # 4. Verify file was patched
    updated_content = config_file.read_text(encoding="utf-8")
    assert "DEBUG = False" in updated_content


def test_sast_scanner_graceful_fallback() -> None:
    """Verify that SASTScanner behaves gracefully even if tools are missing."""
    from sovascan.core.sast_scanner import SASTScanner
    scanner = SASTScanner()
    # Should scan without raising even if semgrep/bandit are not present
    findings = scanner.scan(SCAN_TARGET)
    assert isinstance(findings, list)


def test_git_history_scanner_non_repo(tmp_path: Path) -> None:
    """Verify that GitHistoryScanner exits gracefully for non-git paths."""
    from sovascan.core.git_history_scanner import GitHistoryScanner
    scanner = GitHistoryScanner()
    findings = scanner.scan(tmp_path)
    assert findings == []


def test_websocket_connection(client: TestClient) -> None:
    """Test WebSocket connection and message stream."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "secrets"
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 202
    scan_id = resp.json()["id"]

    # Open WebSocket connection using FastAPI TestClient
    with client.websocket_connect(f"/api/v1/scan/{scan_id}/ws?api_key=ss_live_mock_local_dev_key_12345") as ws:
        # First message is status_change event
        msg = ws.receive_json()
        assert msg["scan_id"] == scan_id
        assert msg["type"] in ("status_change", "progress", "finding_discovered", "scan_complete")

        # Poll status until complete
        start_time = time.time()
        completed = False
        while time.time() - start_time < 10.0:
            try:
                msg = ws.receive_json()
                if msg["type"] == "scan_complete":
                    assert msg["status"] == "completed"
                    completed = True
                    break
            except Exception:
                break

        # In case the scan was fast and completed immediately
        if not completed:
            db_resp = client.get(f"/api/v1/scan/{scan_id}")
            assert db_resp.json()["status"] in ("completed", "failed")


def test_cancel_scan_endpoint(client: TestClient) -> None:
    """Test cancelling an in-progress scan via POST /api/v1/scan/{scan_id}/cancel."""
    payload = {
        "target": SCAN_TARGET,
        "scan_type": "full"
    }
    resp = client.post("/api/v1/scan", json=payload)
    assert resp.status_code == 202
    scan_id = resp.json()["id"]

    # Post cancellation request
    cancel_resp = client.post(f"/api/v1/scan/{scan_id}/cancel")
    assert cancel_resp.status_code == 200
    cancel_data = cancel_resp.json()
    assert cancel_data["scan_id"] == scan_id
    assert cancel_data["status"] in ("cancelled", "completed", "failed")

    # Verify DB status
    db_resp = client.get(f"/api/v1/scan/{scan_id}")
    assert db_resp.status_code == 200
    assert db_resp.json()["status"] in ("failed", "completed")
