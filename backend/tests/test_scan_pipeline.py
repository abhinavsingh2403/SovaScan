import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path
from sovascan.api.websocket import is_allowed_git_url, ScanManager
from sovascan.core.severity_scorer import normalize_severity, Severity
from sovascan.models.scan import Scan, ScanStatus
from sovascan.models.finding import Finding

def test_git_url_protocol_validation():
    # Valid HTTP/HTTPS protocols
    assert is_allowed_git_url("https://github.com/abhinavsingh2403/SovaScan") is True
    assert is_allowed_git_url("http://github.com/abhinavsingh2403/SovaScan") is True

    # Disallowed protocols or formats
    assert is_allowed_git_url("file:///etc/passwd") is False
    assert is_allowed_git_url("ssh://git@github.com/user/repo") is False
    assert is_allowed_git_url("git@github.com:user/repo.git") is False
    assert is_allowed_git_url("https://github.com/user/repo containing spaces") is False

def test_severity_normalization():
    assert normalize_severity("CRITICAL") == Severity.CRITICAL
    assert normalize_severity("crit") == Severity.CRITICAL
    assert normalize_severity("high") == Severity.HIGH
    assert normalize_severity("h") == Severity.HIGH
    assert normalize_severity("moderate") == Severity.MEDIUM
    assert normalize_severity("medium") == Severity.MEDIUM
    assert normalize_severity("low") == Severity.LOW
    assert normalize_severity("l") == Severity.LOW
    assert normalize_severity("info") == Severity.INFO
    assert normalize_severity("unknown_severity") == Severity.INFO
    assert normalize_severity(None) == Severity.INFO

@patch("subprocess.run")
def test_scan_failure_metadata_saving(mock_run, client, db_session):
    # Mock git clone error
    mock_run.return_value = MagicMock(returncode=1, stderr="Remote repository connection timeout", stdout="")

    # Create scan record
    scan = Scan(
        target="https://github.com/abhinavsingh2403/invalid-repo",
        status=ScanStatus.PENDING,
        scan_type="full"
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    manager = ScanManager()
    # Runs the synchronous scan block in worker thread
    manager._execute_scan_sync(
        scan_id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        options=None
    )

    db_session.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.metadata_json is not None
    meta = json.loads(scan.metadata_json)
    assert "error" in meta
    assert "failed_at" in meta
    assert "Git clone failed" in meta["error"]

@patch("sovascan.core.orchestrator.ScanOrchestrator.run_scan")
def test_finding_deduplication_and_sbom_cache(mock_run_scan, client, db_session):
    # Setup mock Orchestrator ScanResult
    mock_scored = MagicMock()
    mock_scored.id = "SOVA-SECRET-001"
    mock_scored.title = "AWS Access Key Leak"
    mock_scored.description = "AWS key leak in settings.py"
    mock_scored.severity = Severity.CRITICAL
    mock_scored.category = "secret"
    mock_scored.file_path = "settings.py"
    mock_scored.line_number = 12
    mock_scored.evidence = "AKIA1234567890"
    mock_scored.remediation = "Rotate key"
    mock_scored.cvss_score = 9.5

    mock_result = MagicMock()
    # 2 duplicate findings in pipeline
    mock_result.findings = [mock_scored, mock_scored]
    mock_result.sbom = {
        "format": "cyclonedx",
        "packages": [
            {"name": "fastapi", "version": "0.104.0", "ecosystem": "pypi"}
        ]
    }

    mock_run_scan.return_value = mock_result

    # Create scan record
    scan = Scan(
        target=str(Path(__file__).parent.parent), # Use directory containing test files
        status=ScanStatus.PENDING,
        scan_type="dependencies"
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    manager = ScanManager()
    manager._execute_scan_sync(
        scan_id=scan.id,
        target=scan.target,
        scan_type="dependencies",
        options=None
    )

    # Reload scan
    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    # Should only save 1 finding (deduplicated)
    assert scan.total_findings == 1
    
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == 1

    # Verify cached SBOM
    assert scan.metadata_json is not None
    meta = json.loads(scan.metadata_json)
    assert "sbom" in meta
    assert meta["sbom"]["packages"][0]["name"] == "fastapi"
