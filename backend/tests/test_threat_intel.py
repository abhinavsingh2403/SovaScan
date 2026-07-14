import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from sovascan.core.threat_intel import ThreatIntelEnricher, ThreatIntelRecord
from sovascan.models.scan import Scan, ScanStatus
from sovascan.models.finding import Finding, Severity

def test_priority_calculation():
    enricher = ThreatIntelEnricher()

    # Case 1: Immediate due to known_exploited
    with patch.object(enricher, "_fetch_kev", return_value={"CVE-2023-0001"}):
        with patch.object(enricher, "_fetch_epss", return_value={}):
            records = enricher.enrich_cves(["CVE-2023-0001"])
            rec = records["CVE-2023-0001"]
            assert rec.priority == "immediate"
            assert "Patch within 24 hours" in rec.remediation_urgency

    # Case 2: Immediate due to high epss
    with patch.object(enricher, "_fetch_kev", return_value=set()):
        with patch.object(enricher, "_fetch_epss", return_value={"CVE-2023-0002": {"epss": 0.85, "percentile": 0.99}}):
            records = enricher.enrich_cves(["CVE-2023-0002"])
            rec = records["CVE-2023-0002"]
            assert rec.priority == "immediate"

    # Case 3: High due to epss >= 0.4
    with patch.object(enricher, "_fetch_kev", return_value=set()):
        with patch.object(enricher, "_fetch_epss", return_value={"CVE-2023-0003": {"epss": 0.45, "percentile": 0.90}}):
            records = enricher.enrich_cves(["CVE-2023-0003"])
            rec = records["CVE-2023-0003"]
            assert rec.priority == "high"
            assert "Patch within 7 days" in rec.remediation_urgency

    # Case 4: High due to cvss >= 9.0
    with patch.object(enricher, "_fetch_kev", return_value=set()):
        with patch.object(enricher, "_fetch_epss", return_value={}):
            records = enricher.enrich_cves(["CVE-2023-0004"], cvss_scores={"CVE-2023-0004": 9.5})
            rec = records["CVE-2023-0004"]
            assert rec.priority == "high"

    # Case 5: Medium due to cvss >= 7.0
    with patch.object(enricher, "_fetch_kev", return_value=set()):
        with patch.object(enricher, "_fetch_epss", return_value={}):
            records = enricher.enrich_cves(["CVE-2023-0005"], cvss_scores={"CVE-2023-0005": 7.5})
            rec = records["CVE-2023-0005"]
            assert rec.priority == "medium"
            assert "Patch within 30 days" in rec.remediation_urgency

    # Case 6: Monitor
    with patch.object(enricher, "_fetch_kev", return_value=set()):
        with patch.object(enricher, "_fetch_epss", return_value={}):
            records = enricher.enrich_cves(["CVE-2023-0006"])
            rec = records["CVE-2023-0006"]
            assert rec.priority == "monitor"
            assert "Monitor and patch" in rec.remediation_urgency

@patch("httpx.Client.get")
def test_enrich_cves_success(mock_get):
    # Mock CISA KEV response
    mock_cisa_res = MagicMock()
    mock_cisa_res.status_code = 200
    mock_cisa_res.json.return_value = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-0001",
                "vendorProject": "Test Vendor",
                "product": "Test Product",
                "shortDescription": "Active exploitation summary."
            }
        ]
    }

    # Mock EPSS response
    mock_epss_res = MagicMock()
    mock_epss_res.status_code = 200
    mock_epss_res.json.return_value = {
        "data": [
            {
                "cve": "CVE-2023-0001",
                "epss": "0.923",
                "percentile": "0.991"
            },
            {
                "cve": "CVE-2023-0002",
                "epss": "0.125",
                "percentile": "0.620"
            }
        ]
    }

    # Alternating mock calls: first KEV, second EPSS
    mock_get.side_effect = [mock_cisa_res, mock_epss_res]

    enricher = ThreatIntelEnricher()
    records = enricher.enrich_cves(["CVE-2023-0001", "CVE-2023-0002"])

    assert len(records) == 2
    assert "CVE-2023-0001" in records
    assert "CVE-2023-0002" in records

    rec1 = records["CVE-2023-0001"]
    assert rec1.known_exploited is True
    assert rec1.epss_score == 0.923
    assert rec1.priority == "immediate"
    assert "CISA-KEV" in rec1.sources

    rec2 = records["CVE-2023-0002"]
    assert rec2.known_exploited is False
    assert rec2.epss_score == 0.125
    assert rec2.priority == "monitor"
    assert "EPSS" in rec2.sources

@patch("httpx.Client.get")
def test_enrich_cves_network_failure(mock_get):
    # Setup mock exceptions
    mock_get.side_effect = Exception("Network timeout")

    enricher = ThreatIntelEnricher()
    records = enricher.enrich_cves(["CVE-2023-9999"])

    # Should gracefully return records with fallbacks
    assert len(records) == 1
    assert "CVE-2023-9999" in records
    rec = records["CVE-2023-9999"]
    assert rec.known_exploited is False
    assert rec.epss_score is None
    assert rec.priority == "monitor"
    assert len(rec.sources) == 1
    assert rec.sources == ["OSV"]

def test_api_endpoint_threat_intel(client, db_session):
    # Create sample scan in db
    db_scan = Scan(
        target="/test/project",
        status=ScanStatus.COMPLETED,
        scan_type="full",
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0
    )
    db_session.add(db_scan)
    db_session.commit()
    db_session.refresh(db_scan)

    # Add CVE findings
    finding1 = Finding(
        scan_id=db_scan.id,
        rule_id="SOVA-CVE-001",
        title="Vulnerability in requests",
        description="Vulnerable dependency requests",
        severity=Severity.HIGH,
        category="cve",
        file_path="requirements.txt",
        cve_id="CVE-2023-0001",
        cvss_score=9.2
    )
    # Add non-CVE findings
    finding2 = Finding(
        scan_id=db_scan.id,
        rule_id="SOVA-SECRET-001",
        title="AWS Secret Key",
        description="Hardcoded AWS Access Key detected in settings.py",
        severity=Severity.CRITICAL,
        category="secret",
        file_path="settings.py"
    )
    db_session.add_all([finding1, finding2])
    db_session.commit()

    with patch.object(ThreatIntelEnricher, "_fetch_kev", return_value=set()):
        with patch.object(ThreatIntelEnricher, "_fetch_epss", return_value={"CVE-2023-0001": {"epss": 0.15, "percentile": 0.55}}):
            res = client.get(f"/api/v1/threat-intel/scan/{db_scan.id}")
            assert res.status_code == 200
            data = res.json()
            assert data["scan_id"] == str(db_scan.id)
            assert data["total_cves"] == 1
            assert data["records"][0]["cve_id"] == "CVE-2023-0001"
            assert data["records"][0]["epss_score"] == 0.15
            assert data["records"][0]["priority"] == "high" # Boosted by CVSS >= 9.0
