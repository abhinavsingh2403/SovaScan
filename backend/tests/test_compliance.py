import pytest
from sovascan.models.scan import Scan, ScanStatus
from sovascan.models.finding import Finding, Severity

def test_global_vs_scan_specific_compliance(client, db_session):
    # Setup scan 1
    scan1 = Scan(
        id="scan-1-uuid",
        target="/test/project1",
        status=ScanStatus.COMPLETED,
        scan_type="full",
    )
    # Setup scan 2
    scan2 = Scan(
        id="scan-2-uuid",
        target="/test/project2",
        status=ScanStatus.COMPLETED,
        scan_type="full",
    )
    db_session.add_all([scan1, scan2])
    db_session.commit()

    # Add findings for scan 1 (dependency category: CVE-2023-0001)
    finding1 = Finding(
        scan_id=scan1.id,
        rule_id="SOVA-CVE-001",
        title="Vulnerable dependency",
        description="Dependency CVE-2023-0001 details",
        severity=Severity.HIGH,
        category="cve",
        file_path="requirements.txt",
    )
    # Add findings for scan 2 (secrets category: AWS key)
    finding2 = Finding(
        scan_id=scan2.id,
        rule_id="SOVA-SECRET-001",
        title="AWS Access Key Leak",
        description="AWS Access Key detected",
        severity=Severity.CRITICAL,
        category="secret",
        file_path="settings.py",
    )
    db_session.add_all([finding1, finding2])
    db_session.commit()

    # 1. Test global compliance (no scan_id)
    # nist-csf has 6 controls total.
    # secret category triggers PR.AC fail.
    # cve category triggers PR.DS fail.
    # Both fail, so score should reflect 4 passed out of 6 controls.
    res_global = client.get("/api/v1/compliance/nist-csf")
    assert res_global.status_code == 200
    data_global = res_global.json()
    assert len(data_global["findings"]) == 2
    assert data_global["total_controls"] == 6
    assert data_global["failed"] == 2
    assert data_global["passed"] == 4
    assert data_global["score"] == 66.7

    # Verify controls list
    controls_map = {c["id"]: c for c in data_global["controls"]}
    assert controls_map["PR.AC"]["status"] == "failed"
    assert controls_map["PR.DS"]["status"] == "failed"
    assert controls_map["ID.AM"]["status"] == "passed"

    # 2. Test scan-specific compliance for scan1 (cve only)
    res_scan1 = client.get(f"/api/v1/compliance/nist-csf?scan_id={scan1.id}")
    assert res_scan1.status_code == 200
    data_scan1 = res_scan1.json()
    assert len(data_scan1["findings"]) == 1
    assert data_scan1["failed"] == 1 # only PR.DS fails
    assert data_scan1["passed"] == 5
    assert data_scan1["score"] == 83.3
    
    controls_map1 = {c["id"]: c for c in data_scan1["controls"]}
    assert controls_map1["PR.AC"]["status"] == "passed"
    assert controls_map1["PR.DS"]["status"] == "failed"

    # 3. Test scan-specific compliance for scan2 (secret only)
    res_scan2 = client.get(f"/api/v1/compliance/nist-csf?scan_id={scan2.id}")
    assert res_scan2.status_code == 200
    data_scan2 = res_scan2.json()
    assert len(data_scan2["findings"]) == 1
    assert data_scan2["failed"] == 1 # only PR.AC fails
    assert data_scan2["passed"] == 5
    
    controls_map2 = {c["id"]: c for c in data_scan2["controls"]}
    assert controls_map2["PR.AC"]["status"] == "failed"
    assert controls_map2["PR.DS"]["status"] == "passed"

    # 4. Test non-existent scan_id returns 404
    res_missing = client.get("/api/v1/compliance/nist-csf?scan_id=non-existent-scan-id")
    assert res_missing.status_code == 404
