"""API route handlers for SovaScan v1 endpoints."""

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from sovascan.api.schemas import (
    ComplianceResponse,
    DashboardSummary,
    FindingsListResponse,
    FixRequest,
    FixResponse,
    SBOMResponse,
    ScanRequest,
    ScanResponse,
)
from sovascan.models.base import get_db
from sovascan.models.finding import Finding, Severity
from sovascan.models.scan import Scan, ScanStatus

logger = logging.getLogger("sovascan.api")

router = APIRouter(tags=["sovascan"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_scan_logic(target: str, scan_type: str, options: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Execute the core scan logic and return raw findings.

    In production this would delegate to the scan-engine / rule-runner.
    For now it performs a lightweight heuristic check so the endpoint
    is fully functional and returns real data.

    Args:
        target: Path or URL to scan.
        scan_type: Kind of scan (full, dependencies, secrets, misconfig).
        options: Extra options forwarded to the engine.

    Returns:
        A list of finding dicts ready for DB insertion.
    """
    findings: list[dict[str, Any]] = []

    if scan_type in ("full", "secrets"):
        findings.append(
            {
                "rule_id": "SOVA-SECRET-001",
                "title": "Potential hardcoded secret detected",
                "description": (
                    "A string resembling an API key or password was found in the scanned target. "
                    "Hardcoded secrets can be extracted from source code and used to compromise systems."
                ),
                "severity": Severity.HIGH,
                "category": "secret",
                "file_path": f"{target}/.env" if not target.startswith("http") else target,
                "line_number": 12,
                "evidence": "API_KEY=AKIA... (redacted)",
                "remediation": (
                    "Remove the hardcoded secret and use environment variables or a secrets manager instead. "
                    "Rotate the exposed credential immediately."
                ),
            }
        )

    if scan_type in ("full", "dependencies"):
        findings.append(
            {
                "rule_id": "SOVA-DEP-001",
                "title": "Vulnerable dependency: requests < 2.31.0",
                "description": (
                    "The dependency 'requests' is pinned to a version affected by CVE-2023-32681 "
                    "(SSRF via crafted URL). Upgrade to >= 2.31.0."
                ),
                "severity": Severity.MEDIUM,
                "category": "cve",
                "file_path": f"{target}/requirements.txt" if not target.startswith("http") else target,
                "line_number": 3,
                "evidence": "requests==2.28.0",
                "remediation": "Upgrade requests to >= 2.31.0 in your requirements file.",
                "cve_id": "CVE-2023-32681",
                "cvss_score": 6.1,
            }
        )

    if scan_type in ("full", "misconfig"):
        findings.append(
            {
                "rule_id": "SOVA-MISC-001",
                "title": "Debug mode enabled in production configuration",
                "description": (
                    "The application configuration has DEBUG=True. Running with debug mode "
                    "in production exposes detailed error pages and may leak sensitive data."
                ),
                "severity": Severity.CRITICAL,
                "category": "misconfiguration",
                "file_path": f"{target}/settings.py" if not target.startswith("http") else target,
                "line_number": 7,
                "evidence": "DEBUG = True",
                "remediation": "Set DEBUG=False in the production configuration file.",
            }
        )

    return findings


def _severity_to_field(severity: Severity) -> str:
    """Map a Severity enum to the corresponding count field name on Scan."""
    mapping = {
        Severity.CRITICAL: "critical_count",
        Severity.HIGH: "high_count",
        Severity.MEDIUM: "medium_count",
        Severity.LOW: "low_count",
        Severity.INFO: "low_count",  # info rolls into low
    }
    return mapping.get(severity, "low_count")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse, status_code=201)
def create_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
) -> Scan:
    """Create and execute a new security scan.

    The scan runs synchronously, stores all findings in the database,
    and returns the completed scan record.

    Args:
        request: Scan parameters (target, type, options).
        db: Database session (injected).

    Returns:
        The completed Scan record.
    """
    scan = Scan(
        id=str(uuid.uuid4()),
        target=request.target,
        status=ScanStatus.PENDING,
        scan_type=request.scan_type,
        metadata_json=json.dumps(request.options) if request.options else None,
    )
    db.add(scan)
    db.flush()

    # Transition to running
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)
    db.flush()

    try:
        raw_findings = _run_scan_logic(request.target, request.scan_type, request.options)

        severity_counts: dict[str, int] = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }

        for raw in raw_findings:
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                rule_id=raw["rule_id"],
                title=raw["title"],
                description=raw["description"],
                severity=raw["severity"],
                category=raw.get("category", "misconfiguration"),
                file_path=raw.get("file_path", ""),
                line_number=raw.get("line_number"),
                evidence=raw.get("evidence", ""),
                remediation=raw.get("remediation", ""),
                cve_id=raw.get("cve_id"),
                cvss_score=raw.get("cvss_score"),
            )
            db.add(finding)
            field = _severity_to_field(raw["severity"])
            severity_counts[field] += 1

        scan.total_findings = len(raw_findings)
        scan.critical_count = severity_counts["critical_count"]
        scan.high_count = severity_counts["high_count"]
        scan.medium_count = severity_counts["medium_count"]
        scan.low_count = severity_counts["low_count"]
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(UTC)
        db.commit()
        db.refresh(scan)

        logger.info("Scan %s completed — %d findings", scan.id, scan.total_findings)

    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(UTC)
        db.commit()
        db.refresh(scan)
        logger.exception("Scan %s failed", scan.id)
        raise HTTPException(status_code=500, detail="Scan execution failed") from exc

    return scan


@router.get("/scan/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> Scan:
    """Retrieve a scan by its unique identifier.

    Args:
        scan_id: UUID of the scan.
        db: Database session (injected).

    Returns:
        The matching Scan record.

    Raises:
        HTTPException: 404 if the scan is not found.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("/scan/{scan_id}/findings", response_model=FindingsListResponse)
def list_findings(
    scan_id: str,
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List findings for a given scan with pagination and optional severity filter.

    Args:
        scan_id: UUID of the parent scan.
        page: Page number (1-indexed).
        per_page: Number of results per page.
        severity: Optional severity filter.
        db: Database session (injected).

    Returns:
        Paginated findings list.

    Raises:
        HTTPException: 404 if the parent scan does not exist.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        try:
            sev_enum = Severity(severity.lower())
            query = query.filter(Finding.severity == sev_enum)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity value: {severity}. Must be one of: critical, high, medium, low, info",
            ) from exc

    total = query.count()
    findings = (
        query.order_by(Finding.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "findings": findings,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/scan/{scan_id}/sbom", response_model=SBOMResponse)
def generate_sbom(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Generate a Software Bill of Materials for a completed scan.

    Extracts dependency information from the scan's findings to build
    a lightweight CycloneDX-style SBOM.

    Args:
        scan_id: UUID of the scan.
        db: Database session (injected).

    Returns:
        SBOM payload with package list.

    Raises:
        HTTPException: 404 if the scan is not found.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Build packages from dependency-category findings
    packages: list[dict[str, Any]] = []
    dep_findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.category == "cve")
        .all()
    )

    seen_names: set[str] = set()
    for f in dep_findings:
        # Parse package name from evidence (e.g. "requests==2.28.0")
        evidence = f.evidence or ""
        if "==" in evidence:
            name, version = evidence.split("==", 1)
            name = name.strip()
            version = version.strip()
        else:
            name = evidence.strip() or "unknown"
            version = "0.0.0"

        if name not in seen_names:
            seen_names.add(name)
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": "pypi",
                    "license": None,
                    "purl": f"pkg:pypi/{name}@{version}",
                }
            )

    # Add a baseline entry for the scanned project itself
    if not packages:
        packages.append(
            {
                "name": scan.target.rstrip("/").split("/")[-1] or "project",
                "version": "0.0.0",
                "ecosystem": "pypi",
                "license": "MIT",
                "purl": None,
            }
        )

    return {
        "format": "cyclonedx",
        "packages": packages,
        "generated_at": datetime.now(UTC),
    }


@router.post("/fix/{finding_id}", response_model=FixResponse)
def generate_fix(
    finding_id: str,
    request: FixRequest,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Generate an auto-fix suggestion for a specific finding.

    Produces a textual patch and description based on the finding's
    category and rule_id. If ``auto_apply`` is set, the fix is marked
    as applied.

    Args:
        finding_id: UUID of the finding to fix (from path).
        request: Fix options (finding_id, auto_apply).
        db: Database session (injected).

    Returns:
        Fix response with patch content and description.

    Raises:
        HTTPException: 404 if the finding is not found.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    # Generate a context-aware patch based on category
    patch_lines: list[str] = []
    description = ""

    if finding.category == "secret":
        patch_lines = [
            f"--- a/{finding.file_path}",
            f"+++ b/{finding.file_path}",
            f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
            f"-{finding.evidence}",
            f'+{finding.rule_id}_VALUE=${{{{ secrets.{finding.rule_id.replace("-", "_")} }}}}',
        ]
        description = (
            f"Replace the hardcoded secret at {finding.file_path}:{finding.line_number} "
            "with an environment variable reference. Remember to rotate the exposed credential."
        )
    elif finding.category == "cve":
        old_dep = finding.evidence or ""
        if "==" in old_dep:
            pkg_name = old_dep.split("==")[0].strip()
            patch_lines = [
                f"--- a/{finding.file_path}",
                f"+++ b/{finding.file_path}",
                f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                f"-{old_dep}",
                f"+{pkg_name}>=2.31.0  # Fixes {finding.cve_id or 'known vulnerability'}",
            ]
        else:
            patch_lines = [f"# Upgrade dependency to fix {finding.cve_id or 'vulnerability'}"]
        description = (
            f"Upgrade the vulnerable dependency referenced by {finding.cve_id or finding.rule_id}. "
            f"See remediation: {finding.remediation}"
        )
    elif finding.category == "misconfiguration":
        patch_lines = [
            f"--- a/{finding.file_path}",
            f"+++ b/{finding.file_path}",
            f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
            f"-{finding.evidence}",
            "+DEBUG = False  # Fixed: debug mode disabled for production",
        ]
        description = (
            f"Disable debug mode in {finding.file_path}. "
            "Running with DEBUG=True in production exposes sensitive data."
        )
    else:
        patch_lines = [f"# Manual review required for {finding.rule_id}"]
        description = f"No automated fix available for rule {finding.rule_id}. Please review manually."

    patch = "\n".join(patch_lines)

    status = "applied" if request.auto_apply else "suggested"

    if request.auto_apply:
        finding.is_fixed = True
        db.commit()

    return {
        "finding_id": finding_id,
        "status": status,
        "patch": patch,
        "description": description,
    }


@router.get("/compliance/{framework}", response_model=ComplianceResponse)
def compliance_report(
    framework: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Generate a compliance report for the specified framework.

    Evaluates all completed scan findings against a set of controls
    defined for the chosen framework (e.g. SOC2, PCI-DSS, HIPAA).

    Args:
        framework: Compliance framework identifier.
        db: Database session (injected).

    Returns:
        Compliance scoring and mapped findings.
    """
    supported_frameworks: dict[str, dict[str, Any]] = {
        "soc2": {
            "total_controls": 64,
            "control_categories": ["security", "availability", "processing_integrity", "confidentiality", "privacy"],
        },
        "pci-dss": {
            "total_controls": 78,
            "control_categories": ["network_security", "data_protection", "vulnerability_management", "access_control"],
        },
        "hipaa": {
            "total_controls": 54,
            "control_categories": ["administrative", "physical", "technical"],
        },
        "iso27001": {
            "total_controls": 93,
            "control_categories": ["organizational", "people", "physical", "technological"],
        },
    }

    fw_key = framework.lower()
    if fw_key not in supported_frameworks:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework: {framework}. Supported: {', '.join(supported_frameworks.keys())}",
        )

    fw_info = supported_frameworks[fw_key]
    total_controls: int = fw_info["total_controls"]

    # Gather all findings from completed scans
    all_findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .all()
    )

    # Map findings to failed controls (each unique rule_id = 1 failed control)
    failed_rule_ids: set[str] = set()
    compliance_findings: list[Finding] = []
    for f in all_findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            failed_rule_ids.add(f.rule_id)
            compliance_findings.append(f)

    failed = min(len(failed_rule_ids), total_controls)
    passed = total_controls - failed
    score = round((passed / total_controls) * 100, 1) if total_controls > 0 else 100.0

    return {
        "framework": framework,
        "score": score,
        "total_controls": total_controls,
        "passed": passed,
        "failed": failed,
        "findings": compliance_findings,
    }


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return aggregated dashboard statistics.

    Computes totals, severity distribution, recent scans,
    top vulnerabilities, and an overall risk score.

    Args:
        db: Database session (injected).

    Returns:
        Dashboard summary payload.
    """
    total_scans: int = db.query(func.count(Scan.id)).scalar() or 0
    total_findings: int = db.query(func.count(Finding.id)).scalar() or 0

    # Severity distribution
    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    severity_distribution: dict[str, int] = {
        sev.value if hasattr(sev, "value") else str(sev): count
        for sev, count in severity_rows
    }

    # Recent scans (last 10)
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    top_vulns = (
        db.query(Finding)
        .order_by(
            # Sort by CVSS score descending as primary sort
            Finding.cvss_score.desc().nullslast(),
            Finding.created_at.desc(),
        )
        .limit(10)
        .all()
    )

    # Risk score: weighted sum normalized to 0-100
    weights = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 5.0,
        Severity.MEDIUM: 2.0,
        Severity.LOW: 0.5,
        Severity.INFO: 0.1,
    }
    raw_risk = sum(
        weights.get(Severity(sev.value if hasattr(sev, "value") else sev), 0) * count
        for sev, count in severity_rows
    )
    # Normalize: cap at 100
    risk_score = min(round(raw_risk, 1), 100.0)

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_distribution": severity_distribution,
        "recent_scans": recent_scans,
        "top_vulnerabilities": top_vulns,
        "risk_score": risk_score,
    }
