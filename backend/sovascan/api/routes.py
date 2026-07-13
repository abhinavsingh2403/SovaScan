"""API route handlers for SovaScan v1 endpoints."""

import json
import logging
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
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
    ThreatIntelScanResponse,
)
from sovascan.api.websocket import scan_manager
from sovascan.core.orchestrator import ScanOrchestrator
from sovascan.core.threat_intel import ThreatIntelEnricher, CVE_PATTERN
from sovascan.models.base import get_db
from sovascan.models.finding import Finding, Severity
from sovascan.models.scan import Scan, ScanStatus

logger = logging.getLogger("sovascan.api")

router = APIRouter(tags=["sovascan"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_path(path_str: str, base_path: Path) -> str:
    """Strip base_path prefix from path_str to keep paths relative and clean."""
    if not path_str:
        return ""
    try:
        p = Path(path_str)
        if p.is_absolute():
            return str(p.relative_to(base_path))
    except Exception:
        pass
    base_str = str(base_path)
    if path_str.startswith(base_str):
        return path_str[len(base_str):].lstrip("\\/")
    return path_str


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


@router.get("/scan", response_model=list[ScanResponse])
def list_scans(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=50, ge=1, le=200, description="Limit for pagination"),
    db: Session = Depends(get_db),
) -> list[Scan]:
    """Retrieve all scans ordered by creation date, newest first.

    Args:
        skip: Number of records to skip.
        limit: Maximum number of records to return.
        db: Database session (injected).

    Returns:
        List of Scan records.
    """
    return (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def create_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
) -> Scan:
    """Create a new security scan and begin async execution.

    Returns 202 Accepted immediately. Connect to the WebSocket
    endpoint ``/api/v1/scan/{scan_id}/ws`` to receive real-time
    progress updates.
    """
    # Validate target before creating DB record
    is_git = request.target.startswith("http://") or request.target.startswith("https://") or "://" in request.target or request.target.startswith("git@")
    if is_git:
        if not (request.target.startswith("https://") or request.target.startswith("http://")) or " " in request.target:
            raise HTTPException(status_code=400, detail="Disallowed git URL protocol. Only HTTP/HTTPS protocols are allowed for remote scans.")
    else:
        if "://" in request.target:
            raise HTTPException(status_code=400, detail="Invalid target syntax or unsupported URI protocol.")
        target_path = Path(request.target)
        if not target_path.exists():
            raise HTTPException(status_code=400, detail=f"Target path does not exist: {request.target}")

    scan = Scan(
        id=str(uuid.uuid4()),
        target=request.target,
        status=ScanStatus.PENDING,
        scan_type=request.scan_type,
        metadata_json=json.dumps(request.options) if request.options else None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Fire-and-forget background scan execution
    await scan_manager.start_scan(
        scan_id=scan.id,
        target=request.target,
        scan_type=request.scan_type,
        options=request.options,
    )

    logger.info("Scan %s queued for async execution", scan.id)
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


@router.get("/findings", response_model=FindingsListResponse)
def list_all_findings(
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=50, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    category: str | None = Query(default=None, description="Filter by category"),
    scan_id: str | None = Query(default=None, description="Filter by scan ID"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List findings across all scans with pagination and optional filters.

    Unlike ``GET /scan/{scan_id}/findings`` which is scoped to a single scan,
    this endpoint queries findings globally.

    Args:
        page: 1-indexed page number.
        per_page: Results per page.
        severity: Optional severity filter (critical/high/medium/low/info).
        category: Optional category filter (case-insensitive substring).
        scan_id: Optional scan ID to restrict results.
        db: Database session (injected).

    Returns:
        Paginated findings list.
    """
    query = db.query(Finding)

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        try:
            sev_enum = Severity(severity.lower())
            query = query.filter(Finding.severity == sev_enum)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity value: {severity}. "
                       f"Must be one of: critical, high, medium, low, info",
            ) from exc
    if category:
        query = query.filter(Finding.category.ilike(f"%{category}%"))

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

    # Check if we have cached SBOM in metadata_json
    if scan.metadata_json:
        try:
            meta = json.loads(scan.metadata_json)
            if "sbom" in meta and meta["sbom"]:
                return meta["sbom"]
        except Exception as e:
            logger.warning(f"Failed to read cached SBOM from metadata_json: {e}")

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


def _apply_finding_fix_on_disk(finding: Finding, target_path: str | None = None) -> bool:
    """Physically applies a patch to the file on disk for a given finding."""
    try:
        from pathlib import Path
        file_path_obj = Path(finding.file_path)
        if not file_path_obj.is_absolute():
            if target_path:
                file_path_obj = Path(target_path) / finding.file_path
            elif finding.scan:
                file_path_obj = Path(finding.scan.target) / finding.file_path

        file_path_obj = file_path_obj.resolve()
        if file_path_obj.exists() and file_path_obj.is_file():
            content = file_path_obj.read_text(encoding="utf-8")
            lines = content.splitlines(keepends=True)
            line_idx = finding.line_number - 1 if finding.line_number else None
            applied = False

            if finding.category == "secret" and line_idx is not None and 0 <= line_idx < len(lines):
                old_line = lines[line_idx]
                new_val = f'{finding.rule_id}_VALUE=${{{{ secrets.{finding.rule_id.replace("-", "_")} }}}}'
                # preserve trailing newline if present
                if old_line.endswith("\n"):
                    new_val += "\n"
                lines[line_idx] = new_val
                applied = True
            elif finding.category == "cve":
                old_dep = finding.evidence or ""
                pkg_name = old_dep.split("==")[0].strip() if "==" in old_dep else old_dep.strip()
                if pkg_name:
                    new_line = f"{pkg_name}>=2.31.0  # Fixes {finding.cve_id or 'known vulnerability'}"

                    if line_idx is not None and 0 <= line_idx < len(lines) and pkg_name in lines[line_idx]:
                        if lines[line_idx].endswith("\n"):
                            new_line += "\n"
                        lines[line_idx] = new_line
                        applied = True
                    else:
                        for idx, line in enumerate(lines):
                            if pkg_name in line:
                                if line.endswith("\n"):
                                    new_line += "\n"
                                lines[idx] = new_line
                                applied = True
                                break
            elif finding.category in ("misconfig", "misconfiguration") and line_idx is not None and 0 <= line_idx < len(lines):
                old_line = lines[line_idx]
                if finding.rule_id == "SOVA-INFRA-001":
                    base_line = old_line
                    if not base_line.endswith("\n"):
                        base_line += "\n"
                    new_line = base_line + "USER appuser\n"
                    lines[line_idx] = new_line
                    applied = True
                elif finding.rule_id == "SOVA-WEB-003":
                    new_line = 'Access-Control-Allow-Origin = "https://yourdomain.com"'
                    if old_line.endswith("\n"):
                        new_line += "\n"
                    lines[line_idx] = new_line
                    applied = True
                else:
                    new_line = "DEBUG = False  # Fixed: debug mode disabled for production"
                    if old_line.endswith("\n"):
                        new_line += "\n"
                    lines[line_idx] = new_line
                    applied = True

            if applied:
                file_path_obj.write_text("".join(lines), encoding="utf-8")
                logger.info("Auto-fix successfully applied to file %s on disk", file_path_obj)
                return True
    except Exception as write_err:
        logger.exception("Failed to physically apply auto-fix: %s", write_err)
    return False


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
    elif finding.category in ("misconfig", "misconfiguration"):
        if finding.rule_id == "SOVA-INFRA-001":
            patch_lines = [
                f"--- a/{finding.file_path}",
                f"+++ b/{finding.file_path}",
                f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},2 @@",
                f"-{finding.evidence}",
                f"+{finding.evidence}",
                "+USER appuser",
            ]
            description = (
                f"Avoid running the container as root by adding a USER directive "
                f"in {finding.file_path} after the base image is defined."
            )
        elif finding.rule_id == "SOVA-WEB-003":
            patch_lines = [
                f"--- a/{finding.file_path}",
                f"+++ b/{finding.file_path}",
                f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                f"-{finding.evidence}",
                '+Access-Control-Allow-Origin = "https://yourdomain.com"',
            ]
            description = (
                f"Specify exact allowed domains in {finding.file_path} "
                "instead of using the wildcard '*'."
            )
        else:
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
        target_path = finding.scan.target if finding.scan else None
        success = _apply_finding_fix_on_disk(finding, target_path=target_path)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to physically apply auto-fix suggestion to file on disk."
            )
        finding.is_fixed = True
        db.commit()

    return {
        "finding_id": finding_id,
        "status": status,
        "patch": patch,
        "description": description,
    }


@router.post("/fix/all", response_model=dict[str, Any])
def fix_all_findings(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Apply auto-fixes to all fixable findings across all scans in one go.

    Args:
        db: Database session (injected).

    Returns:
        Summary of applied fixes.
    """
    scans = db.query(Scan).all()
    scan_targets = {s.id: s.target for s in scans}

    findings = (
        db.query(Finding)
        .filter(Finding.is_fixed.is_(False))
        .all()
    )

    applied_finding_ids = []
    applied_findings = []
    for finding in findings:
        if finding.category in ("secret", "cve", "misconfig", "misconfiguration"):
            target_path = scan_targets.get(finding.scan_id)
            success = _apply_finding_fix_on_disk(finding, target_path=target_path)
            if success:
                finding.is_fixed = True
                applied_finding_ids.append(finding.id)
                applied_findings.append({
                    "id": finding.id,
                    "title": finding.title,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                })

    if applied_finding_ids:
        db.commit()

    return {
        "applied_count": len(applied_finding_ids),
        "applied_finding_ids": applied_finding_ids,
        "applied_findings": applied_findings,
    }


@router.post("/scan/{scan_id}/fix-all", response_model=dict[str, Any])
def fix_all_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Apply auto-fixes to all fixable findings in a scan at once.

    Args:
        scan_id: UUID of the parent scan.
        db: Database session (injected).

    Returns:
        Summary of applied fixes.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.is_fixed.is_(False))
        .all()
    )

    applied_finding_ids = []
    applied_findings = []
    for finding in findings:
        if finding.category in ("secret", "cve", "misconfig", "misconfiguration"):
            success = _apply_finding_fix_on_disk(finding, target_path=scan.target)
            if success:
                finding.is_fixed = True
                applied_finding_ids.append(finding.id)
                applied_findings.append({
                    "id": finding.id,
                    "title": finding.title,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                })

    if applied_finding_ids:
        db.commit()

    return {
        "scan_id": scan_id,
        "applied_count": len(applied_finding_ids),
        "applied_finding_ids": applied_finding_ids,
        "applied_findings": applied_findings,
    }


@router.get("/compliance/{framework}", response_model=ComplianceResponse)
def compliance_report(
    framework: str,
    scan_id: str | None = Query(default=None, description="Optional scan ID to scope compliance assessment"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Generate a compliance report for the specified framework.

    Evaluates findings against controls defined for the chosen framework.

    Args:
        framework: Compliance framework identifier.
        scan_id: Optional scan ID. If provided, uses findings only from that scan.
        db: Database session (injected).

    Returns:
        Compliance scoring, controls list, and mapped findings.
    """
    fw_key = framework.lower().strip()
    supported_frameworks = ("nist-csf", "nist", "soc2", "soc-2", "owasp-10", "owasp10")
    if fw_key not in supported_frameworks:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework: {framework}. Supported: nist-csf, soc-2, owasp-10",
        )

    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Define control descriptors
    controls_definitions = []
    if fw_key in ("nist-csf", "nist"):
        controls_definitions = [
            {"id": "ID.AM", "name": "Asset Management", "category": "Identify", "description": "Identify assets to manage security risks.", "match_cat": "misconfig"},
            {"id": "PR.AC", "name": "Access Control", "category": "Protect", "description": "Ensure access to assets is limited to authorized users.", "match_cat": "secret"},
            {"id": "PR.DS", "name": "Data Security", "category": "Protect", "description": "Manage data consistent with the organization's risk strategy.", "match_cat": "cve"},
            {"id": "PR.PT", "name": "Protective Technology", "category": "Protect", "description": "Manage security logs and protection systems.", "match_cat": "sast"},
            {"id": "DE.AE", "name": "Security Monitoring & Detections", "category": "Detect", "description": "Detect anomalies and events to identify threats.", "match_cat": "sast"},
            {"id": "RS.CO", "name": "Incident Response Communication", "category": "Respond", "description": "Manage response activities and coordination.", "match_cat": "drift"}
        ]
    elif fw_key in ("soc2", "soc-2"):
        controls_definitions = [
            {"id": "CC6.1", "name": "Logical Access Controls", "category": "Security", "description": "Restrict logical access to authorized endpoints.", "match_cat": "secret"},
            {"id": "CC6.6", "name": "Transmission Integrity Protection", "category": "Security", "description": "Protect data transmission from tampering or leakage.", "match_cat": "secret"},
            {"id": "CC7.1", "name": "Vulnerability & Threat Management", "category": "Security", "description": "Identify and evaluate system vulnerabilities.", "match_cat": "cve"},
            {"id": "CC8.1", "name": "System Operation Controls", "category": "Security", "description": "Monitor system operations to detect anomalies.", "match_cat": "sast"},
            {"id": "CC9.1", "name": "Business Risk Mitigation", "category": "Security", "description": "Manage vendor and operational risks.", "match_cat": "misconfig"}
        ]
    else:  # owasp-10
        controls_definitions = [
            {"id": "A01", "name": "Broken Access Control", "category": "Web Security", "description": "Prevent unauthorized privilege escalation and access.", "match_cat": "secret"},
            {"id": "A02", "name": "Cryptographic Failures", "category": "Web Security", "description": "Ensure protection of sensitive data at rest and in transit.", "match_cat": "secret"},
            {"id": "A03", "name": "Injection", "category": "Web Security", "description": "Prevent SQL, OS, or LDAP injection scripts.", "match_cat": "sast"},
            {"id": "A05", "name": "Security Misconfiguration", "category": "Web Security", "description": "Enforce secure defaults and configuration hardening.", "match_cat": "misconfig"},
            {"id": "A06", "name": "Vulnerable and Outdated Components", "category": "Web Security", "description": "Keep dependencies and software packages up to date.", "match_cat": "cve"},
            {"id": "A07", "name": "Identification and Authentication Failures", "category": "Web Security", "description": "Enforce authentication and session management.", "match_cat": "secret"},
            {"id": "A09", "name": "Security Logging and Monitoring Failures", "category": "Web Security", "description": "Record audit trails and monitor threats.", "match_cat": "sast"}
        ]

    # Query findings
    query = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    else:
        query = query.filter(Scan.status == ScanStatus.COMPLETED)
    
    findings = query.all()

    # Map findings to controls
    response_controls = []
    compliance_findings = []
    seen_finding_ids = set()

    for ctrl in controls_definitions:
        matching_findings = [
            f for f in findings
            if f.category.lower() == ctrl["match_cat"]
            and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        
        status = "passed"
        finding_ids = []
        if matching_findings:
            status = "failed"
            finding_ids = [str(f.id) for f in matching_findings]
            for f in matching_findings:
                if f.id not in seen_finding_ids:
                    seen_finding_ids.add(f.id)
                    compliance_findings.append(f)
        
        response_controls.append({
            "id": ctrl["id"],
            "name": ctrl["name"],
            "category": ctrl["category"],
            "status": status,
            "findings": finding_ids,
            "description": ctrl["description"]
        })

    total_controls = len(response_controls)
    passed = sum(1 for c in response_controls if c["status"] == "passed")
    failed = total_controls - passed
    score = round((passed / total_controls) * 100, 1) if total_controls > 0 else 100.0

    return {
        "framework": framework,
        "score": score,
        "total_controls": total_controls,
        "passed": passed,
        "failed": failed,
        "findings": compliance_findings,
        "controls": response_controls,
    }


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return aggregated dashboard statistics.

    Computes totals, severity distribution, recent scans,
    top vulnerabilities (grouped by rule), trend data (daily severity
    totals), and an overall risk score.

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
    # Ensure all five keys are always present for the frontend pie chart
    for s in ("critical", "high", "medium", "low", "info"):
        severity_distribution.setdefault(s, 0)

    # Recent scans (last 10)
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    # Top vulnerabilities — grouped by rule_id so the frontend shows
    # aggregated counts like "SQL Injection: 7 occurrences".
    top_vulns_rows = (
        db.query(
            Finding.rule_id,
            Finding.title,
            Finding.severity,
            Finding.category,
            func.count(Finding.id).label("cnt"),
        )
        .group_by(Finding.rule_id, Finding.title, Finding.severity, Finding.category)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
        .all()
    )
    top_vulnerabilities = [
        {
            "id": row.rule_id,
            "title": row.title,
            "severity": row.severity.value if hasattr(row.severity, "value") else str(row.severity),
            "category": row.category,
            "count": row.cnt,
        }
        for row in top_vulns_rows
    ]

    # Trend data — hourly aggregated severity counts from completed scans
    trend_rows = (
        db.query(
            func.strftime("%Y-%m-%d %H:00", Scan.created_at, "localtime").label("date"),
            func.coalesce(func.sum(Scan.critical_count), 0).label("critical"),
            func.coalesce(func.sum(Scan.high_count), 0).label("high"),
            func.coalesce(func.sum(Scan.medium_count), 0).label("medium"),
            func.coalesce(func.sum(Scan.low_count), 0).label("low"),
        )
        .filter(Scan.status == ScanStatus.COMPLETED)
        .group_by(func.strftime("%Y-%m-%d %H:00", Scan.created_at, "localtime"))
        .order_by(func.strftime("%Y-%m-%d %H:00", Scan.created_at, "localtime").asc())
        .limit(30)
        .all()
    )
    trend_data = [
        {
            "date": row.date,
            "critical": int(row.critical),
            "high": int(row.high),
            "medium": int(row.medium),
            "low": int(row.low),
        }
        for row in trend_rows
    ]

    # Risk score: weighted sum capped at 100
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
    risk_score = min(round(raw_risk, 1), 100.0)

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_distribution": severity_distribution,
        "recent_scans": recent_scans,
        "top_vulnerabilities": top_vulnerabilities,
        "risk_score": risk_score,
        "trend_data": trend_data,
    }


@router.get("/threat-intel/scan/{scan_id}", response_model=ThreatIntelScanResponse)
def get_scan_threat_intel(
    scan_id: str,
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve threat intelligence exploitability enrichment for a specific scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Extract all CVE IDs associated with findings from this scan
    cve_ids = set()
    cvss_scores = {}

    for f in findings:
        cves_found = []
        if f.cve_id:
            cves_found.append(f.cve_id)
        if f.rule_id and CVE_PATTERN.match(f.rule_id):
            cves_found.append(f.rule_id)

        # Fallback to search text fields
        for text_field in [f.title, f.description]:
            if text_field:
                cves_found.extend(CVE_PATTERN.findall(text_field))

        for cve in cves_found:
            cve_upper = cve.upper()
            cve_ids.add(cve_upper)
            if f.cvss_score is not None:
                cvss_scores[cve_upper] = max(cvss_scores.get(cve_upper, 0.0), f.cvss_score)

    if not cve_ids:
        return {
            "scan_id": scan_id,
            "generated_at": datetime.now(UTC),
            "total_cves": 0,
            "known_exploited_count": 0,
            "high_priority_count": 0,
            "records": []
        }

    # Enrich extracted CVE list using threat intel sources
    try:
        enricher = ThreatIntelEnricher()
        records_map = enricher.enrich_cves(list(cve_ids), cvss_scores)
    except Exception as e:
        logger.error(f"Failed to enrich CVEs for scan {scan_id}: {e}")
        # Fallback behaviour: Return empty list on enricher failures to prevent reports from crashing
        return {
            "scan_id": scan_id,
            "generated_at": datetime.now(UTC),
            "total_cves": len(cve_ids),
            "known_exploited_count": 0,
            "high_priority_count": 0,
            "records": [
                {
                    "cve_id": cve,
                    "known_exploited": False,
                    "epss_score": None,
                    "epss_percentile": None,
                    "priority": "monitor",
                    "summary": "Threat intelligence unavailable.",
                    "remediation_urgency": "Exploitability enrichment could not be refreshed.",
                    "sources": []
                }
                for cve in cve_ids
            ]
        }

    records_list = []
    known_exploited_cnt = 0
    high_priority_cnt = 0

    for rec in records_map.values():
        if rec.known_exploited:
            known_exploited_cnt += 1
        if rec.priority in ("immediate", "high"):
            high_priority_cnt += 1

        records_list.append({
            "cve_id": rec.cve_id,
            "known_exploited": rec.known_exploited,
            "epss_score": rec.epss_score,
            "epss_percentile": rec.epss_percentile,
            "priority": rec.priority,
            "summary": rec.summary,
            "remediation_urgency": rec.remediation_urgency,
            "sources": rec.sources
        })

    return {
        "scan_id": scan_id,
        "generated_at": datetime.now(UTC),
        "total_cves": len(records_list),
        "known_exploited_count": known_exploited_cnt,
        "high_priority_count": high_priority_cnt,
        "records": records_list
    }

