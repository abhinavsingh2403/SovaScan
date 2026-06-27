"""API route handlers for SovaScan v1 endpoints."""

import json
import logging
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
)
from sovascan.core.orchestrator import ScanOrchestrator
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

    Delegates to the real ScanOrchestrator (discovery -> dependency
    resolution -> CVE/misconfig/secret detection -> severity scoring),
    then converts each ScoredFinding into the plain dict shape the
    caller already inserts into the database.

    Args:
        target: Path to scan. (Remote URLs are not yet supported by the
            orchestrator; see the 404 raised below.)
        scan_type: Kind of scan (full, dependencies, secrets, misconfig).
        options: Extra options forwarded to the engine (currently unused
            by the orchestrator, but accepted for forward compatibility).

    Returns:
        A list of finding dicts ready for DB insertion.

    Raises:
        HTTPException: 400 if the target path does not exist, or the
            scan otherwise fails to run.
    """
    if target.startswith("http://") or target.startswith("https://"):
        raise HTTPException(
            status_code=400,
            detail="Remote URL scanning is not yet supported. Provide a local filesystem path.",
        )

    target_path = Path(target)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {target}")

    orchestrator = ScanOrchestrator(target_path=target_path, scan_type=scan_type)

    try:
        result = orchestrator.run_scan()
    except Exception as exc:
        logger.exception("Orchestrator failed for target %s", target)
        raise HTTPException(status_code=500, detail=f"Scan engine failed: {exc}") from exc

    findings: list[dict[str, Any]] = []
    for sf in result.findings:
        findings.append(
            {
                # ScoredFinding.id is a rule-style identifier (e.g.
                # "SOVA-MISC-001", "SECRET-HIGH-ENTROPY", or a CVE id) —
                # it maps directly onto Finding.rule_id.
                "rule_id": sf.id,
                "title": sf.title,
                "description": sf.description,
                "severity": Severity(sf.severity.value),
                "category": sf.category,
                "file_path": sf.file_path,
                "line_number": sf.line_number,
                "evidence": sf.evidence,
                "remediation": sf.remediation,
                "cve_id": sf.id if sf.category == "cve" else None,
                "cvss_score": sf.cvss_score or None,
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

    except HTTPException:
        # Validation-style failures (bad/missing target path, unsupported
        # scan target, etc.) already carry the correct status code and
        # message — mark the scan failed in the DB, but don't mask them as 500s.
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(UTC)
        db.commit()
        db.refresh(scan)
        logger.warning("Scan %s rejected before execution", scan.id)
        raise
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
                f'+Access-Control-Allow-Origin = "https://yourdomain.com"',
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
        "nist-csf": {
            "total_controls": 10,
            "control_categories": ["identify", "protect", "detect", "respond", "recover"],
        },
        "soc2": {
            "total_controls": 10,
            "control_categories": ["security", "availability", "processing_integrity", "confidentiality", "privacy"],
        },
        "soc-2": {
            "total_controls": 10,
            "control_categories": ["security", "availability", "processing_integrity", "confidentiality", "privacy"],
        },
        "owasp-10": {
            "total_controls": 10,
            "control_categories": [
                "broken_access_control",
                "cryptographic_failures",
                "injection",
                "insecure_design",
                "security_misconfiguration",
                "vulnerable_components",
                "auth_failures",
                "integrity_failures",
                "logging_failures",
                "ssrf",
            ],
        },
        "owasp10": {
            "total_controls": 10,
            "control_categories": [
                "broken_access_control",
                "cryptographic_failures",
                "injection",
                "insecure_design",
                "security_misconfiguration",
                "vulnerable_components",
                "auth_failures",
                "integrity_failures",
                "logging_failures",
                "ssrf",
            ],
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
