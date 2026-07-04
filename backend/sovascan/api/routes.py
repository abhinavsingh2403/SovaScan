"""API route handlers for SovaScan v1 endpoints."""

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import subprocess

from sovascan.models.finding import Severity
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

def _map_semgrep_severity(sev: str) -> Severity:
    return {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }.get(sev.upper(), Severity.LOW)

def _map_bandit_severity(sev: str) -> Severity:
    return {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(sev.upper(), Severity.LOW)

def _run_semgrep(target_path: Path) -> list[dict[str, Any]]:
    """Run semgrep with the auto ruleset and return findings as dicts."""
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(target_path)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError as exc:
        logger.warning("semgrep binary not found: %s", exc)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out for target %s", target_path)
        return []

    if not proc.stdout:
        logger.warning("semgrep produced no output (stderr: %s)", proc.stderr)
        return []

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.exception("Failed to parse semgrep JSON output")
        return []

    findings: list[dict[str, Any]] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        findings.append(
            {
                "rule_id": result.get("check_id", "SEMGREP-UNKNOWN"),
                "title": extra.get("message", "Semgrep finding")[:200],
                "description": extra.get("message", ""),
                "severity": _map_semgrep_severity(extra.get("severity", "INFO")),
                "category": "sast",
                "file_path": result.get("path", ""),
                "line_number": result.get("start", {}).get("line"),
                "evidence": extra.get("lines", ""),
                "remediation": extra.get("metadata", {}).get("fix", "") or "Review and remediate per rule guidance.",
                "cve_id": None,
                "cvss_score": None,
            }
        )
    return findings

def _run_bandit(target_path: Path) -> list[dict[str, Any]]:
    """Run bandit against a Python target and return findings as dicts."""
    try:
        proc = subprocess.run(
            ["bandit", "-r", str(target_path), "-f", "json"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError as exc:
        logger.warning("bandit binary not found: %s", exc)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("bandit timed out for target %s", target_path)
        return []

    # bandit exits non-zero when it finds issues, so don't gate on returncode
    if not proc.stdout:
        logger.warning("bandit produced no output (stderr: %s)", proc.stderr)
        return []

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        logger.exception("Failed to parse bandit JSON output")
        return []

    findings: list[dict[str, Any]] = []
    for result in payload.get("results", []):
        findings.append(
            {
                "rule_id": result.get("test_id", "BANDIT-UNKNOWN"),
                "title": result.get("test_name", "Bandit finding"),
                "description": result.get("issue_text", ""),
                "severity": _map_bandit_severity(result.get("issue_severity", "LOW")),
                "category": "sast",
                "file_path": result.get("filename", ""),
                "line_number": result.get("line_number"),
                "evidence": result.get("code", ""),
                "remediation": f"See Bandit docs for {result.get('test_id', '')}: "
                f"{result.get('more_info', '')}",
                "cve_id": result.get("issue_cwe", {}).get("id") if result.get("issue_cwe") else None,
                "cvss_score": None,
            }
        )
    return findings


def _run_scan_logic(target:str, scan_type:str, options: dict[str, Any] | None) -> None:
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

    # Run SAST tools along side the orchestrator for full scan types
    if scan_type in ("full", "sast"):
        findings.extend(_run_semgrep(target_path))
        findings.extend(_run_bandit(target_path))
    
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


def _generate_fixed_line(finding: Finding, old_line: str, file_path_obj: Path) -> tuple[str, bool]:
    """Generates the fixed version of a line based on the finding and file type.

    Returns:
        tuple[str, bool]: The new line and whether the fix was successfully generated.
    """
    import re
    applied = False
    new_line = old_line

    if finding.category == "secret":
        # Try to import patterns to find the matching regex pattern
        from sovascan.core.secret_scanner import COMPILED_PATTERNS

        pattern = None
        if finding.title == "High-Entropy Secret Detected":
            pattern = re.compile(r"""(?i)(?:secret|token|key|password|credential|auth)\s*[=:]\s*['"]?([a-zA-Z0-9+/=_-]{20,})['"]?""")
        else:
            for p in COMPILED_PATTERNS:
                if p.name == finding.title:
                    pattern = p.pattern
                    break

        if pattern:
            match = pattern.search(old_line)
            if match:
                g_idx = 0
                if pattern.groups >= 1:
                    for i in range(1, pattern.groups + 1):
                        if match.group(i) is not None:
                            g_idx = i
                            break
                start, end = match.span(g_idx)

                # Preserve trailing brackets/delimiters that the regex greedily consumed.
                # Patterns like [^\s'"]{4,} can swallow ), ], } etc. at the end of
                # type annotations or function calls, breaking the surrounding code.
                matched_text = old_line[start:end]
                while matched_text and matched_text[-1] in "()[]{}:;,":
                    end -= 1
                    matched_text = matched_text[:-1]

                placeholder = f'${{{{ secrets.{finding.rule_id.replace("-", "_")} }}}}'
                new_line = old_line[:start] + placeholder + old_line[end:]
                applied = True

        # Fallback if pattern matching failed
        if not applied:
            placeholder = f'${{{{ secrets.{finding.rule_id.replace("-", "_")} }}}}'
            new_val = f'{finding.rule_id}_VALUE={placeholder}'
            if old_line.endswith("\n"):
                new_val += "\n"
            new_line = new_val
            applied = True

    elif finding.category == "cve":
        old_dep = finding.evidence or ""
        pkg_name = old_dep.split("==")[0].strip() if "==" in old_dep else old_dep.strip()
        if pkg_name.startswith("Vulnerable dependency:"):
            pkg_name = pkg_name.replace("Vulnerable dependency:", "").strip()
        
        if "@" in pkg_name:
            pkg_name = pkg_name.split("@")[0].strip()

        if pkg_name:
            fixed_ver = "2.31.0"
            if finding.remediation:
                match = re.search(r"to\s+([0-9a-zA-Z.-]+)", finding.remediation)
                if match:
                    fixed_ver = match.group(1)

            if file_path_obj.name == "package.json":
                # JSON package replacement preserving quotes, version prefix, and trailing comma
                pattern = re.compile(rf"(\"\s*{re.escape(pkg_name)}\s*\"\s*:\s*\"\s*)([~^>=]?)(\d+[0-9a-zA-Z.-]*)([^\"\n]*\")")
                match = pattern.search(old_line)
                if match:
                    new_line = old_line[:match.start(3)] + fixed_ver + old_line[match.end(3):]
                    applied = True
            elif file_path_obj.name == "pom.xml":
                # XML version tag replacement
                pattern = re.compile(r"(<version\s*>)([^<]+)(</version\s*>)")
                match = pattern.search(old_line)
                if match:
                    new_line = old_line[:match.start(2)] + fixed_ver + old_line[match.end(2):]
                    applied = True
            else:
                # Default / requirements.txt format
                # Check if package name is in the line to avoid writing mismatched lines
                if pkg_name in old_line:
                    new_val = f"{pkg_name}>={fixed_ver}  # Fixes {finding.cve_id or 'known vulnerability'}"
                    if old_line.endswith("\n"):
                        new_val += "\n"
                    new_line = new_val
                    applied = True

    elif finding.category in ("misconfig", "misconfiguration"):
        if finding.rule_id == "SOVA-INFRA-001":
            base_line = old_line
            if not base_line.endswith("\n"):
                base_line += "\n"
            new_line = base_line + "USER appuser\n"
            applied = True
        elif finding.rule_id == "SOVA-WEB-003":
            # CORS Wildcard Origin Allowed
            pattern = re.compile(r"([\"']?Access-Control-Allow-Origin[\"']?\s*[:=]\s*)([\"']?)\*([\"']?)")
            match = pattern.search(old_line)
            if match:
                prefix = match.group(1)
                q1 = match.group(2)
                q2 = match.group(3)
                if not q1 and not q2:
                    new_val = f'{prefix}"https://yourdomain.com"'
                else:
                    new_val = f'{prefix}{q1}https://yourdomain.com{q2}'
                new_line = old_line[:match.start()] + new_val + old_line[match.end():]
                applied = True
            else:
                new_val = 'Access-Control-Allow-Origin = "https://yourdomain.com"'
                if old_line.endswith("\n"):
                    new_val += "\n"
                new_line = new_val
                applied = True
        elif finding.rule_id == "SOVA-WEB-001":
            # Debug Mode Enabled in Web Configuration
            pattern = re.compile(r"([\"']?\b(?:debug|dev_mode)\b[\"']?\s*[:=]\s*)(true|1|on|yes)\b", re.IGNORECASE)
            match = pattern.search(old_line)
            if match:
                prefix = match.group(1)
                val = match.group(2)
                if val.lower() == "true":
                    disabled_val = "False" if val == "True" else "false"
                elif val.lower() == "yes":
                    disabled_val = "No" if val == "Yes" else "no"
                elif val.lower() == "on":
                    disabled_val = "Off" if val == "On" else "off"
                else:
                    disabled_val = "0"

                new_line = old_line[:match.start(2)] + disabled_val + old_line[match.end(2):]
                applied = True
            else:
                new_val = "DEBUG = False  # Fixed: debug mode disabled for production"
                if old_line.endswith("\n"):
                    new_val += "\n"
                new_line = new_val
                applied = True
        else:
            # General fallback for other misconfigs
            new_val = "DEBUG = False  # Fixed: debug mode disabled for production"
            if old_line.endswith("\n"):
                new_val += "\n"
            new_line = new_val
            applied = True

    return new_line, applied


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
        
        # Safeguard: Do not apply auto-fixes to the security scanner's own source code files
        if "sovascan" in file_path_obj.parts and ("core" in file_path_obj.parts or "api" in file_path_obj.parts or "rules" in file_path_obj.parts or "models" in file_path_obj.parts):
            logger.warning("Skipping auto-fix on scanner's own code file: %s", file_path_obj)
            return False

        if file_path_obj.exists() and file_path_obj.is_file():
            content = file_path_obj.read_text(encoding="utf-8")
            lines = content.splitlines(keepends=True)
            line_idx = finding.line_number - 1 if finding.line_number else None
            applied = False

            if line_idx is not None and 0 <= line_idx < len(lines):
                old_line = lines[line_idx]
                new_line, applied = _generate_fixed_line(finding, old_line, file_path_obj)
                if applied:
                    lines[line_idx] = new_line
            else:
                # If line_idx is not set or out of bounds (e.g. for cve dependencies)
                # we search all lines for the package/rule
                if finding.category == "cve":
                    old_dep = finding.evidence or ""
                    pkg_name = old_dep.split("==")[0].strip() if "==" in old_dep else old_dep.strip()
                    if pkg_name.startswith("Vulnerable dependency:"):
                        pkg_name = pkg_name.replace("Vulnerable dependency:", "").strip()
                    if "@" in pkg_name:
                        pkg_name = pkg_name.split("@")[0].strip()
                    if pkg_name:
                        for idx, line in enumerate(lines):
                            new_line, applied = _generate_fixed_line(finding, line, file_path_obj)
                            if applied:
                                lines[idx] = new_line
                                break

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

    # Load the file content to generate the actual diff
    from pathlib import Path
    target_path = finding.scan.target if finding.scan else None
    file_path_obj = Path(finding.file_path)
    if not file_path_obj.is_absolute():
        if target_path:
            file_path_obj = Path(target_path) / finding.file_path
        elif finding.scan:
            file_path_obj = Path(finding.scan.target) / finding.file_path
    
    file_path_obj = file_path_obj.resolve()
    old_line = None
    new_line = None
    applied = False
    
    if file_path_obj.exists() and file_path_obj.is_file():
        try:
            content = file_path_obj.read_text(encoding="utf-8")
            lines = content.splitlines(keepends=True)
            line_idx = finding.line_number - 1 if finding.line_number else None
            
            if line_idx is not None and 0 <= line_idx < len(lines):
                old_line = lines[line_idx]
                new_line, applied = _generate_fixed_line(finding, old_line, file_path_obj)
            else:
                # If line_idx not set or invalid, search
                if finding.category == "cve":
                    old_dep = finding.evidence or ""
                    pkg_name = old_dep.split("==")[0].strip() if "==" in old_dep else old_dep.strip()
                    if pkg_name.startswith("Vulnerable dependency:"):
                        pkg_name = pkg_name.replace("Vulnerable dependency:", "").strip()
                    if "@" in pkg_name:
                        pkg_name = pkg_name.split("@")[0].strip()
                    if pkg_name:
                        for idx, line in enumerate(lines):
                            new_line, applied = _generate_fixed_line(finding, line, file_path_obj)
                            if applied:
                                old_line = line
                                break
        except Exception as e:
            logger.warning("Failed to read file for generating fix patch: %s", e)

    # Generate patch lines
    patch_lines: list[str] = []
    
    if old_line and new_line and applied:
        # Strip trailing newlines for the diff display
        old_stripped = old_line.rstrip("\r\n")
        new_stripped = new_line.rstrip("\r\n")
        patch_lines = [
            f"--- a/{finding.file_path}",
            f"+++ b/{finding.file_path}",
            f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
            f"-{old_stripped}",
            f"+{new_stripped}",
        ]
    else:
        # Fallback to general suggestion diff shape if file cannot be read/matched
        placeholder = f'${{{{ secrets.{finding.rule_id.replace("-", "_")} }}}}'
        if finding.category == "secret":
            patch_lines = [
                f"--- a/{finding.file_path}",
                f"+++ b/{finding.file_path}",
                f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                f"-{finding.evidence}",
                f"+{placeholder}",
            ]
        elif finding.category == "cve":
            old_dep = finding.evidence or ""
            pkg_name = old_dep.split("==")[0].strip() if "==" in old_dep else old_dep.strip()
            if pkg_name.startswith("Vulnerable dependency:"):
                pkg_name = pkg_name.replace("Vulnerable dependency:", "").strip()
            if "@" in pkg_name:
                pkg_name = pkg_name.split("@")[0].strip()
            fixed_ver = "2.31.0"
            if finding.remediation:
                import re
                match = re.search(r"to\s+([0-9a-zA-Z.-]+)", finding.remediation)
                if match:
                    fixed_ver = match.group(1)
            patch_lines = [
                f"--- a/{finding.file_path}",
                f"+++ b/{finding.file_path}",
                f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                f"-{old_dep}",
                f"+{pkg_name}>={fixed_ver}  # Fixes {finding.cve_id or 'known vulnerability'}",
            ]
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
            elif finding.rule_id == "SOVA-WEB-003":
                patch_lines = [
                    f"--- a/{finding.file_path}",
                    f"+++ b/{finding.file_path}",
                    f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                    f"-{finding.evidence}",
                    '+Access-Control-Allow-Origin = "https://yourdomain.com"',
                ]
            else:
                patch_lines = [
                    f"--- a/{finding.file_path}",
                    f"+++ b/{finding.file_path}",
                    f"@@ -{finding.line_number or 1},1 +{finding.line_number or 1},1 @@",
                    f"-{finding.evidence}",
                    "+DEBUG = False  # Fixed: debug mode disabled for production",
                ]
        else:
            patch_lines = [f"# Manual review required for {finding.rule_id}"]

    description = ""
    if finding.category == "secret":
        description = (
            f"Replace the hardcoded secret at {finding.file_path}:{finding.line_number} "
            "with an environment variable/secrets reference. Remember to rotate the exposed credential."
        )
    elif finding.category == "cve":
        description = (
            f"Upgrade the vulnerable dependency referenced by {finding.cve_id or finding.rule_id}. "
            f"See remediation: {finding.remediation}"
        )
    elif finding.category in ("misconfig", "misconfiguration"):
        if finding.rule_id == "SOVA-INFRA-001":
            description = (
                f"Avoid running the container as root by adding a USER directive "
                f"in {finding.file_path} after the base image is defined."
            )
        elif finding.rule_id == "SOVA-WEB-003":
            description = (
                f"Specify exact allowed domains in {finding.file_path} "
                "instead of using the wildcard '*'."
            )
        else:
            description = (
                f"Disable debug mode in {finding.file_path}. "
                "Running with DEBUG=True in production exposes sensitive data."
            )
    else:
        description = f"No automated fix available for rule {finding.rule_id}. Please review manually."

    patch = "\n".join(patch_lines)
    status = "applied" if request.auto_apply else "suggested"

    if request.auto_apply:
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
        "iso-27001": {
            "total_controls": 93,
            "control_categories": ["organizational", "people", "physical", "technological"],
        },
        "rbi-csf": {
            "total_controls": 42,
            "control_categories": ["governance", "identify", "protect", "detect", "respond", "recover"],
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

    # Trend data — daily aggregated severity counts from completed scans
    trend_rows = (
        db.query(
            func.strftime("%Y-%m-%d", Scan.created_at).label("date"),
            func.coalesce(func.sum(Scan.critical_count), 0).label("critical"),
            func.coalesce(func.sum(Scan.high_count), 0).label("high"),
            func.coalesce(func.sum(Scan.medium_count), 0).label("medium"),
            func.coalesce(func.sum(Scan.low_count), 0).label("low"),
        )
        .filter(Scan.status == ScanStatus.COMPLETED)
        .group_by(func.strftime("%Y-%m-%d", Scan.created_at))
        .order_by(func.strftime("%Y-%m-%d", Scan.created_at).asc())
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
