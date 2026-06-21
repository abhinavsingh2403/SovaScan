"""CVE Scanner - queries OSV.dev API for known vulnerabilities in dependencies.

Uses the Open Source Vulnerabilities (OSV) database for comprehensive
vulnerability data across npm, PyPI, and Maven ecosystems.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ecosystem mapping from our internal names to OSV ecosystem names
OSV_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
}


@dataclass
class Finding:
    """Represents a single security finding."""

    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # cve, misconfig, secret, drift
    file_path: str = ""
    line_number: int = 0
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class CVEScanner:
    """Scans dependencies against the OSV.dev vulnerability database."""

    OSV_API_URL = "https://api.osv.dev/v1/query"
    BATCH_API_URL = "https://api.osv.dev/v1/querybatch"
    RATE_LIMIT_DELAY = 0.25  # seconds between requests
    MAX_BATCH_SIZE = 100

    def __init__(self, cache_dir: str | Path | None = None) -> None:
        """Initialize the CVE scanner.

        Args:
            cache_dir: Optional directory for caching query results.
        """
        self._cache: dict[str, list[dict]] = {}
        self._cache_dir = Path(cache_dir) if cache_dir else None
        self._last_request_time: float = 0.0
        self._httpx_available: bool = False
        self._network_available: bool = False

        try:
            import httpx  # noqa: F401
            self._httpx_available = True
        except ImportError:
            logger.warning("httpx not installed; CVE scanning will use cached/offline mode only")

        if self._httpx_available:
            self._network_available = self._check_network()

        if self._cache_dir and self._cache_dir.exists():
            self._load_cache()

    def _check_network(self) -> bool:
        """Check if the OSV API is reachable."""
        try:
            import httpx
            resp = httpx.head("https://api.osv.dev", timeout=5.0)
            return resp.status_code < 500
        except Exception:
            logger.info("OSV API not reachable; operating in offline mode")
            return False

    def scan(self, dependencies: list) -> list[Finding]:
        """Scan a list of dependencies for known vulnerabilities.

        Args:
            dependencies: List of Dependency objects to scan.

        Returns:
            List of Finding objects for discovered CVEs.
        """
        findings: list[Finding] = []
        logger.info("Scanning %d dependencies for CVEs", len(dependencies))

        for dep in dependencies:
            cache_key = self._cache_key(dep.name, dep.version, dep.ecosystem)

            if cache_key in self._cache:
                vulns = self._cache[cache_key]
                logger.debug("Cache hit for %s@%s", dep.name, dep.version)
            else:
                vulns = self._query_osv(dep.name, dep.version, dep.ecosystem)
                self._cache[cache_key] = vulns

            for vuln in vulns:
                finding = self._build_finding(vuln, dep)
                if finding:
                    findings.append(finding)

        if self._cache_dir:
            self._save_cache()

        logger.info("Found %d CVE findings across %d dependencies", len(findings), len(dependencies))
        return findings

    def _query_osv(self, package_name: str, version: str, ecosystem: str) -> list[dict]:
        """Query the OSV API for vulnerabilities affecting a package version.

        Args:
            package_name: Package name.
            version: Package version string.
            ecosystem: Internal ecosystem name (npm, pypi, maven).

        Returns:
            List of raw vulnerability dicts from OSV.
        """
        if not self._httpx_available or not self._network_available:
            return []

        osv_ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem, ecosystem)
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            },
        }

        self._rate_limit()

        try:
            import httpx

            with httpx.Client(timeout=15.0) as client:
                response = client.post(self.OSV_API_URL, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("vulns", [])
        except Exception as exc:
            logger.warning("OSV query failed for %s@%s: %s", package_name, version, exc)
            return []

    def _rate_limit(self) -> None:
        """Enforce rate limiting between API requests."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()

    def _parse_osv_response(self, vuln: dict) -> dict[str, Any]:
        """Extract structured fields from a raw OSV vulnerability record.

        Args:
            vuln: Raw vulnerability dict from OSV API.

        Returns:
            Parsed vulnerability information.
        """
        vuln_id = vuln.get("id", "UNKNOWN")

        # Extract aliases (CVE IDs)
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # Extract severity
        severity_info = vuln.get("severity", [])
        cvss_score = 0.0
        severity_str = "medium"

        for sev in severity_info:
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # Extract base score from CVSS vector
                cvss_score = self._extract_cvss_score(score_str)
                severity_str = self._cvss_to_severity(cvss_score)
                break

        if not severity_info:
            # Fallback: infer from database_specific
            db_severity = vuln.get("database_specific", {}).get("severity", "MODERATE")
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "medium",
                "MEDIUM": "medium",
                "LOW": "low",
            }
            severity_str = severity_map.get(db_severity.upper(), "medium")
            cvss_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5}
            cvss_score = cvss_map.get(severity_str, 5.5)

        # Extract summary
        summary = vuln.get("summary", vuln.get("details", "No description available"))

        # Extract affected ranges and fixed versions
        fixed_versions: list[str] = []
        affected_versions: list[str] = []

        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])
                    if "introduced" in event:
                        introduced = event["introduced"]
                        if introduced != "0":
                            affected_versions.append(f">={introduced}")

            # ecosystem-specific versions
            versions = affected.get("versions", [])
            affected_versions.extend(versions[:10])  # cap for readability

        # Extract references
        references = [ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")]

        return {
            "cve_id": cve_id,
            "osv_id": vuln_id,
            "severity": severity_str,
            "cvss_score": cvss_score,
            "summary": summary,
            "fixed_versions": fixed_versions,
            "affected_versions": affected_versions[:20],
            "references": references[:10],
            "aliases": aliases,
        }

    def _build_finding(self, vuln: dict, dep: Any) -> Finding | None:
        """Build a Finding object from parsed vulnerability and dependency data.

        Args:
            vuln: Raw OSV vulnerability dict.
            dep: Dependency object.

        Returns:
            Finding or None if parsing fails.
        """
        parsed = self._parse_osv_response(vuln)

        fixed = parsed["fixed_versions"]
        if fixed:
            remediation = f"Upgrade {dep.name} from {dep.version} to {fixed[0]}"
            if len(fixed) > 1:
                remediation += f" (other fixed versions: {', '.join(fixed[1:4])})"
        else:
            remediation = f"No fixed version available for {dep.name}. Consider finding an alternative package."

        return Finding(
            id=parsed["cve_id"],
            title=f"{parsed['cve_id']}: {dep.name}@{dep.version}",
            description=parsed["summary"],
            severity=parsed["severity"],
            category="cve",
            file_path=dep.source_file,
            line_number=0,
            evidence=f"Vulnerable dependency: {dep.coordinate}",
            remediation=remediation,
            references=parsed["references"],
            tags=["cve", dep.ecosystem],
            cvss_score=parsed["cvss_score"],
            metadata={
                "osv_id": parsed["osv_id"],
                "package": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "fixed_versions": fixed,
                "is_dev": dep.is_dev,
                "is_transitive": dep.is_transitive,
            },
        )

    @staticmethod
    def _extract_cvss_score(cvss_vector: str) -> float:
        """Extract the base score from a CVSS v3 vector string.

        For a proper implementation, parse the vector components.
        For simplicity, we estimate based on known vector patterns.
        """
        if not cvss_vector:
            return 0.0

        # Common pattern: the vector may contain a score directly
        # Otherwise, do a rough estimate from attack vector and impact
        score_components = {
            "AV:N": 1.5, "AV:A": 1.0, "AV:L": 0.5, "AV:P": 0.2,
            "AC:L": 1.0, "AC:H": 0.5,
            "PR:N": 1.0, "PR:L": 0.7, "PR:H": 0.3,
            "UI:N": 1.0, "UI:R": 0.5,
            "C:H": 1.5, "C:L": 0.5, "C:N": 0.0,
            "I:H": 1.5, "I:L": 0.5, "I:N": 0.0,
            "A:H": 1.5, "A:L": 0.5, "A:N": 0.0,
        }

        total = 0.0
        for component, weight in score_components.items():
            if component in cvss_vector:
                total += weight

        # Normalize to 0-10 scale
        normalized = min(10.0, max(0.0, total))
        return round(normalized, 1)

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Convert a CVSS score to a severity string."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "info"

    @staticmethod
    def _cache_key(name: str, version: str, ecosystem: str) -> str:
        """Generate a deterministic cache key."""
        raw = f"{ecosystem}:{name}:{version}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _load_cache(self) -> None:
        """Load cached results from disk."""
        if not self._cache_dir:
            return
        cache_file = self._cache_dir / "osv_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, encoding="utf-8") as fh:
                    self._cache = json.load(fh)
                logger.info("Loaded %d cached OSV results", len(self._cache))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load cache: %s", exc)

    def _save_cache(self) -> None:
        """Persist cached results to disk."""
        if not self._cache_dir:
            return
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = self._cache_dir / "osv_cache.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh, indent=2)
        except OSError as exc:
            logger.warning("Failed to save cache: %s", exc)
