"""threat_intel.py — OSV-based threat intelligence enrichment for resolved dependencies."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from sovascan.core.cve_scanner import Finding
from sovascan.core.dependency_resolver import Dependency

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    package: str
    ecosystem: str
    vuln_id: str
    summary: str
    severity: str
    affected_versions: list[str]
    fixed_version: str | None


def _query_osv(package: str, ecosystem: str, version: str) -> list[dict]:
    """Query OSV API for a specific package version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        },
    }
    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(url, json=payload)
            if response.status_code != 200:
                return []
            return response.json().get("vulns", [])
    except Exception as exc:
        logger.warning("OSV query failed for %s==%s: %s", package, version, exc)
        return []


def _extract_fixed_version(vuln: dict) -> str | None:
    """Extract the first fixed version from an OSV vuln entry."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _map_severity(vuln: dict) -> str:
    """Map OSV severity to SovaScan severity string."""
    db_severity = vuln.get("database_specific", {}).get("severity", "")
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    return severity_map.get(db_severity.upper(), "medium")


class ThreatIntelScanner:
    """Enriches resolved dependencies with live OSV vulnerability data."""

    def scan(self, dependencies: list[Dependency]) -> list[Finding]:
        """Cross-reference dependencies against OSV and return findings.

        Args:
            dependencies: Resolved dependencies from DependencyResolver.

        Returns:
            List of Finding objects for vulnerable dependencies.
        """
        findings: list[Finding] = []

        # Map ecosystem names to OSV ecosystem identifiers
        ecosystem_map = {
            "pypi": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "go": "Go",
            "cargo": "crates.io",
        }

        for dep in dependencies:
            ecosystem = ecosystem_map.get(dep.ecosystem.lower(), dep.ecosystem)
            vulns = _query_osv(dep.name, ecosystem, dep.version)

            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary", f"Vulnerability in {dep.name}")
                severity = _map_severity(vuln)
                fixed_version = _extract_fixed_version(vuln)
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

                remediation = (
                    f"Upgrade {dep.name} to version {fixed_version} or later."
                    if fixed_version
                    else f"Review {vuln_id} and upgrade {dep.name} to a patched version."
                )

                findings.append(
                    Finding(
                        id=cve_id or vuln_id,
                        title=f"{dep.name} {dep.version} — {summary[:80]}",
                        description=summary,
                        severity=severity,
                        category="cve",
                        file_path=str(dep.source_file) if hasattr(dep, "source_file") else "",
                        line_number=None,
                        evidence=f"{dep.name}=={dep.version}",
                        remediation=remediation,
                        references=[
                            f"https://osv.dev/vulnerability/{vuln_id}",
                            *[r.get("url", "") for r in vuln.get("references", [])[:2]],
                        ],
                        tags=["osv", "dependency", ecosystem.lower()],
                        metadata={
                            "vuln_id": vuln_id,
                            "cve_id": cve_id,
                            "fixed_version": fixed_version,
                            "package": dep.name,
                            "version": dep.version,
                            "ecosystem": ecosystem,
                        },
                        cvss_score=None,
                    )
                )
                logger.info(
                    "Found %s in %s==%s (%s)", vuln_id, dep.name, dep.version, severity
                )

        logger.info("ThreatIntel: %d findings across %d dependencies", len(findings), len(dependencies))
        return findings
    
import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class ThreatIntelRecord:
    cve_id: str
    known_exploited: bool
    epss_score: float | None
    epss_percentile: float | None
    priority: str
    summary: str
    remediation_urgency: str
    sources: list[str]


class ThreatIntelEnricher:
    """Enriches CVE IDs with exploitability data from CISA KEV and EPSS."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def enrich_cves(
        self,
        cve_ids: list[str],
        cvss_scores: dict[str, float] | None = None,
    ) -> dict[str, ThreatIntelRecord]:
        """Enrich a list of CVE IDs with KEV and EPSS data.

        Args:
            cve_ids: List of CVE ID strings.
            cvss_scores: Optional mapping of CVE ID to known CVSS score.

        Returns:
            Dict mapping CVE ID to ThreatIntelRecord.
        """
        cvss_scores = cvss_scores or {}
        kev_set = self._fetch_kev()
        epss_map = self._fetch_epss(cve_ids)

        records: dict[str, ThreatIntelRecord] = {}
        for cve_id in cve_ids:
            cve_upper = cve_id.upper()
            known_exploited = cve_upper in kev_set
            epss_data = epss_map.get(cve_upper, {})
            epss_score = epss_data.get("epss")
            epss_percentile = epss_data.get("percentile")
            cvss = cvss_scores.get(cve_upper, 0.0)

            # Priority logic
            if known_exploited or (epss_score and epss_score >= 0.7):
                priority = "immediate"
            elif cvss >= 9.0 or (epss_score and epss_score >= 0.4):
                priority = "high"
            elif cvss >= 7.0 or (epss_score and epss_score >= 0.2):
                priority = "medium"
            else:
                priority = "monitor"

            urgency_map = {
                "immediate": "Patch within 24 hours — actively exploited or high EPSS.",
                "high": "Patch within 7 days — critical severity or elevated exploit probability.",
                "medium": "Patch within 30 days — moderate risk.",
                "monitor": "Monitor and patch in next scheduled cycle.",
            }

            sources = ["OSV"]
            if known_exploited:
                sources.append("CISA-KEV")
            if epss_score is not None:
                sources.append("EPSS")

            records[cve_upper] = ThreatIntelRecord(
                cve_id=cve_upper,
                known_exploited=known_exploited,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                priority=priority,
                summary=f"{'Known exploited. ' if known_exploited else ''}EPSS: {epss_score:.3f}" if epss_score else "No exploit data available.",
                remediation_urgency=urgency_map[priority],
                sources=sources,
            )

        return records

    def _fetch_kev(self) -> set[str]:
        """Fetch CISA Known Exploited Vulnerabilities list."""
        try:
            with httpx.Client(timeout=15) as client:
                response = client.get(self.CISA_KEV_URL)
                data = response.json()
                return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
        except Exception as exc:
            logger.warning("Failed to fetch CISA KEV: %s", exc)
            return set()

    def _fetch_epss(self, cve_ids: list[str]) -> dict[str, dict]:
        """Fetch EPSS scores for a list of CVE IDs."""
        if not cve_ids:
            return {}
        try:
            with httpx.Client(timeout=15) as client:
                # EPSS API accepts comma-separated CVE IDs
                params = {"cve": ",".join(cve_ids[:100])}  # cap at 100
                response = client.get(self.EPSS_URL, params=params)
                data = response.json()
                return {
                    item["cve"].upper(): {
                        "epss": float(item["epss"]),
                        "percentile": float(item["percentile"]),
                    }
                    for item in data.get("data", [])
                }
        except Exception as exc:
            logger.warning("Failed to fetch EPSS scores: %s", exc)
            return {}