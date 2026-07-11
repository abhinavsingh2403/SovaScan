"""Scan Orchestrator - coordinates the 5-phase security scan pipeline.

Discovers manifests, resolves dependencies, executes scanners, scores severity,
and produces structured outputs.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sovascan.core.config_drift import ConfigDriftAnalyzer
from sovascan.core.cve_scanner import CVEScanner, Finding
from sovascan.core.dependency_resolver import Dependency, DependencyResolver
from sovascan.core.misconfig_detector import MisconfigDetector
from sovascan.core.secret_scanner import SecretScanner
from sovascan.core.severity_scorer import ScoredFinding, Severity, SeverityScorer
from sovascan.core.sast_scanner import SASTScanner
from sovascan.core.git_history_scanner import GitHistoryScanner

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """The result of a completed security scan."""

    target_path: str
    scan_type: str
    findings: list[ScoredFinding] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    duration: float = 0.0
    total_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    sbom: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class ScanOrchestrator:
    """Orchestrates the discovery, analysis, detection, scoring, and reporting phases."""

    def __init__(
        self,
        target_path: str | Path,
        scan_type: str = "full",
        rules_dir: str | Path | None = None,
        baselines_dir: str | Path | None = None,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> None:
        """Initialize the scan orchestrator.

        Args:
            target_path: Target directory or file to scan.
            scan_type: Type of scan to run ('full', 'dependencies', 'secrets', 'misconfig', 'drift').
            rules_dir: Optional custom rules directory.
            baselines_dir: Optional custom config baselines directory.
            progress_callback: Optional progress update hook.
        """
        self.target_path = Path(target_path).resolve()
        self.scan_type = scan_type.lower().strip()

        # Resolve rules directory relative to backend/sovascan root if not provided
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            self.rules_dir = Path(__file__).parents[1] / "rules"

        self.baselines_dir = Path(baselines_dir) if baselines_dir else None
        self.progress_callback = progress_callback

    def _update_progress(self, phase: str, percentage: float) -> None:
        """Trigger the progress callback if registered."""
        if self.progress_callback:
            try:
                self.progress_callback(phase, percentage)
            except Exception as exc:
                logger.error("Progress callback failed: %s", exc)

    def run_scan(self) -> ScanResult:
        """Execute the 5-phase scan pipeline.

        Returns:
            A populated ScanResult instance.
        """
        start_time = time.time()
        logger.info("Starting scan of target: %s (Type: %s)", self.target_path, self.scan_type)

        # Phase 1: Discovery
        self._update_progress("Discovering manifest files", 10.0)
        manifests = self._discover_manifests()

        # Phase 2: Dependency Resolution
        self._update_progress("Resolving dependencies", 25.0)
        dependencies: list[Dependency] = []
        if self.scan_type in ("full", "dependencies"):
            resolver = DependencyResolver()
            for manifest in manifests:
                try:
                    resolved = resolver.resolve(manifest)
                    dependencies.extend(resolved)
                except Exception as exc:
                    logger.error("Failed to resolve dependency for %s: %s", manifest, exc)

        # Phase 3: Detection
        self._update_progress("Scanning target for vulnerabilities and config issues", 50.0)
        raw_findings: list[Finding] = []

        # 3.1 CVE scanning
        if self.scan_type in ("full", "dependencies") and dependencies:
            cve_scanner = CVEScanner()
            try:
                raw_findings.extend(cve_scanner.scan(dependencies))
            except Exception as exc:
                logger.error("CVE Scan failed: %s", exc)

        # 3.2 Misconfiguration detection
        if self.scan_type in ("full", "misconfig"):
            misconfig_detector = MisconfigDetector(self.rules_dir)
            try:
                raw_findings.extend(misconfig_detector.scan(self.target_path))
            except Exception as exc:
                logger.error("Misconfiguration detector failed: %s", exc)

        # 3.3 Secrets scanning
        if self.scan_type in ("full", "secrets"):
            secret_scanner = SecretScanner()
            try:
                raw_findings.extend(secret_scanner.scan(self.target_path))
            except Exception as exc:
                logger.error("Secret scanner failed: %s", exc)

        # 3.4 Config drift analysis
        if self.scan_type in ("full", "drift") and self.baselines_dir:
            drift_analyzer = ConfigDriftAnalyzer(self.baselines_dir)
            try:
                raw_findings.extend(drift_analyzer.analyze(self.target_path))
            except Exception as exc:
                logger.error("Config drift analysis failed: %s", exc)

        # 3.5 SAST scanning (Bandit + Semgrep)
        if self.scan_type in ("full", "sast"):
            self._update_progress("Running SAST analysis (Bandit + Semgrep)", 60.0)
            sast_scanner = SASTScanner()
            try:
                raw_findings.extend(sast_scanner.scan(self.target_path))
            except Exception as exc:
                logger.error("SAST scan failed: %s", exc)

        # 3.6 Git history secrets scanning
        if self.scan_type in ("full", "git-history"):
            self._update_progress("Scanning git history for leaked secrets", 70.0)
            git_scanner = GitHistoryScanner()
            try:
                raw_findings.extend(git_scanner.scan(self.target_path))
            except Exception as exc:
                logger.error("Git history scan failed: %s", exc)

        # Phase 4: Severity Scoring
        self._update_progress("Applying contextual severity scoring", 80.0)
        scorer = SeverityScorer()
        scored_findings: list[ScoredFinding] = []
        for finding in raw_findings:
            try:
                scored = scorer.score(finding)
                scored_findings.append(scored)
            except Exception as exc:
                logger.error("Failed to score finding %s: %s", finding.id, exc)
                # Fallback to unscored severity
                scored_findings.append(
                    ScoredFinding(
                        id=finding.id,
                        title=finding.title,
                        description=finding.description,
                        category=finding.category,
                        file_path=finding.file_path,
                        line_number=finding.line_number,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        references=finding.references,
                        tags=finding.tags,
                        metadata=finding.metadata,
                        base_score=5.0,
                        final_score=5.0,
                        severity=Severity(finding.severity) if finding.severity in [s.value for s in Severity] else Severity.MEDIUM,
                        original_severity=finding.severity,
                        cvss_score=finding.cvss_score,
                    )
                )

        # Phase 5: Reporting
        self._update_progress("Packaging scan report", 95.0)
        duration = time.time() - start_time

        # Calculate counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for sf in scored_findings:
            severity_counts[sf.severity.value] += 1

        # Generate SBOM
        packages = []
        for d in dependencies:
            packages.append({
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "license": getattr(d, "license", None) or "MIT",
                "purl": f"pkg:{d.ecosystem}/{d.name}@{d.version}"
            })

        sbom = {
            "format": "cyclonedx",
            "packages": packages,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        # Build scanned manifests manifest
        scanned_manifest_paths = []
        for manifest in manifests:
            try:
                scanned_manifest_paths.append(str(manifest.relative_to(self.target_path)))
            except ValueError:
                scanned_manifest_paths.append(str(manifest))

        rules_loaded_count = 0
        if self.scan_type in ("full", "misconfig"):
            try:
                rules_loaded_count = len(MisconfigDetector(self.rules_dir).rules)
            except Exception as exc:
                logger.debug("Failed to get rules count: %s", exc)

        result = ScanResult(
            target_path=str(self.target_path),
            scan_type=self.scan_type,
            findings=scored_findings,
            dependencies=dependencies,
            duration=round(duration, 2),
            total_findings=len(scored_findings),
            severity_counts=severity_counts,
            sbom=sbom,
            metadata={
                "manifests_scanned": scanned_manifest_paths,
                "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "rules_loaded": rules_loaded_count
            }
        )

        self._update_progress("Scan complete", 100.0)
        return result

    def _discover_manifests(self) -> list[Path]:
        """Traverse target path to find supported manifest files."""
        manifests: list[Path] = []
        manifest_names = {"package.json", "requirements.txt", "pom.xml", "Pipfile.lock"}
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

        if self.target_path.is_file():
            if self.target_path.name in manifest_names:
                return [self.target_path]
            return []

        for item in self.target_path.rglob("*"):
            if item.is_dir():
                continue
            if any(part in skip_dirs for part in item.parts):
                continue
            if item.name in manifest_names:
                manifests.append(item)

        return manifests
