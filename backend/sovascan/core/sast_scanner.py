"""SAST Scanner — wraps Bandit and Semgrep for static application security testing.

Runs external SAST tools as subprocesses, parses their JSON output, and returns
unified Finding objects compatible with the SovaScan orchestrator pipeline.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from sovascan.core.cve_scanner import Finding

logger = logging.getLogger(__name__)


def _map_semgrep_severity(sev: str) -> str:
    """Map Semgrep severity levels to SovaScan severity strings."""
    return {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }.get(sev.upper(), "low")


def _map_bandit_severity(sev: str) -> str:
    """Map Bandit severity levels to SovaScan severity strings."""
    return {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(sev.upper(), "low")


class SASTScanner:
    """Static Application Security Testing scanner wrapping Bandit and Semgrep.

    Runs external SAST tools against the target directory, parses their JSON
    output, and returns a unified list of Finding objects. If a tool binary
    is not installed the scanner gracefully returns zero findings.
    """

    def __init__(self, timeout: int = 300) -> None:
        """Initialize the SAST scanner.

        Args:
            timeout: Maximum seconds to wait for each subprocess.
        """
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target_path: str | Path) -> list[Finding]:
        """Run all available SAST tools against *target_path*.

        Args:
            target_path: Root directory to scan.

        Returns:
            Combined list of Finding objects from all tools.
        """
        target = Path(target_path).resolve()
        if not target.exists():
            logger.warning("SAST target does not exist: %s", target)
            return []

        findings: list[Finding] = []
        findings.extend(self._run_semgrep(target))
        findings.extend(self._run_bandit(target))

        logger.info("SAST scan complete — %d findings from %s", len(findings), target)
        return findings

    # ------------------------------------------------------------------
    # Tool availability
    # ------------------------------------------------------------------

    @staticmethod
    def _is_tool_available(tool_name: str) -> bool:
        """Check whether *tool_name* is available on PATH."""
        return shutil.which(tool_name) is not None

    # ------------------------------------------------------------------
    # Semgrep
    # ------------------------------------------------------------------

    def _run_semgrep(self, target: Path) -> list[Finding]:
        """Run Semgrep with the auto ruleset against *target*."""
        if not self._is_tool_available("semgrep"):
            logger.info("semgrep not installed — skipping SAST/Semgrep scan")
            return []

        try:
            proc = subprocess.run(  # noqa: S603, S607
                ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(target)],  # noqa: S607
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("semgrep timed out after %ds for %s", self.timeout, target)
            return []
        except OSError as exc:
            logger.warning("Failed to run semgrep: %s", exc)
            return []

        if not proc.stdout:
            if proc.stderr:
                logger.debug("semgrep stderr: %s", proc.stderr[:500])
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.exception("Failed to parse semgrep JSON output")
            return []

        findings: list[Finding] = []
        for result in payload.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            rule_id = result.get("check_id", "SEMGREP-UNKNOWN")
            findings.append(
                Finding(
                    id=rule_id,
                    title=extra.get("message", "Semgrep finding")[:200],
                    description=extra.get("message", ""),
                    severity=_map_semgrep_severity(extra.get("severity", "INFO")),
                    category="sast",
                    file_path=result.get("path", ""),
                    line_number=result.get("start", {}).get("line"),
                    evidence=extra.get("lines", ""),
                    remediation=metadata.get("fix", "") or "Review and remediate per Semgrep rule guidance.",
                    references=[metadata.get("source-url", "")] if metadata.get("source-url") else [],
                    tags=["sast", "semgrep"],
                    cvss_score=None,
                    metadata={"tool": "semgrep", "check_id": rule_id},
                )
            )

        logger.info("Semgrep produced %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Bandit
    # ------------------------------------------------------------------

    def _run_bandit(self, target: Path) -> list[Finding]:
        """Run Bandit against Python files in *target*."""
        if not self._is_tool_available("bandit"):
            logger.info("bandit not installed — skipping SAST/Bandit scan")
            return []

        try:
            proc = subprocess.run(  # noqa: S603, S607
                ["bandit", "-r", str(target), "-f", "json"],  # noqa: S607
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("bandit timed out after %ds for %s", self.timeout, target)
            return []
        except OSError as exc:
            logger.warning("Failed to run bandit: %s", exc)
            return []

        # bandit exits non-zero when it finds issues — don't gate on returncode
        if not proc.stdout:
            if proc.stderr:
                logger.debug("bandit stderr: %s", proc.stderr[:500])
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.exception("Failed to parse bandit JSON output")
            return []

        findings: list[Finding] = []
        for result in payload.get("results", []):
            test_id = result.get("test_id", "BANDIT-UNKNOWN")
            cwe = result.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe.get('id')}" if isinstance(cwe, dict) and cwe.get("id") else None
            findings.append(
                Finding(
                    id=test_id,
                    title=result.get("test_name", "Bandit finding"),
                    description=result.get("issue_text", ""),
                    severity=_map_bandit_severity(result.get("issue_severity", "LOW")),
                    category="sast",
                    file_path=result.get("filename", ""),
                    line_number=result.get("line_number"),
                    evidence=result.get("code", ""),
                    remediation=f"See Bandit docs for {test_id}: {result.get('more_info', '')}",
                    references=[result.get("more_info", "")] if result.get("more_info") else [],
                    tags=["sast", "bandit"],
                    cvss_score=None,
                    metadata={"tool": "bandit", "test_id": test_id, "cwe": cwe_id},
                )
            )

        logger.info("Bandit produced %d findings", len(findings))
        return findings
