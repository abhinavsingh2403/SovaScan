"""Secret Scanner - detects hardcoded secrets, credentials, and API keys.

Performs entropy-based analysis and pattern matching to find secrets
accidentally committed to source code and configuration files.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecretPattern:
    """A compiled secret detection pattern."""

    name: str
    pattern: re.Pattern
    severity: str
    description: str
    tags: list[str] = field(default_factory=list)


# ── Built-in Secret Patterns ──────────────────────────────────────────────

_RAW_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "severity": "critical",
        "description": "AWS Access Key ID detected. These provide direct access to AWS services.",
        "tags": ["aws", "cloud", "credential"],
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"""(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        "severity": "critical",
        "description": "AWS Secret Access Key detected.",
        "tags": ["aws", "cloud", "credential"],
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"(?<![a-zA-Z0-9_])(ghp_[a-zA-Z0-9]{36,255})(?![a-zA-Z0-9_])",
        "severity": "critical",
        "description": "GitHub Personal Access Token detected.",
        "tags": ["github", "token", "scm"],
    },
    {
        "name": "GitHub OAuth Access Token",
        "pattern": r"(?<![a-zA-Z0-9_])(gho_[a-zA-Z0-9]{36,255})(?![a-zA-Z0-9_])",
        "severity": "critical",
        "description": "GitHub OAuth Access Token detected.",
        "tags": ["github", "token", "scm"],
    },
    {
        "name": "GitHub App Installation Token",
        "pattern": r"(?<![a-zA-Z0-9_])(ghs_[a-zA-Z0-9]{36,255})(?![a-zA-Z0-9_])",
        "severity": "high",
        "description": "GitHub App Installation Token detected.",
        "tags": ["github", "token", "scm"],
    },
    {
        "name": "GitHub Refresh Token",
        "pattern": r"(?<![a-zA-Z0-9_])(ghr_[a-zA-Z0-9]{36,255})(?![a-zA-Z0-9_])",
        "severity": "high",
        "description": "GitHub Refresh Token detected.",
        "tags": ["github", "token", "scm"],
    },
    {
        "name": "Generic API Key Assignment",
        "pattern": r"""(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{16,64})['"]?""",
        "severity": "high",
        "description": "Hardcoded API key or token detected.",
        "tags": ["api", "credential"],
    },
    {
        "name": "Password in Configuration",
        "pattern": r"""(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?""",
        "severity": "high",
        "description": "Hardcoded password detected in configuration.",
        "tags": ["password", "credential", "config"],
    },
    {
        "name": "RSA Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "critical",
        "description": "RSA private key detected. Private keys must never be committed to source control.",
        "tags": ["private-key", "crypto"],
    },
    {
        "name": "EC Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "critical",
        "description": "EC private key detected.",
        "tags": ["private-key", "crypto"],
    },
    {
        "name": "DSA Private Key",
        "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
        "severity": "critical",
        "description": "DSA private key detected.",
        "tags": ["private-key", "crypto"],
    },
    {
        "name": "Generic Private Key",
        "pattern": r"-----BEGIN PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private key detected.",
        "tags": ["private-key", "crypto"],
    },
    {
        "name": "JWT Token",
        "pattern": r"(?<![a-zA-Z0-9_])(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})(?![a-zA-Z0-9_])",
        "severity": "high",
        "description": "JSON Web Token (JWT) detected. JWTs may contain sensitive claims.",
        "tags": ["jwt", "token", "auth"],
    },
    {
        "name": "Database Connection String with Password",
        "pattern": r"""(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|oracle)://[^:\s]+:([^@\s]{3,})@[^\s]+""",
        "severity": "critical",
        "description": "Database connection string with embedded credentials detected.",
        "tags": ["database", "credential", "connection-string"],
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}",
        "severity": "high",
        "description": "Slack webhook URL detected. This can be used to send messages to Slack channels.",
        "tags": ["slack", "webhook"],
    },
    {
        "name": "Discord Webhook URL",
        "pattern": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+",
        "severity": "high",
        "description": "Discord webhook URL detected.",
        "tags": ["discord", "webhook"],
    },
    {
        "name": "Slack Bot Token",
        "pattern": r"(?<![a-zA-Z0-9_])(xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})(?![a-zA-Z0-9_])",
        "severity": "critical",
        "description": "Slack Bot Token detected.",
        "tags": ["slack", "token", "bot"],
    },
    {
        "name": "Google API Key",
        "pattern": r"(?<![a-zA-Z0-9_])(AIza[0-9A-Za-z_-]{35})(?![a-zA-Z0-9_])",
        "severity": "high",
        "description": "Google API Key detected.",
        "tags": ["google", "api", "cloud"],
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"(?<![a-zA-Z0-9_])(sk_live_[0-9a-zA-Z]{24,})(?![a-zA-Z0-9_])",
        "severity": "critical",
        "description": "Stripe secret key detected. This provides access to payment processing.",
        "tags": ["stripe", "payment", "banking"],
    },
]

COMPILED_PATTERNS: list[SecretPattern] = []
for _p in _RAW_PATTERNS:
    COMPILED_PATTERNS.append(
        SecretPattern(
            name=_p["name"],
            pattern=re.compile(_p["pattern"]),
            severity=_p["severity"],
            description=_p["description"],
            tags=_p.get("tags", []),
        )
    )

# ── Skip lists ──────────────────────────────────────────────────────

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".eggs", ".mypy_cache", ".pytest_cache", "dist",
    "build", ".next", ".nuxt", "coverage",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".o",
    ".sqlite", ".db", ".lock",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


class SecretScanner:
    """Scans source trees for hardcoded secrets and credentials."""

    def __init__(
        self,
        extra_patterns: list[SecretPattern] | None = None,
        entropy_threshold: float = 4.5,
    ) -> None:
        """Initialize the secret scanner.

        Args:
            extra_patterns: Additional patterns to scan for.
            entropy_threshold: Shannon entropy threshold for high-entropy detection.
        """
        self.patterns = list(COMPILED_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)
        self.entropy_threshold = entropy_threshold

    def scan(self, target_path: str | Path) -> list:
        """Scan a target path for hardcoded secrets.

        Args:
            target_path: File or directory to scan.

        Returns:
            List of Finding objects.
        """
        from sovascan.core.cve_scanner import Finding

        target = Path(target_path)
        findings: list[Finding] = []

        if target.is_file():
            files = [target]
        else:
            files = self._discover_files(target)

        logger.info("Scanning %d files for secrets", len(files))

        for file_path in files:
            try:
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
            except Exception as exc:
                logger.debug("Error scanning %s: %s", file_path, exc)

        logger.info("Found %d secret findings", len(findings))
        return findings

    def _discover_files(self, target: Path) -> list[Path]:
        """Discover all scannable files under a directory."""
        files: list[Path] = []

        for item in target.rglob("*"):
            if not item.is_file():
                continue

            # Skip excluded directories
            if any(part in SKIP_DIRS for part in item.parts):
                continue

            # Skip binary files
            if item.suffix.lower() in BINARY_EXTENSIONS:
                continue

            # Skip files that are too large
            try:
                if item.stat().st_size > MAX_FILE_SIZE:
                    continue
                if item.stat().st_size == 0:
                    continue
            except OSError:
                continue

            files.append(item)

        return files

    def _scan_file(self, file_path: Path) -> list:
        """Scan a single file for secret patterns and high-entropy strings.

        Args:
            file_path: Path to file to scan.

        Returns:
            List of Finding objects.
        """
        from sovascan.core.cve_scanner import Finding

        findings: list[Finding] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.split("\n")

        # Pattern-based scanning
        for secret_pattern in self.patterns:
            for match in secret_pattern.pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                matched_text = match.group(0)
                masked = self._mask_secret(matched_text)

                # Context lines
                start_ctx = max(0, line_num - 2)
                end_ctx = min(len(lines), line_num + 1)
                context = "\n".join(lines[start_ctx:end_ctx])

                findings.append(
                    Finding(
                        id=f"SECRET-{secret_pattern.name.upper().replace(' ', '-')[:30]}",
                        title=secret_pattern.name,
                        description=secret_pattern.description,
                        severity=secret_pattern.severity,
                        category="secret",
                        file_path=str(file_path),
                        line_number=line_num,
                        evidence=masked,
                        remediation=(
                            "Remove the hardcoded secret and use environment variables "
                            "or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). "
                            "Rotate the exposed credential immediately."
                        ),
                        references=[],
                        tags=secret_pattern.tags,
                        metadata={"context": context, "pattern_name": secret_pattern.name},
                    )
                )

        # Entropy-based scanning for potential base64-encoded secrets
        for i, line in enumerate(lines, start=1):
            # Look for assignment-like patterns with high-entropy values
            entropy_matches = re.finditer(
                r"""(?i)(?:secret|token|key|password|credential|auth)\s*[=:]\s*['"]?([a-zA-Z0-9+/=_-]{20,})['"]?""",
                line,
            )
            for match in entropy_matches:
                value = match.group(1)
                if self._is_high_entropy(value, self.entropy_threshold):
                    # Check it wasn't already detected by a specific pattern
                    already_found = any(
                        f.file_path == str(file_path) and f.line_number == i
                        for f in findings
                    )
                    if not already_found:
                        masked = self._mask_secret(value)
                        findings.append(
                            Finding(
                                id="SECRET-HIGH-ENTROPY",
                                title="High-Entropy Secret Detected",
                                description=(
                                    "A high-entropy string was found in an assignment context, "
                                    "suggesting a potential hardcoded secret or encoded credential."
                                ),
                                severity="medium",
                                category="secret",
                                file_path=str(file_path),
                                line_number=i,
                                evidence=masked,
                                remediation=(
                                    "Review this value. If it is a secret, remove it and use "
                                    "environment variables or a secrets management solution."
                                ),
                                tags=["entropy", "potential-secret"],
                                metadata={
                                    "entropy": round(self._calculate_entropy(value), 2),
                                    "threshold": self.entropy_threshold,
                                },
                            )
                        )

        return findings

    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            string: Input string.

        Returns:
            Shannon entropy value (bits per character).
        """
        if not string:
            return 0.0

        length = len(string)
        freq: dict[str, int] = {}
        for ch in string:
            freq[ch] = freq.get(ch, 0) + 1

        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def _is_high_entropy(string: str, threshold: float = 4.5) -> bool:
        """Check if a string has high Shannon entropy, suggesting randomness.

        Args:
            string: Input string.
            threshold: Minimum entropy to be considered high.

        Returns:
            True if entropy exceeds threshold.
        """
        if len(string) < 16:
            return False
        entropy = SecretScanner._calculate_entropy(string)
        return entropy >= threshold

    @staticmethod
    def _mask_secret(value: str) -> str:
        """Mask a secret value, showing only first and last 4 characters.

        Args:
            value: Secret value to mask.

        Returns:
            Masked string like 'ghp_****...****abcd'.
        """
        if len(value) <= 8:
            return "*" * len(value)

        prefix = value[:4]
        suffix = value[-4:]
        masked_len = len(value) - 8
        return f"{prefix}{'*' * min(masked_len, 20)}...{suffix}"
