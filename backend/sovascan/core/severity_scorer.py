"""Severity Scorer - applies contextual scoring to security findings.

Adjusts base severity scores based on file location, dependency type,
and domain-specific context (e.g., banking/financial keywords).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


@dataclass
class ScoredFinding:
    """A Finding with contextual scoring applied."""

    # Original finding fields
    id: str
    title: str
    description: str
    category: str
    file_path: str
    line_number: int
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Scoring fields
    base_score: float = 0.0
    contextual_modifiers: list[tuple[str, float]] = field(default_factory=list)
    final_score: float = 0.0
    severity: Severity = Severity.INFO
    original_severity: str = ""
    cvss_score: float = 0.0


# ── Banking & financial context keywords ───────────────────────────

BANKING_KEYWORDS: set[str] = {
    "payment", "transaction", "account", "banking", "upi",
    "neft", "rtgs", "imps", "kyc", "aadhar", "pan",
    "aadhaar", "ifsc", "swift", "iban", "credit", "debit",
    "wallet", "fintech", "ledger", "settlement", "merchant",
    "pci", "pci-dss", "cardholder", "cvv", "card_number",
    "routing_number", "wire_transfer", "escrow", "forex",
    "mutual_fund", "insurance", "loan", "emi", "rbi",
}

# ── Severity score mapping ─────────────────────────────────────────

SEVERITY_TO_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

# ── Directory patterns ─────────────────────────────────────────────

TEST_DIR_PATTERNS = re.compile(
    r"(?i)[\\/](?:test|tests|__tests__|spec|specs|testing|test_|_test)[\\/]"
)

EXAMPLE_DIR_PATTERNS = re.compile(
    r"(?i)[\\/](?:example|examples|sample|samples|demo|demos|fixtures|mock|mocks)[\\/]"
)

PROD_CONFIG_PATTERNS = re.compile(
    r"(?i)(?:prod|production|live|release|deploy|\.env\.prod|application-prod|docker-compose\.prod)"
)


class SeverityScorer:
    """Applies contextual severity scoring to security findings."""

    def __init__(self, banking_context: bool = True) -> None:
        """Initialize the scorer.

        Args:
            banking_context: Whether to apply banking/financial context modifiers.
        """
        self.banking_context = banking_context

    def score(self, finding: Any) -> ScoredFinding:
        """Score a finding with contextual modifiers.

        Args:
            finding: A Finding object (from CVEScanner or other detectors).

        Returns:
            ScoredFinding with contextual severity applied.
        """
        # Determine base score
        base_score = self._get_base_score(finding)
        modifiers: list[tuple[str, float]] = []

        file_path = getattr(finding, "file_path", "")

        # ── Contextual modifiers ───────────────────────────────────

        # +2 if file is in production config
        if PROD_CONFIG_PATTERNS.search(file_path):
            modifiers.append(("production_config", 2.0))

        # +1 if dependency is direct (not transitive)
        metadata = getattr(finding, "metadata", {})
        if metadata.get("is_transitive") is False and finding.category == "cve":
            modifiers.append(("direct_dependency", 1.0))

        # +1 if secret is in a non-test file
        if finding.category == "secret" and not TEST_DIR_PATTERNS.search(file_path):
            modifiers.append(("secret_non_test", 1.0))

        # +1.5 if banking/financial keyword in context
        if self.banking_context:
            banking_score = self._check_banking_context(finding)
            if banking_score > 0:
                modifiers.append(("banking_context", banking_score))

        # -1 if in test directory
        if TEST_DIR_PATTERNS.search(file_path):
            modifiers.append(("test_directory", -1.0))

        # -0.5 if in example/sample directory
        if EXAMPLE_DIR_PATTERNS.search(file_path):
            modifiers.append(("example_directory", -0.5))

        # ── Calculate final score ──────────────────────────────────

        modifier_total = sum(mod for _, mod in modifiers)
        final_score = max(0.0, min(10.0, base_score + modifier_total))
        severity = self._score_to_severity(final_score)

        return ScoredFinding(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            category=finding.category,
            file_path=finding.file_path,
            line_number=finding.line_number,
            evidence=finding.evidence,
            remediation=finding.remediation,
            references=getattr(finding, "references", []),
            tags=getattr(finding, "tags", []),
            metadata=metadata,
            base_score=base_score,
            contextual_modifiers=modifiers,
            final_score=round(final_score, 1),
            severity=severity,
            original_severity=getattr(finding, "severity", "info"),
            cvss_score=getattr(finding, "cvss_score", 0.0),
        )

    def score_all(self, findings: list) -> list[ScoredFinding]:
        """Score a list of findings.

        Args:
            findings: List of Finding objects.

        Returns:
            List of ScoredFinding objects, sorted by final_score descending.
        """
        scored = [self.score(f) for f in findings]
        scored.sort(key=lambda sf: sf.final_score, reverse=True)
        return scored

    def _get_base_score(self, finding: Any) -> float:
        """Determine the base severity score from CVSS or rule severity.

        Args:
            finding: Finding object.

        Returns:
            Base score as float (0-10).
        """
        # Prefer CVSS score if available and non-zero
        cvss = getattr(finding, "cvss_score", 0.0)
        if cvss and cvss > 0:
            return cvss

        # Fall back to severity string mapping
        severity_str = getattr(finding, "severity", "info").lower()
        return SEVERITY_TO_SCORE.get(severity_str, 0.5)

    def _check_banking_context(self, finding: Any) -> float:
        """Check if finding has banking/financial context.

        Args:
            finding: Finding object.

        Returns:
            Modifier value (0 or 1.5).
        """
        # Build a searchable context string from various finding fields
        context_parts: list[str] = []

        context_parts.append(getattr(finding, "file_path", "").lower())
        context_parts.append(getattr(finding, "evidence", "").lower())
        context_parts.append(getattr(finding, "description", "").lower())
        context_parts.append(getattr(finding, "title", "").lower())

        metadata = getattr(finding, "metadata", {})
        if isinstance(metadata, dict):
            context_value = metadata.get("context", "")
            if isinstance(context_value, str):
                context_parts.append(context_value.lower())

        tags = getattr(finding, "tags", [])
        context_parts.extend(t.lower() for t in tags)

        context_blob = " ".join(context_parts)

        for keyword in BANKING_KEYWORDS:
            if keyword in context_blob:
                return 1.5

        return 0.0

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        """Map a numerical score to a Severity enum.

        Thresholds:
            critical >= 9.0
            high >= 7.0
            medium >= 4.0
            low >= 1.0
            info < 1.0
        """
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 1.0:
            return Severity.LOW
        return Severity.INFO
