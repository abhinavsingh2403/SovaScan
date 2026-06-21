"""Rule Engine - loads, parses, and compiles YAML security rules."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Represents a compiled security scan rule."""

    id: str
    name: str
    description: str
    severity: str
    category: str
    pattern: str
    file_types: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    _compiled: re.Pattern | None = field(default=None, repr=False)

    def compile(self) -> re.Pattern:
        """Compile and cache the regex pattern."""
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                logger.error("Failed to compile pattern in rule %s: %s", self.id, exc)
                self._compiled = re.compile(r"(?!)")
        return self._compiled


class RuleEngine:
    """Manages loading and compilation of YAML rules."""

    def __init__(self, rules_dir: str | Path) -> None:
        """Initialize the rule engine.

        Args:
            rules_dir: Path to directory containing rule files.
        """
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []

    def load_rules(self) -> list[Rule]:
        """Load all YAML rules from the rules directory.

        Returns:
            List of compiled Rule objects.
        """
        self.rules = []
        if not self.rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self.rules_dir)
            return self.rules

        yaml_files = list(self.rules_dir.rglob("*.yaml")) + list(self.rules_dir.rglob("*.yml"))
        for rule_file in yaml_files:
            try:
                with open(rule_file, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)

                if not data:
                    continue

                if isinstance(data, list):
                    for r_data in data:
                        rule = self._parse_rule(r_data)
                        if rule:
                            self.rules.append(rule)
                elif isinstance(data, dict):
                    if "rules" in data:
                        for r_data in data["rules"]:
                            rule = self._parse_rule(r_data)
                            if rule:
                                self.rules.append(rule)
                    else:
                        rule = self._parse_rule(data)
                        if rule:
                            self.rules.append(rule)
            except Exception as exc:
                logger.error("Failed to load rule from %s: %s", rule_file, exc)

        logger.info("RuleEngine loaded %d rules", len(self.rules))
        return self.rules

    def _parse_rule(self, data: dict[str, Any]) -> Rule | None:
        """Parse raw YAML dict into a Rule dataclass."""
        if "id" not in data or "name" not in data or "pattern" not in data:
            return None

        rule = Rule(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium").lower(),
            category=data.get("category", "misconfiguration").lower(),
            pattern=data["pattern"],
            file_types=data.get("file_types", ["*"]),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
        )
        if rule.enabled:
            rule.compile()
            return rule
        return None
