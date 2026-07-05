"""Misconfiguration Detector - scans configuration files against YAML rules.

Loads rule definitions from YAML files and applies regex-based pattern
matching against configuration files to detect security misconfigurations.
"""

from __future__ import annotations

import ast
import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# File extensions that are configuration files
CONFIG_EXTENSIONS = {
    ".yml", ".yaml", ".json", ".xml", ".properties",
    ".ini", ".cfg", ".conf", ".toml", ".env",
    ".py", ".java", ".js", ".ts",
}

CONFIG_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".eslintrc", ".babelrc", "nginx.conf",
    "httpd.conf", "my.cnf", "pg_hba.conf", "redis.conf",
    "application.properties", "application.yml", "web.xml",
    "pom.xml", "build.gradle", "Makefile", "Vagrantfile",
    "Procfile", ".htaccess", "supervisord.conf",
}


@dataclass
class MisconfigRule:
    """A single misconfiguration detection rule."""

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
    _compiled: Any = field(default=None, repr=False)

    def compile_pattern(self) -> re.Pattern:
        """Compile and cache the regex pattern."""
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                logger.error("Invalid regex in rule %s: %s", self.id, exc)
                self._compiled = re.compile(r"(?!)")  # never-match pattern
        return self._compiled


class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor to check Python configuration and security issues structurally."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings_data: list[dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check variable assignments (e.g. DEBUG = True, allow_origins = ["*"])
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_assignment(target.id, node.value, node.lineno)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self._check_assignment(elt.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_assignment(self, var_name: str, value_node: ast.AST, lineno: int) -> None:
        name_lower = var_name.lower()
        
        # 1. SOVA-WEB-001: Debug Mode Enabled
        if name_lower in ("debug", "dev_mode"):
            is_true = False
            if isinstance(value_node, ast.Constant) and value_node.value in (True, 1, "on", "yes"):
                is_true = True
            elif isinstance(value_node, ast.Name) and value_node.id == "True":
                is_true = True
            
            if is_true:
                self.findings_data.append({
                    "rule_id": "SOVA-WEB-001",
                    "title": "Debug Mode Enabled in Web Configuration",
                    "description": "Running web frameworks in debug/development mode leaks stack traces, environment variables, and system details",
                    "severity": "critical",
                    "line_number": lineno,
                    "evidence": f"{var_name} = {ast.unparse(value_node) if hasattr(ast, 'unparse') else 'True'}",
                    "remediation": "Set DEBUG=False or equivalent in production environments.",
                    "category": "web",
                    "references": ["https://cwe.mitre.org/data/definitions/489.html"],
                    "tags": ["web", "debug", "disclosure"]
                })
        
        # 2. SOVA-WEB-003: CORS Wildcard Origin Allowed
        elif name_lower in ("allow_origins", "cors_origins", "access_control_allow_origin", "cors_origin"):
            is_wildcard = False
            evidence_str = ""
            if isinstance(value_node, ast.Constant) and value_node.value == "*":
                is_wildcard = True
                evidence_str = f"{var_name} = '*'"
            elif isinstance(value_node, ast.List):
                for elt in value_node.elts:
                    if isinstance(elt, ast.Constant) and elt.value == "*":
                        is_wildcard = True
                        evidence_str = f"{var_name} = {ast.unparse(value_node) if hasattr(ast, 'unparse') else '[\"*\"]'}"
                        break
            
            if is_wildcard:
                self.findings_data.append({
                    "rule_id": "SOVA-WEB-003",
                    "title": "CORS Wildcard Origin Allowed",
                    "description": "Wildcard Access-Control-Allow-Origin header allows any site to access client API responses",
                    "severity": "high",
                    "line_number": lineno,
                    "evidence": evidence_str,
                    "remediation": "Specify exact allowed domains in the Access-Control-Allow-Origin configuration instead of using wildcard '*'.",
                    "category": "web",
                    "references": ["https://cwe.mitre.org/data/definitions/942.html"],
                    "tags": ["web", "cors", "network"]
                })

    def visit_Call(self, node: ast.Call) -> None:
        # 3. SOVA-CRYPTO-001: Weak Hashing Algorithm (md5, sha1 calls)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                method = node.func.attr
                if method in ("md5", "sha1"):
                    self.findings_data.append({
                        "rule_id": "SOVA-CRYPTO-001",
                        "title": "Weak Hashing Algorithm Detected",
                        "description": "Use of MD5 or SHA-1 for cryptographic purposes is insecure",
                        "severity": "high",
                        "line_number": node.lineno,
                        "evidence": f"hashlib.{method}()",
                        "remediation": "Replace with SHA-256 or stronger hashing algorithm (SHA-384, SHA-512, bcrypt for passwords)",
                        "category": "cryptographic",
                        "references": ["https://cwe.mitre.org/data/definitions/328.html"],
                        "tags": ["crypto", "hashing", "banking"]
                    })
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("md5", "sha1"):
                self.findings_data.append({
                    "rule_id": "SOVA-CRYPTO-001",
                    "title": "Weak Hashing Algorithm Detected",
                    "description": "Use of MD5 or SHA-1 for cryptographic purposes is insecure",
                    "severity": "high",
                    "line_number": node.lineno,
                    "evidence": f"{func_name}()",
                    "remediation": "Replace with SHA-256 or stronger hashing algorithm (SHA-384, SHA-512, bcrypt for passwords)",
                    "category": "cryptographic",
                    "references": ["https://cwe.mitre.org/data/definitions/328.html"],
                    "tags": ["crypto", "hashing", "banking"]
                })
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # 4. SOVA-CRYPTO-005: Insecure TLS/SSL Protocol Version
        if isinstance(node.value, ast.Name) and node.value.id == "ssl":
            attr_name = node.attr
            if attr_name in ("PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"):
                self.findings_data.append({
                    "rule_id": "SOVA-CRYPTO-005",
                    "title": "Insecure TLS/SSL Protocol Version",
                    "description": "Legacy TLS/SSL protocols (TLS 1.0, 1.1, SSLv2, SSLv3) are vulnerable to various attacks",
                    "severity": "high",
                    "line_number": node.lineno,
                    "evidence": f"ssl.{attr_name}",
                    "remediation": "Upgrade configuration to require TLS 1.2 or TLS 1.3 (e.g., tls_version = TLSv1_2 or similar)",
                    "category": "cryptographic",
                    "references": ["https://cwe.mitre.org/data/definitions/327.html"],
                    "tags": ["crypto", "tls", "security"]
                })
        self.generic_visit(node)


class MisconfigDetector:
    """Detects security misconfigurations using YAML-based rules."""

    def __init__(self, rules_dir: str | Path) -> None:
        """Initialize the detector with a rules directory.

        Args:
            rules_dir: Path to directory containing YAML rule files.
        """
        self.rules_dir = Path(rules_dir)
        self.rules: list[MisconfigRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all YAML rule files from the rules directory tree."""
        if not self.rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self.rules_dir)
            return

        yaml_files = list(self.rules_dir.rglob("*.yaml")) + list(self.rules_dir.rglob("*.yml"))
        logger.info("Found %d rule files in %s", len(yaml_files), self.rules_dir)

        for rule_file in sorted(yaml_files):
            try:
                with open(rule_file, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)

                if data is None:
                    continue

                # Handle files with multiple rules (list at top level)
                if isinstance(data, list):
                    for rule_data in data:
                        rule = self._parse_rule(rule_data, rule_file)
                        if rule and rule.enabled:
                            self.rules.append(rule)
                elif isinstance(data, dict):
                    # Single rule or rules under a key
                    if "rules" in data:
                        for rule_data in data["rules"]:
                            rule = self._parse_rule(rule_data, rule_file)
                            if rule and rule.enabled:
                                self.rules.append(rule)
                    else:
                        rule = self._parse_rule(data, rule_file)
                        if rule and rule.enabled:
                            self.rules.append(rule)
            except (yaml.YAMLError, OSError) as exc:
                logger.error("Failed to load rule file %s: %s", rule_file, exc)

        logger.info("Loaded %d active rules", len(self.rules))

    @staticmethod
    def _parse_rule(data: dict, source_file: Path) -> MisconfigRule | None:
        """Parse a single rule from YAML data."""
        required_fields = ["id", "name", "pattern"]
        for field_name in required_fields:
            if field_name not in data:
                logger.warning(
                    "Rule in %s missing required field '%s', skipping",
                    source_file, field_name,
                )
                return None

        return MisconfigRule(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            category=data.get("category", "misconfiguration"),
            pattern=data["pattern"],
            file_types=data.get("file_types", ["*"]),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
        )

    def scan(self, target_path: str | Path) -> list:
        """Scan a target directory for misconfigurations.

        Args:
            target_path: Root directory to scan.

        Returns:
            List of Finding objects.
        """
        from sovascan.core.cve_scanner import Finding

        target = Path(target_path)
        findings: list[Finding] = []

        if not target.exists():
            logger.error("Target path does not exist: %s", target)
            return findings

        config_files = self._discover_config_files(target)
        logger.info("Discovered %d configuration files to scan", len(config_files))

        for config_file in config_files:
            file_findings = self._scan_file(config_file, self.rules)
            findings.extend(file_findings)

        logger.info("Detected %d misconfigurations", len(findings))
        return findings

    def _discover_config_files(self, target: Path) -> list[Path]:
        """Find all configuration files under target directory."""
        config_files: list[Path] = []

        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".eggs"}

        if target.is_file():
            return [target]

        for item in target.rglob("*"):
            if item.is_dir():
                continue

            # Skip excluded directories
            if any(part in skip_dirs for part in item.parts):
                continue

            # Check by extension or by known filename
            if item.suffix.lower() in CONFIG_EXTENSIONS or item.name in CONFIG_FILENAMES:
                config_files.append(item)

        return config_files

    def _scan_file(self, file_path: Path, rules: list[MisconfigRule]) -> list:
        """Scan a single file against all applicable rules.

        Args:
            file_path: Path to the configuration file.
            rules: List of rules to check.

        Returns:
            List of Finding objects.
        """
        from sovascan.core.cve_scanner import Finding

        findings: list[Finding] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read file %s: %s", file_path, exc)
            return findings

        # Run AST scanning for Python files to avoid false positives in comments/logs
        is_python_file = file_path.suffix.lower() == ".py"
        if is_python_file:
            findings.extend(self._scan_python_ast(file_path, content))

        AST_HANDLED_RULES = {"SOVA-WEB-001", "SOVA-WEB-003", "SOVA-CRYPTO-001", "SOVA-CRYPTO-005"}

        for rule in rules:
            if is_python_file and rule.id in AST_HANDLED_RULES:
                # Handled cleanly by AST visitor
                continue

            if not self._file_matches_rule(file_path, rule):
                continue

            matches = self._match_pattern(content, rule.compile_pattern())
            for line_num, matched_text, context in matches:
                findings.append(
                    Finding(
                        id=rule.id,
                        title=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        category="misconfig",
                        file_path=str(file_path),
                        line_number=line_num,
                        evidence=matched_text[:200],
                        remediation=rule.remediation,
                        references=rule.references,
                        tags=rule.tags,
                        metadata={
                            "rule_category": rule.category,
                            "context": context,
                        },
                    )
                )

        return findings

    def _scan_python_ast(self, file_path: Path, content: str) -> list:
        """Scan a Python file using AST parser to prevent false positives in comments/logs."""
        from sovascan.core.cve_scanner import Finding
        findings: list[Finding] = []

        try:
            tree = ast.parse(content, filename=str(file_path))
            visitor = PythonASTVisitor(str(file_path))
            visitor.visit(tree)

            for f_data in visitor.findings_data:
                findings.append(
                    Finding(
                        id=f_data["rule_id"],
                        title=f_data["title"],
                        description=f_data["description"],
                        severity=f_data["severity"],
                        category="misconfig",
                        file_path=str(file_path),
                        line_number=f_data["line_number"],
                        evidence=f_data["evidence"],
                        remediation=f_data["remediation"],
                        references=f_data["references"],
                        tags=f_data["tags"],
                        metadata={
                            "rule_category": f_data["category"],
                            "context": f_data["evidence"],
                        },
                    )
                )
        except SyntaxError as exc:
            logger.warning("AST parsing failed due to SyntaxError in %s: %s", file_path, exc)
        except Exception as exc:
            logger.error("AST scanning encountered an unexpected error in %s: %s", file_path, exc)

        return findings

    @staticmethod
    def _file_matches_rule(file_path: Path, rule: MisconfigRule) -> bool:
        """Check if a file matches the rule's file_type globs."""
        if not rule.file_types or rule.file_types == ["*"]:
            return True

        filename = file_path.name
        for pattern in rule.file_types:
            if fnmatch.fnmatch(filename, pattern):
                return True
            # Also match on full path for patterns like "**/config/*.yml"
            if fnmatch.fnmatch(str(file_path), pattern):
                return True

        return False

    @staticmethod
    def _match_pattern(
        content: str, pattern: re.Pattern
    ) -> list[tuple[int, str, str]]:
        """Match a compiled regex pattern against file content.

        Args:
            content: File content string.
            pattern: Compiled regex pattern.

        Returns:
            List of (line_number, matched_text, context) tuples.
        """
        results: list[tuple[int, str, str]] = []
        lines = content.split("\n")

        for match in pattern.finditer(content):
            # Calculate line number from match position
            line_num = content[:match.start()].count("\n") + 1
            matched_text = match.group(0)

            # Build context: 2 lines before and after
            start_ctx = max(0, line_num - 3)
            end_ctx = min(len(lines), line_num + 2)
            context_lines = lines[start_ctx:end_ctx]
            context = "\n".join(context_lines)

            results.append((line_num, matched_text, context))

        return results
