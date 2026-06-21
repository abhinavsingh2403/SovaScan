"""Configuration Drift Analyzer - detects deviations from secure baselines.

Compares live configuration files against known-good security baselines
for Docker, Nginx, Spring Boot, and other infrastructure configurations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BaselineCheck:
    """A single baseline check definition."""

    id: str
    name: str
    description: str
    severity: str
    check_type: str  # "must_exist", "must_not_exist", "must_match", "must_not_match"
    pattern: str
    remediation: str
    tags: list[str] = field(default_factory=list)


# ── Built-in baselines ─────────────────────────────────────────────────

DOCKERFILE_BASELINE: list[BaselineCheck] = [
    BaselineCheck(
        id="DRIFT-DOCKER-001",
        name="Container Running as Root",
        description="Dockerfile does not contain a USER directive, so the container will run as root.",
        severity="high",
        check_type="must_exist",
        pattern=r"^\s*USER\s+(?!root)\S+",
        remediation="Add a USER directive with a non-root user: USER appuser",
        tags=["docker", "privilege", "container"],
    ),
    BaselineCheck(
        id="DRIFT-DOCKER-002",
        name="Using 'latest' Tag in FROM",
        description="Using 'latest' tag leads to unpredictable builds and potential security regressions.",
        severity="medium",
        check_type="must_not_match",
        pattern=r"^\s*FROM\s+\S+:latest",
        remediation="Pin the base image to a specific version: FROM image:1.2.3",
        tags=["docker", "supply-chain", "versioning"],
    ),
    BaselineCheck(
        id="DRIFT-DOCKER-003",
        name="Missing HEALTHCHECK",
        description="No HEALTHCHECK instruction found. Health checks enable orchestrators to detect unhealthy containers.",
        severity="low",
        check_type="must_exist",
        pattern=r"^\s*HEALTHCHECK\s+",
        remediation="Add a HEALTHCHECK instruction: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
        tags=["docker", "availability", "monitoring"],
    ),
    BaselineCheck(
        id="DRIFT-DOCKER-004",
        name="Using ADD Instead of COPY",
        description="ADD can fetch remote URLs and auto-extract archives, creating unexpected attack surface. Use COPY for simple file copies.",
        severity="low",
        check_type="must_not_match",
        pattern=r"^\s*ADD\s+(?!--chown)",
        remediation="Replace ADD with COPY unless you specifically need remote URL fetch or archive extraction.",
        tags=["docker", "best-practice"],
    ),
    BaselineCheck(
        id="DRIFT-DOCKER-005",
        name="Running apt-get Without --no-install-recommends",
        description="Installing recommended packages increases attack surface unnecessarily.",
        severity="low",
        check_type="must_not_match",
        pattern=r"apt-get\s+install\s+(?!.*--no-install-recommends)",
        remediation="Use apt-get install --no-install-recommends to minimize installed packages.",
        tags=["docker", "minimization"],
    ),
]

DOCKER_COMPOSE_BASELINE: list[BaselineCheck] = [
    BaselineCheck(
        id="DRIFT-COMPOSE-001",
        name="Privileged Container",
        description="Container is running in privileged mode, granting access to all host devices.",
        severity="critical",
        check_type="must_not_match",
        pattern=r"(?i)privileged\s*:\s*true",
        remediation="Remove 'privileged: true' and use specific capabilities instead.",
        tags=["docker-compose", "privilege"],
    ),
    BaselineCheck(
        id="DRIFT-COMPOSE-002",
        name="No Resource Limits Set",
        description="Container has no memory or CPU limits, risking resource exhaustion on the host.",
        severity="medium",
        check_type="must_exist",
        pattern=r"(?i)(mem_limit|memory|cpus|cpu_quota|deploy:\s*\n\s*resources:)",
        remediation="Set resource limits using deploy.resources or mem_limit/cpus directives.",
        tags=["docker-compose", "resources"],
    ),
    BaselineCheck(
        id="DRIFT-COMPOSE-003",
        name="Host Network Mode",
        description="Container uses host network mode, bypassing network isolation.",
        severity="high",
        check_type="must_not_match",
        pattern=r"(?i)network_mode\s*:\s*['\"]?host['\"]?",
        remediation="Use bridge networking or custom networks instead of host mode.",
        tags=["docker-compose", "network"],
    ),
    BaselineCheck(
        id="DRIFT-COMPOSE-004",
        name="Host PID Namespace",
        description="Container shares the host PID namespace, allowing process visibility.",
        severity="high",
        check_type="must_not_match",
        pattern=r"(?i)pid\s*:\s*['\"]?host['\"]?",
        remediation="Remove 'pid: host' to maintain PID namespace isolation.",
        tags=["docker-compose", "isolation"],
    ),
]

NGINX_BASELINE: list[BaselineCheck] = [
    BaselineCheck(
        id="DRIFT-NGINX-001",
        name="Insecure TLS Protocol Versions",
        description="TLS 1.0 or 1.1 is enabled. These protocols have known vulnerabilities.",
        severity="high",
        check_type="must_not_match",
        pattern=r"(?i)ssl_protocols\s+.*(?:TLSv1(?:\.0)?(?:\s|;)|TLSv1\.1)",
        remediation="Configure ssl_protocols to TLSv1.2 and TLSv1.3 only.",
        tags=["nginx", "tls", "crypto"],
    ),
    BaselineCheck(
        id="DRIFT-NGINX-002",
        name="Server Tokens Enabled",
        description="Nginx version is exposed in responses, aiding attackers in version-specific exploits.",
        severity="medium",
        check_type="must_exist",
        pattern=r"(?i)server_tokens\s+off\s*;",
        remediation="Add 'server_tokens off;' to the http or server block.",
        tags=["nginx", "information-disclosure"],
    ),
    BaselineCheck(
        id="DRIFT-NGINX-003",
        name="Missing X-Frame-Options Header",
        description="X-Frame-Options header not set, making the site vulnerable to clickjacking.",
        severity="medium",
        check_type="must_exist",
        pattern=r"(?i)add_header\s+X-Frame-Options",
        remediation="Add 'add_header X-Frame-Options \"SAMEORIGIN\";' to the server block.",
        tags=["nginx", "headers", "clickjacking"],
    ),
    BaselineCheck(
        id="DRIFT-NGINX-004",
        name="Missing X-Content-Type-Options Header",
        description="X-Content-Type-Options header not set, allowing MIME-type sniffing attacks.",
        severity="medium",
        check_type="must_exist",
        pattern=r"(?i)add_header\s+X-Content-Type-Options",
        remediation="Add 'add_header X-Content-Type-Options \"nosniff\";' to the server block.",
        tags=["nginx", "headers", "mime-sniffing"],
    ),
    BaselineCheck(
        id="DRIFT-NGINX-005",
        name="Missing Content-Security-Policy Header",
        description="Content-Security-Policy header not set.",
        severity="medium",
        check_type="must_exist",
        pattern=r"(?i)add_header\s+Content-Security-Policy",
        remediation="Add a Content-Security-Policy header to restrict resource loading.",
        tags=["nginx", "headers", "csp"],
    ),
]

SPRING_BASELINE: list[BaselineCheck] = [
    BaselineCheck(
        id="DRIFT-SPRING-001",
        name="Debug Mode Enabled",
        description="Spring Boot debug mode is enabled in production configuration.",
        severity="high",
        check_type="must_not_match",
        pattern=r"(?i)(?:debug\s*[=:]\s*true|logging\.level\.root\s*[=:]\s*DEBUG)",
        remediation="Set debug=false and logging.level.root=INFO or WARN for production.",
        tags=["spring", "debug", "information-disclosure"],
    ),
    BaselineCheck(
        id="DRIFT-SPRING-002",
        name="Insecure Cookie Configuration",
        description="Secure flag or HttpOnly flag is not set on session cookies.",
        severity="high",
        check_type="must_exist",
        pattern=r"(?i)server\.servlet\.session\.cookie\.secure\s*[=:]\s*true",
        remediation="Set server.servlet.session.cookie.secure=true and server.servlet.session.cookie.http-only=true.",
        tags=["spring", "cookies", "session"],
    ),
    BaselineCheck(
        id="DRIFT-SPRING-003",
        name="CSRF Protection Disabled",
        description="CSRF protection appears to be disabled.",
        severity="high",
        check_type="must_not_match",
        pattern=r"(?i)csrf\(\)\s*\.disable\(\)|csrf\.enabled\s*[=:]\s*false",
        remediation="Enable CSRF protection unless you have a stateless API-only application with proper token auth.",
        tags=["spring", "csrf", "web-security"],
    ),
    BaselineCheck(
        id="DRIFT-SPRING-004",
        name="Actuator Endpoints Exposed",
        description="Spring Boot actuator endpoints may be publicly accessible.",
        severity="medium",
        check_type="must_not_match",
        pattern=r"(?i)management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*",
        remediation="Limit actuator exposure: management.endpoints.web.exposure.include=health,info",
        tags=["spring", "actuator", "information-disclosure"],
    ),
]


class ConfigDriftAnalyzer:
    """Analyzes configuration files for security drift from established baselines."""

    BASELINE_MAP: dict[str, list[BaselineCheck]] = {}  # populated in __init__

    def __init__(self, baselines_dir: str | Path | None = None) -> None:
        """Initialize the drift analyzer.

        Args:
            baselines_dir: Optional directory with custom JSON/YAML baseline definitions.
                          Built-in baselines are always available.
        """
        self.baselines_dir = Path(baselines_dir) if baselines_dir else None
        self._baselines: dict[str, list[BaselineCheck]] = {
            "Dockerfile": DOCKERFILE_BASELINE,
            "docker-compose": DOCKER_COMPOSE_BASELINE,
            "nginx": NGINX_BASELINE,
            "spring": SPRING_BASELINE,
        }

        if self.baselines_dir and self.baselines_dir.exists():
            self._load_custom_baselines()

    def _load_custom_baselines(self) -> None:
        """Load additional baseline checks from YAML files in baselines_dir."""
        if not self.baselines_dir:
            return

        import yaml

        for yaml_file in self.baselines_dir.glob("*.yaml"):
            try:
                with open(yaml_file, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if not data or not isinstance(data, dict):
                    continue
                config_type = data.get("config_type", yaml_file.stem)
                checks = []
                for check_data in data.get("checks", []):
                    checks.append(BaselineCheck(
                        id=check_data.get("id", f"CUSTOM-{yaml_file.stem}"),
                        name=check_data.get("name", "Custom Check"),
                        description=check_data.get("description", ""),
                        severity=check_data.get("severity", "medium"),
                        check_type=check_data.get("check_type", "must_not_match"),
                        pattern=check_data.get("pattern", ""),
                        remediation=check_data.get("remediation", ""),
                        tags=check_data.get("tags", []),
                    ))
                if config_type in self._baselines:
                    self._baselines[config_type].extend(checks)
                else:
                    self._baselines[config_type] = checks
            except Exception as exc:
                logger.warning("Failed to load custom baseline %s: %s", yaml_file, exc)

    def analyze(self, config_path: str | Path) -> list:
        """Analyze a configuration file for drift from security baselines.

        Args:
            config_path: Path to the configuration file.

        Returns:
            List of Finding objects representing detected drift.
        """
        from sovascan.core.cve_scanner import Finding

        config_path = Path(config_path)
        findings: list[Finding] = []

        if not config_path.exists():
            logger.error("Config file not found: %s", config_path)
            return findings

        try:
            content = config_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Cannot read config file %s: %s", config_path, exc)
            return findings

        config_type = self._detect_config_type(config_path)
        if config_type is None:
            logger.debug("No baseline available for %s", config_path.name)
            return findings

        baseline = self._baselines.get(config_type, [])
        logger.info("Analyzing %s against %d baseline checks (%s)", config_path, len(baseline), config_type)

        drift_results = self._compare_against_baseline(content, baseline)

        for check, details in drift_results:
            line_number = 0
            if details.get("match_position"):
                line_number = content[:details["match_position"]].count("\n") + 1

            findings.append(
                Finding(
                    id=check.id,
                    title=check.name,
                    description=check.description,
                    severity=check.severity,
                    category="drift",
                    file_path=str(config_path),
                    line_number=line_number,
                    evidence=details.get("evidence", ""),
                    remediation=check.remediation,
                    tags=check.tags,
                    metadata={
                        "config_type": config_type,
                        "check_type": check.check_type,
                        "drift_detail": details.get("detail", ""),
                    },
                )
            )

        logger.info("Found %d drift issues in %s", len(findings), config_path)
        return findings

    def _compare_against_baseline(
        self, content: str, baseline: list[BaselineCheck]
    ) -> list[tuple[BaselineCheck, dict[str, Any]]]:
        """Compare file content against a list of baseline checks.

        Args:
            content: File content string.
            baseline: List of baseline checks to apply.

        Returns:
            List of (check, details) tuples for each detected drift.
        """
        drifts: list[tuple[BaselineCheck, dict[str, Any]]] = []

        for check in baseline:
            try:
                compiled = re.compile(check.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                logger.warning("Invalid regex in check %s: %s", check.id, exc)
                continue

            match = compiled.search(content)

            if check.check_type == "must_exist":
                if match is None:
                    drifts.append((check, {
                        "detail": f"Expected pattern not found: {check.pattern}",
                        "evidence": "Pattern not present in file",
                    }))

            elif check.check_type == "must_not_exist":
                if match is not None:
                    drifts.append((check, {
                        "detail": f"Forbidden pattern found: {match.group(0)}",
                        "evidence": match.group(0)[:200],
                        "match_position": match.start(),
                    }))

            elif check.check_type == "must_match":
                if match is None:
                    drifts.append((check, {
                        "detail": f"Required pattern not matched: {check.pattern}",
                        "evidence": "Pattern not matched",
                    }))

            elif check.check_type == "must_not_match":
                if match is not None:
                    drifts.append((check, {
                        "detail": f"Insecure pattern matched: {match.group(0)}",
                        "evidence": match.group(0)[:200],
                        "match_position": match.start(),
                    }))

        return drifts

    @staticmethod
    def _detect_config_type(file_path: Path) -> str | None:
        """Detect the configuration type from the file path and name."""
        name = file_path.name.lower()

        if name == "dockerfile" or name.startswith("dockerfile."):
            return "Dockerfile"

        if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            return "docker-compose"

        if "nginx" in name and name.endswith(".conf"):
            return "nginx"

        if name in ("application.properties", "application.yml", "application.yaml"):
            return "spring"

        if "nginx" in str(file_path).lower():
            return "nginx"

        return None

    @staticmethod
    def _parse_dockerfile(content: str) -> list[dict[str, Any]]:
        """Parse a Dockerfile into a list of directive dicts.

        Args:
            content: Dockerfile content.

        Returns:
            List of dicts with 'instruction', 'arguments', 'line' keys.
        """
        directives: list[dict[str, Any]] = []
        lines = content.split("\n")
        current_line = ""

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and blank lines
            if not stripped or stripped.startswith("#"):
                continue

            # Handle line continuations
            if stripped.endswith("\\"):
                current_line += stripped[:-1].strip() + " "
                continue

            current_line += stripped
            parts = current_line.split(None, 1)
            instruction = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""

            directives.append({
                "instruction": instruction,
                "arguments": arguments,
                "line": i,
            })
            current_line = ""

        return directives

    @staticmethod
    def _parse_nginx_conf(content: str) -> list[dict[str, Any]]:
        """Basic Nginx configuration parser.

        Extracts directives and their values from nginx.conf style files.

        Args:
            content: Nginx configuration content.

        Returns:
            List of dicts with 'directive', 'value', 'line', 'block' keys.
        """
        directives: list[dict[str, Any]] = []
        lines = content.split("\n")
        block_stack: list[str] = []

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and blank lines
            if not stripped or stripped.startswith("#"):
                continue

            # Track block entry
            if "{" in stripped:
                block_name = stripped.replace("{", "").strip()
                block_stack.append(block_name)
                continue

            # Track block exit
            if "}" in stripped:
                if block_stack:
                    block_stack.pop()
                continue

            # Parse directive
            if ";" in stripped:
                directive_str = stripped.rstrip(";").strip()
                parts = directive_str.split(None, 1)
                if parts:
                    directive_name = parts[0]
                    directive_value = parts[1] if len(parts) > 1 else ""
                    directives.append({
                        "directive": directive_name,
                        "value": directive_value,
                        "line": i,
                        "block": "/".join(block_stack),
                    })

        return directives
