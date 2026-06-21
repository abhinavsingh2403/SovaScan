"""Dependency Resolver - parses manifests and resolves dependency trees.

Supports package.json, package-lock.json, requirements.txt, Pipfile.lock,
and pom.xml manifest formats.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a resolved software dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, maven
    is_dev: bool = False
    is_transitive: bool = False
    source_file: str = ""
    parent: Optional[str] = None
    extras: dict = field(default_factory=dict)

    @property
    def coordinate(self) -> str:
        """Return ecosystem-specific coordinate string."""
        if self.ecosystem == "maven":
            group = self.extras.get("group_id", "unknown")
            return f"{group}:{self.name}:{self.version}"
        return f"{self.name}@{self.version}"


class DependencyResolver:
    """Resolves dependencies from various package manifest formats."""

    MANIFEST_PARSERS = {
        "package.json": "_parse_package_json",
        "package-lock.json": "_parse_package_lock",
        "requirements.txt": "_parse_requirements_txt",
        "Pipfile.lock": "_parse_pipfile_lock",
        "pom.xml": "_parse_pom_xml",
    }

    def resolve(self, manifest_path: str | Path) -> list[Dependency]:
        """Resolve dependencies from a manifest file.

        Args:
            manifest_path: Path to the manifest file.

        Returns:
            List of resolved Dependency objects.

        Raises:
            FileNotFoundError: If manifest file does not exist.
            ValueError: If manifest type is not supported.
        """
        manifest_path = Path(manifest_path)
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")

        filename = manifest_path.name
        parser_method = self.MANIFEST_PARSERS.get(filename)
        if parser_method is None:
            # Try partial matches for requirements files (e.g., requirements-dev.txt)
            if filename.startswith("requirements") and filename.endswith(".txt"):
                parser_method = "_parse_requirements_txt"
            else:
                raise ValueError(
                    f"Unsupported manifest type: {filename}. "
                    f"Supported: {', '.join(self.MANIFEST_PARSERS.keys())}"
                )

        parser = getattr(self, parser_method)
        logger.info("Parsing %s with %s", manifest_path, parser_method)

        try:
            dependencies = parser(manifest_path)
        except Exception as exc:
            logger.error("Failed to parse %s: %s", manifest_path, exc)
            raise

        logger.info("Resolved %d dependencies from %s", len(dependencies), manifest_path)
        return dependencies

    # ── npm parsers ──────────────────────────────────────────────────

    def _parse_package_json(self, path: Path) -> list[Dependency]:
        """Parse package.json for dependencies and devDependencies."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        deps: list[Dependency] = []

        for dep_name, version_spec in data.get("dependencies", {}).items():
            version = self._clean_npm_version(version_spec)
            deps.append(
                Dependency(
                    name=dep_name,
                    version=version,
                    ecosystem="npm",
                    is_dev=False,
                    is_transitive=False,
                    source_file=str(path),
                )
            )

        for dep_name, version_spec in data.get("devDependencies", {}).items():
            version = self._clean_npm_version(version_spec)
            deps.append(
                Dependency(
                    name=dep_name,
                    version=version,
                    ecosystem="npm",
                    is_dev=True,
                    is_transitive=False,
                    source_file=str(path),
                )
            )

        return deps

    def _parse_package_lock(self, path: Path) -> list[Dependency]:
        """Parse package-lock.json for locked dependency versions."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        deps: list[Dependency] = []
        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2 and "packages" in data:
            # lockfileVersion 2/3: packages dict
            for pkg_path, pkg_info in data.get("packages", {}).items():
                if pkg_path == "":
                    continue  # skip root
                name = pkg_path.split("node_modules/")[-1]
                version = pkg_info.get("version", "0.0.0")
                is_dev = pkg_info.get("dev", False)
                is_transitive = pkg_path.count("node_modules/") > 1
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        is_dev=is_dev,
                        is_transitive=is_transitive,
                        source_file=str(path),
                    )
                )
        elif "dependencies" in data:
            # lockfileVersion 1: nested dependencies dict
            self._walk_lock_deps(data["dependencies"], deps, str(path), is_transitive=False)

        return deps

    def _walk_lock_deps(
        self,
        deps_dict: dict,
        result: list[Dependency],
        source: str,
        is_transitive: bool,
    ) -> None:
        """Recursively walk lockfileVersion-1 nested dependencies."""
        for name, info in deps_dict.items():
            version = info.get("version", "0.0.0")
            is_dev = info.get("dev", False)
            result.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_dev=is_dev,
                    is_transitive=is_transitive,
                    source_file=source,
                )
            )
            # recurse into nested dependencies
            if "dependencies" in info:
                self._walk_lock_deps(info["dependencies"], result, source, is_transitive=True)

    @staticmethod
    def _clean_npm_version(spec: str) -> str:
        """Strip npm version prefixes (^, ~, >=, etc.) to get base version."""
        return re.sub(r"^[~^>=<|!\s]+", "", spec).strip()

    # ── Python parsers ───────────────────────────────────────────────

    def _parse_requirements_txt(self, path: Path) -> list[Dependency]:
        """Parse requirements.txt handling ==, >=, ~=, comments, -r includes."""
        deps: list[Dependency] = []
        seen: set[str] = set()
        self._parse_requirements_file(path, deps, seen)
        return deps

    def _parse_requirements_file(
        self, path: Path, deps: list[Dependency], seen: set[str]
    ) -> None:
        """Recursively parse a requirements file, following -r includes."""
        canonical = str(path.resolve())
        if canonical in seen:
            return
        seen.add(canonical)

        if not path.exists():
            logger.warning("Requirements file not found: %s", path)
            return

        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()

                # skip blanks and comments
                if not line or line.startswith("#"):
                    continue

                # handle inline comments
                if " #" in line:
                    line = line[: line.index(" #")].strip()

                # handle -r / --requirement includes
                if line.startswith(("-r ", "--requirement ")):
                    include_path = line.split(None, 1)[1].strip()
                    resolved = (path.parent / include_path).resolve()
                    self._parse_requirements_file(resolved, deps, seen)
                    continue

                # handle -e (editable), -i, --index-url, --extra-index-url, -f, etc.
                if line.startswith(("-e ", "-i ", "--index-url", "--extra-index-url", "-f ", "--find-links")):
                    continue

                # handle environment markers
                if ";" in line:
                    line = line[: line.index(";")].strip()

                # handle extras like package[extra1,extra2]
                extras_match = re.match(r"^([a-zA-Z0-9_.-]+)\[.*?\](.*)", line)
                if extras_match:
                    line = extras_match.group(1) + extras_match.group(2)

                # parse version specifiers
                version = "0.0.0"
                name = line

                version_operators = ["~=", "==", "!=", "<=", ">=", "<", ">"]
                for op in version_operators:
                    if op in line:
                        parts = line.split(op, 1)
                        name = parts[0].strip()
                        # Take first version if multiple specifiers via comma
                        ver_part = parts[1].strip()
                        if "," in ver_part:
                            ver_part = ver_part.split(",")[0].strip()
                        version = ver_part
                        break

                name = name.strip().lower()
                if name:
                    is_dev = "dev" in str(path.name).lower() or "test" in str(path.name).lower()
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            is_dev=is_dev,
                            is_transitive=False,
                            source_file=str(path),
                        )
                    )

    def _parse_pipfile_lock(self, path: Path) -> list[Dependency]:
        """Parse Pipfile.lock JSON for locked dependency versions."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        deps: list[Dependency] = []

        for section, is_dev in [("default", False), ("develop", True)]:
            for name, info in data.get(section, {}).items():
                version = info.get("version", "0.0.0")
                # Pipfile.lock versions start with ==
                version = version.lstrip("=")
                deps.append(
                    Dependency(
                        name=name.lower(),
                        version=version,
                        ecosystem="pypi",
                        is_dev=is_dev,
                        is_transitive=False,
                        source_file=str(path),
                    )
                )

        return deps

    # ── Maven parser ─────────────────────────────────────────────────

    def _parse_pom_xml(self, path: Path) -> list[Dependency]:
        """Parse Maven pom.xml for dependency declarations."""
        tree = ET.parse(path)
        root = tree.getroot()

        # Handle Maven namespace
        ns = ""
        ns_match = re.match(r"\{(.+)\}", root.tag)
        if ns_match:
            ns = ns_match.group(1)

        def tag(name: str) -> str:
            return f"{{{ns}}}{name}" if ns else name

        # Collect properties for variable substitution
        properties: dict[str, str] = {}
        props_elem = root.find(tag("properties"))
        if props_elem is not None:
            for prop in props_elem:
                prop_name = prop.tag
                if ns:
                    prop_name = prop_name.replace(f"{{{ns}}}", "")
                properties[prop_name] = prop.text or ""

        deps: list[Dependency] = []

        # Parse <dependencies> section
        deps_section = root.find(tag("dependencies"))
        if deps_section is not None:
            for dep_elem in deps_section.findall(tag("dependency")):
                dep = self._parse_maven_dep(dep_elem, tag, properties, str(path))
                if dep:
                    deps.append(dep)

        # Parse <dependencyManagement><dependencies> section
        dep_mgmt = root.find(tag("dependencyManagement"))
        if dep_mgmt is not None:
            mgmt_deps = dep_mgmt.find(tag("dependencies"))
            if mgmt_deps is not None:
                for dep_elem in mgmt_deps.findall(tag("dependency")):
                    dep = self._parse_maven_dep(dep_elem, tag, properties, str(path))
                    if dep:
                        dep.extras["managed"] = True
                        deps.append(dep)

        return deps

    @staticmethod
    def _parse_maven_dep(dep_elem, tag, properties: dict, source: str) -> Optional[Dependency]:
        """Parse a single Maven <dependency> element."""
        group_elem = dep_elem.find(tag("groupId"))
        artifact_elem = dep_elem.find(tag("artifactId"))
        version_elem = dep_elem.find(tag("version"))
        scope_elem = dep_elem.find(tag("scope"))

        if artifact_elem is None or artifact_elem.text is None:
            return None

        group_id = group_elem.text if group_elem is not None and group_elem.text else "unknown"
        artifact_id = artifact_elem.text
        version = "0.0.0"

        if version_elem is not None and version_elem.text:
            version = version_elem.text
            # Resolve ${property} references
            prop_match = re.match(r"\$\{(.+)\}", version)
            if prop_match:
                prop_name = prop_match.group(1)
                # Handle project.version specially
                if prop_name == "project.version":
                    version = properties.get("version", "0.0.0")
                else:
                    version = properties.get(prop_name, version)

        scope = scope_elem.text if scope_elem is not None and scope_elem.text else "compile"
        is_dev = scope in ("test", "provided")

        return Dependency(
            name=artifact_id,
            version=version,
            ecosystem="maven",
            is_dev=is_dev,
            is_transitive=False,
            source_file=source,
            extras={"group_id": group_id, "scope": scope},
        )
