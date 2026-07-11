"""Git History Scanner — detects secrets leaked in past git commits.

Traverses the git log diff output to find credentials that were committed
at any point in the repository history, even if they have been deleted
from the current HEAD.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sovascan.core.cve_scanner import Finding
from sovascan.core.secret_scanner import COMPILED_PATTERNS, SecretPattern

logger = logging.getLogger(__name__)


@dataclass
class FileDiff:
    """Represents a single file's changes within a commit."""

    path: str
    added_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class CommitDiff:
    """Represents a parsed git commit with its file diffs."""

    hash: str
    short_hash: str
    author: str
    date: str
    message: str
    files: list[FileDiff] = field(default_factory=list)


class GitHistoryScanner:
    """Scans git commit history for leaked secrets and credentials.

    Uses ``git log --all -p`` to extract diffs from all branches, then
    applies the same secret detection patterns used by
    :class:`~sovascan.core.secret_scanner.SecretScanner` against the
    added lines in each commit.

    Findings are deduplicated by (pattern_name, file_path, masked_value)
    so that a secret committed in multiple commits is only reported once.
    """

    def __init__(
        self,
        max_commits: int = 500,
        extra_patterns: list[SecretPattern] | None = None,
    ) -> None:
        """Initialize the git history scanner.

        Args:
            max_commits: Maximum number of commits to traverse.
            extra_patterns: Additional secret patterns beyond the built-in set.
        """
        self.max_commits = max_commits
        self.patterns: list[SecretPattern] = list(COMPILED_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target_path: str | Path) -> list[Finding]:
        """Scan git history of the repository containing *target_path*.

        Args:
            target_path: Any path inside a git repository.

        Returns:
            List of Finding objects for secrets found in commit history.
        """
        target = Path(target_path).resolve()

        if not self._is_git_repo(target):
            logger.info("Not a git repository: %s — skipping git history scan", target)
            return []

        raw_log = self._get_git_log(target)
        if not raw_log:
            logger.info("Empty git log for %s", target)
            return []

        commits = self._parse_git_log(raw_log)
        logger.info("Parsed %d commits from git history", len(commits))

        all_findings: list[Finding] = []
        seen: set[str] = set()  # dedup key: (pattern_name, file_path, masked_value)

        for commit in commits:
            for finding in self._scan_commit(commit):
                dedup_key = f"{finding.metadata.get('pattern_name', '')}:{finding.file_path}:{finding.metadata.get('masked_value', '')}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    all_findings.append(finding)

        logger.info(
            "Git history scan complete — %d unique secrets found across %d commits",
            len(all_findings),
            len(commits),
        )
        return all_findings

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

    @staticmethod
    def _is_git_repo(path: Path) -> bool:
        """Check whether *path* is inside a git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=str(path if path.is_dir() else path.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _get_git_log(self, target: Path) -> str:
        """Run ``git log`` and return the raw diff output."""
        cwd = str(target if target.is_dir() else target.parent)
        try:
            result = subprocess.run(
                [
                    "git", "log",
                    "--all",
                    "--diff-filter=A",     # only commits that Added files
                    "-p",                  # include patch / diff
                    f"--max-count={self.max_commits}",
                    "--no-merges",
                    "--format=COMMIT:%H|%h|%an|%ai|%s",
                ],
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
            )
        except FileNotFoundError:
            logger.warning("git binary not found on PATH")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning("git log timed out for %s", target)
            return ""
        except OSError as exc:
            logger.warning("Failed to run git log: %s", exc)
            return ""

        return result.stdout

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_git_log(self, raw: str) -> list[CommitDiff]:
        """Parse raw ``git log -p`` output into structured CommitDiff objects."""
        commits: list[CommitDiff] = []
        current_commit: CommitDiff | None = None
        current_file: FileDiff | None = None
        line_counter = 0

        for line in raw.split("\n"):
            # New commit header
            if line.startswith("COMMIT:"):
                parts = line[7:].split("|", maxsplit=4)
                if len(parts) >= 5:
                    current_commit = CommitDiff(
                        hash=parts[0],
                        short_hash=parts[1],
                        author=parts[2],
                        date=parts[3],
                        message=parts[4],
                    )
                    commits.append(current_commit)
                    current_file = None
                    line_counter = 0
                continue

            if current_commit is None:
                continue

            # New file in diff
            if line.startswith("diff --git"):
                # Extract b/ path
                match = re.search(r" b/(.+)$", line)
                if match:
                    current_file = FileDiff(path=match.group(1))
                    current_commit.files.append(current_file)
                    line_counter = 0
                continue

            # Hunk header — extract starting line number
            if line.startswith("@@"):
                hunk_match = re.search(r"\+(\d+)", line)
                if hunk_match:
                    line_counter = int(hunk_match.group(1)) - 1
                continue

            # Added line in diff
            if line.startswith("+") and not line.startswith("+++"):
                line_counter += 1
                if current_file is not None:
                    current_file.added_lines.append((line_counter, line[1:]))  # strip leading +
            elif not line.startswith("-"):
                line_counter += 1

        return commits

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def _scan_commit(self, commit: CommitDiff) -> list[Finding]:
        """Apply secret patterns to added lines in a single commit."""
        findings: list[Finding] = []

        for file_diff in commit.files:
            # Skip binary-looking paths
            if any(file_diff.path.endswith(ext) for ext in (".png", ".jpg", ".gif", ".zip", ".exe", ".bin", ".lock", ".db")):
                continue

            for line_num, line_content in file_diff.added_lines:
                for pattern in self.patterns:
                    match = pattern.pattern.search(line_content)
                    if match:
                        matched_text = match.group(0)
                        masked = self._mask_secret(matched_text)
                        finding_id = self._make_finding_id(pattern.name, commit.short_hash, file_diff.path)

                        findings.append(
                            Finding(
                                id=finding_id,
                                title=f"Git History: {pattern.name}",
                                description=(
                                    f"{pattern.description} "
                                    f"This secret was found in commit {commit.short_hash} "
                                    f"by {commit.author} on {commit.date}."
                                ),
                                severity=pattern.severity,
                                category="secret",
                                file_path=file_diff.path,
                                line_number=line_num,
                                evidence=(
                                    f"Commit: {commit.short_hash} | "
                                    f"Author: {commit.author} | "
                                    f"Date: {commit.date} | "
                                    f"Secret: {masked}"
                                ),
                                remediation=(
                                    f"This secret was exposed in commit {commit.hash}. "
                                    f"1) Rotate the credential immediately. "
                                    f"2) Use git filter-branch or BFG Repo Cleaner to purge it from history. "
                                    f"3) Force-push the cleaned history."
                                ),
                                references=[
                                    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                                ],
                                tags=["git-history", "leaked-credential", *pattern.tags],
                                cvss_score=None,
                                metadata={
                                    "commit_hash": commit.hash,
                                    "commit_short": commit.short_hash,
                                    "commit_author": commit.author,
                                    "commit_date": commit.date,
                                    "commit_message": commit.message,
                                    "pattern_name": pattern.name,
                                    "masked_value": masked,
                                },
                            )
                        )

        return findings

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_secret(value: str) -> str:
        """Mask a secret value, showing only first and last 4 characters."""
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"

    @staticmethod
    def _make_finding_id(pattern_name: str, short_hash: str, file_path: str) -> str:
        """Generate a deterministic finding ID."""
        slug = re.sub(r"[^a-zA-Z0-9]", "-", pattern_name).upper().strip("-")
        path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:6]
        return f"GIT-SECRET-{slug}-{short_hash}-{path_hash}"
