"""Financial Integrity Scanner — detects salami-slicing style fraud patterns in monetary arithmetic.

Unlike SAST (Bandit/Semgrep) or dependency/secret scanning, this module does
not look for CWE-style vulnerabilities. It looks for a category of banking
fraud that has no CVE and produces no crash: code that is syntactically and
functionally correct, but whose rounding/truncation behavior systematically
diverts fractional currency amounts (the classic "salami slicing" / "penny
shaving" attack).

Three heuristics:
1. FIN-001: Currency-as-float: monetary values stored/parameterized as `float` instead of `Decimal`.
2. FIN-002: Directional truncation bias: monetary expressions truncated with `int(...)` or `math.floor(...)`.
3. FIN-003: Orphaned remainder: discarded fraction/remainder captured into a variable that is never read again.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sovascan.core.cve_scanner import Finding

logger = logging.getLogger(__name__)

CURRENCY_KEYWORDS = {
    "amount", "balance", "price", "fee", "interest", "total", "payment",
    "principal", "rate", "charge", "salary", "wage", "tax", "refund",
    "credit", "debit", "transaction", "txn", "cents", "penny", "pennies",
    "rupee", "rupees", "inr", "usd", "cost", "premium", "payout", "ledger",
    "invoice", "billing", "commission",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def _is_currency_name(name: str) -> bool:
    lowered = name.lower()
    return any(kw in lowered for kw in CURRENCY_KEYWORDS)


def _annotation_is_float(annotation: ast.expr | None) -> bool:
    return isinstance(annotation, ast.Name) and annotation.id == "float"


@dataclass
class _FunctionScan:
    """Accumulates evidence within a single function body."""

    file_path: str
    func_name: str
    findings: list[Finding] = field(default_factory=list)


class FinancialIntegrityScanner:
    """Scans Python source for salami-slicing style financial-logic fraud patterns."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target_path: str | Path) -> list[Finding]:
        """Scan all Python files under *target_path* for financial-integrity issues.

        Args:
            target_path: Root directory or single .py file to scan.

        Returns:
            List of Finding objects (category="financial-integrity").
        """
        target = Path(target_path).resolve()
        if not target.exists():
            logger.warning("Financial integrity scan target does not exist: %s", target)
            return []

        py_files: list[Path]
        if target.is_file():
            py_files = [target] if target.suffix == ".py" else []
        else:
            py_files = [
                p for p in target.rglob("*.py")
                if not any(part in SKIP_DIRS for part in p.parts)
            ]

        findings: list[Finding] = []
        for py_file in py_files:
            try:
                findings.extend(self._scan_file(py_file, target))
            except Exception as exc:
                logger.error("Financial integrity scan failed for %s: %s", py_file, exc)

        logger.info("Financial integrity scan complete — %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Per-file / per-function analysis
    # ------------------------------------------------------------------

    def _scan_file(self, py_file: Path, root: Path) -> list[Finding]:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError) as exc:
            logger.debug("Skipping unparsable file %s: %s", py_file, exc)
            return []

        try:
            rel_path = str(py_file.relative_to(root))
        except ValueError:
            rel_path = str(py_file)

        lines = source.splitlines()
        findings: list[Finding] = []

        # Module-level float-currency assignments
        findings.extend(self._check_module_level_float_currency(tree, rel_path, lines))

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_float_currency_params(node, rel_path))
                findings.extend(self._check_truncation_bias(node, rel_path, lines))
                findings.extend(self._check_orphaned_remainder(node, rel_path, lines))

        return findings

    # ------------------------------------------------------------------
    # Heuristic 1: currency stored as float
    # ------------------------------------------------------------------

    def _check_module_level_float_currency(
        self, tree: ast.Module, rel_path: str, lines: list[str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and _annotation_is_float(node.annotation):
                target = node.target
                if isinstance(target, ast.Name) and _is_currency_name(target.id):
                    out.append(self._make_finding(
                        rule_id="FIN-001",
                        title="Currency value typed as float",
                        rel_path=rel_path,
                        line_number=node.lineno,
                        evidence=self._snippet(lines, node.lineno),
                        description=(
                            f"'{target.id}' is annotated as float but its name suggests a "
                            "monetary value. Binary floats cannot represent most decimal "
                            "fractions exactly, which is the enabling condition for silent "
                            "sub-cent drift (salami slicing) across many transactions."
                        ),
                        remediation="Use `decimal.Decimal` (or integer minor-units, e.g. cents) for monetary fields.",
                    ))
        return out

    def _check_float_currency_params(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str
    ) -> list[Finding]:
        out: list[Finding] = []
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if _annotation_is_float(arg.annotation) and _is_currency_name(arg.arg):
                out.append(self._make_finding(
                    rule_id="FIN-001",
                    title="Currency parameter typed as float",
                    rel_path=rel_path,
                    line_number=func.lineno,
                    evidence=f"def {func.name}(..., {arg.arg}: float, ...)",
                    description=(
                        f"Parameter '{arg.arg}' in `{func.name}` is typed float but its name "
                        "suggests a monetary amount. Float arithmetic on money is the enabling "
                        "condition for undetected rounding-based fraud."
                    ),
                    remediation="Use `decimal.Decimal` or an integer minor-units type for monetary parameters.",
                ))
        return out

    # ------------------------------------------------------------------
    # Heuristic 2: directional truncation bias
    # ------------------------------------------------------------------

    def _check_truncation_bias(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str, lines: list[str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._call_name(node)
            if func_name not in ("int", "math.floor", "floor"):
                continue

            if not node.args:
                continue

            arg_expr = node.args[0]
            if self._expr_touches_currency(arg_expr):
                out.append(self._make_finding(
                    rule_id="FIN-002",
                    title="One-directional truncation on monetary value",
                    rel_path=rel_path,
                    line_number=node.lineno,
                    evidence=self._snippet(lines, node.lineno),
                    description=(
                        f"`{func_name}(...)` truncates a monetary expression in `{func.name}` "
                        "toward a single direction on every call. Applied consistently across "
                        "many transactions, this generates a predictable fractional remainder "
                        "on every single one — the arithmetic signature of penny-shaving."
                    ),
                    remediation=(
                        "Use symmetric rounding (Decimal with ROUND_HALF_EVEN) unless one-directional "
                        "truncation is a deliberate, documented business rule — and if it is, reconcile "
                        "the discarded fraction against a visible ledger entry."
                    ),
                ))
        return out

    # ------------------------------------------------------------------
    # Heuristic 3: orphaned remainder
    # ------------------------------------------------------------------

    def _check_orphaned_remainder(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str, lines: list[str]
    ) -> list[Finding]:
        out: list[Finding] = []

        loaded_names: set[str] = set()
        remainder_assigns: list[tuple[str, ast.Assign]] = []

        for node in ast.walk(func):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                loaded_names.add(node.id)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp):
                if isinstance(node.value.op, (ast.Mod, ast.Sub)) and self._expr_touches_currency(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            remainder_assigns.append((target.id, node))

        for var_name, assign_node in remainder_assigns:
            if var_name not in loaded_names:
                out.append(self._make_finding(
                    rule_id="FIN-003",
                    title="Orphaned remainder from monetary calculation",
                    rel_path=rel_path,
                    line_number=assign_node.lineno,
                    evidence=self._snippet(lines, assign_node.lineno),
                    description=(
                        f"'{var_name}' captures a remainder/modulo from a monetary expression in "
                        f"`{func.name}` but is never read again anywhere in the function — it's "
                        "computed and then goes nowhere. A discarded fraction that isn't reconciled "
                        "against a ledger, log, or return value is the actual fingerprint of "
                        "salami slicing."
                    ),
                    remediation=(
                        "Either remove the unused remainder capture, or explicitly reconcile it — "
                        "add it back to the ledger, log it, or return it to the caller so its "
                        "disposition is auditable."
                    ),
                ))
        return out

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Name):
            return f.id
        if isinstance(f, ast.Attribute):
            if isinstance(f.value, ast.Name):
                return f"{f.value.id}.{f.attr}"
            return f.attr
        return ""

    def _expr_touches_currency(self, expr: ast.expr) -> bool:
        """True if any Name leaf in *expr* matches a currency keyword."""
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and _is_currency_name(node.id):
                return True
        return False

    @staticmethod
    def _snippet(lines: list[str], lineno: int) -> str:
        idx = lineno - 1
        if 0 <= idx < len(lines):
            return lines[idx].strip()
        return ""

    def _make_finding(
        self,
        rule_id: str,
        title: str,
        rel_path: str,
        line_number: int,
        evidence: str,
        description: str,
        remediation: str,
    ) -> Finding:
        severity = "medium" if rule_id == "FIN-001" else "high"
        return Finding(
            id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category="financial-integrity",
            file_path=rel_path,
            line_number=line_number,
            evidence=evidence,
            remediation=remediation,
            references=[],
            tags=["financial-integrity", "salami-slicing", rule_id.lower()],
            cvss_score=None,
            metadata={"tool": "financial_integrity_scanner", "rule_id": rule_id},
        )
