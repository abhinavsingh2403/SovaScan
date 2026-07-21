"""Tests for FinancialIntegrityScanner (FIN-001, FIN-002, FIN-003)."""

from pathlib import Path

from sovascan.core.financial_integrity_scanner import FinancialIntegrityScanner
from sovascan.core.orchestrator import ScanOrchestrator

VULNERABLE_CODE = """
def apply_monthly_interest(balance: float, rate: float) -> float:
    interest = balance * rate / 12
    whole_interest = int(interest)
    remainder = interest % 1
    new_balance = balance + whole_interest
    return new_balance

def process_batch(accounts: list) -> None:
    for account in accounts:
        fee: float = account["fee"]
        skimmed = fee - int(fee)
        account["fee"] = int(fee)
"""

RECONCILED_CODE = """
from decimal import Decimal, ROUND_HALF_EVEN

def apply_monthly_interest(balance: Decimal, rate: Decimal) -> Decimal:
    interest = (balance * rate / 12).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    return balance + interest

def process_batch(accounts: list, rounding_ledger: dict) -> None:
    for account in accounts:
        fee: Decimal = account["fee"]
        rounded = fee.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        remainder = fee - rounded
        rounding_ledger["total_adjustments"] = rounding_ledger.get("total_adjustments", Decimal("0")) + remainder
        account["fee"] = rounded
"""


def test_financial_integrity_vulnerable(tmp_path: Path):
    vuln_file = tmp_path / "vulnerable_interest.py"
    vuln_file.write_text(VULNERABLE_CODE, encoding="utf-8")

    scanner = FinancialIntegrityScanner()
    findings = scanner.scan(vuln_file)

    rule_ids = {f.id for f in findings}
    assert "FIN-001" in rule_ids  # float monetary parameter/variable
    assert "FIN-002" in rule_ids  # int() truncation on monetary calculation
    assert "FIN-003" in rule_ids  # orphaned remainder variable (remainder, skimmed)
    assert len(findings) >= 5


def test_financial_integrity_reconciled(tmp_path: Path):
    clean_file = tmp_path / "clean_interest.py"
    clean_file.write_text(RECONCILED_CODE, encoding="utf-8")

    scanner = FinancialIntegrityScanner()
    findings = scanner.scan(clean_file)

    assert len(findings) == 0


def test_orchestrator_integration_financial_integrity(tmp_path: Path):
    vuln_file = tmp_path / "banking_code.py"
    vuln_file.write_text(VULNERABLE_CODE, encoding="utf-8")

    orchestrator = ScanOrchestrator(target_path=tmp_path, scan_type="financial-integrity")
    result = orchestrator.run_scan()

    assert result.total_findings >= 5
    categories = {f.category for f in result.findings}
    assert "financial-integrity" in categories
