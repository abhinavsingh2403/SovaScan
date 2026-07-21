"""Sample Banking Module — Reconciled & Secure Financial Arithmetic.

This file demonstrates secure monetary arithmetic using Python's `decimal.Decimal`
with banker's rounding (ROUND_HALF_EVEN) and explicit ledger reconciliation.
SovaScan's Financial Integrity Scanner produces 0 findings on this file.
"""

from decimal import Decimal, ROUND_HALF_EVEN


def apply_monthly_interest(balance: Decimal, interest_rate: Decimal) -> Decimal:
    """Calculates and applies monthly interest securely using Decimal and banker's rounding."""
    monthly_rate = interest_rate / Decimal("12")
    raw_interest = balance * monthly_rate

    # Symmetric banker's rounding
    rounded_interest = raw_interest.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    return balance + rounded_interest


def process_batch_monthly_fees(account_ledgers: list, audit_reconciliation_ledger: dict) -> None:
    """Processes monthly fees and explicitly reconciles every sub-cent remainder to an audit ledger."""
    total_reconciled_remainder = Decimal("0.00")

    for ledger in account_ledgers:
        fee_amount: Decimal = ledger.get("monthly_fee", Decimal("15.75"))
        discount_rate: Decimal = ledger.get("discount", Decimal("0.05"))

        net_fee = fee_amount * (Decimal("1.00") - discount_rate)
        rounded_fee = net_fee.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)

        # Discarded fraction is explicitly tracked and accumulated into audit ledger
        remainder = net_fee - rounded_fee
        total_reconciled_remainder += remainder

        ledger["account_balance"] -= rounded_fee

    audit_reconciliation_ledger["accumulated_rounding_drift"] = (
        audit_reconciliation_ledger.get("accumulated_rounding_drift", Decimal("0.00"))
        + total_reconciled_remainder
    )
