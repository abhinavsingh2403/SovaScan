"""Sample Banking Interest & Fee Processing Module — Salami-Slicing Demonstration.

This file contains financial arithmetic patterns designed to demonstrate SovaScan's
Financial Integrity Scanner (FIN-001, FIN-002, FIN-003).

NOTE: This is a test file for security auditing and static analysis verification.
"""

import math


def apply_monthly_interest(balance: float, interest_rate: float) -> float:
    """Calculates and applies monthly compound interest to a savings account.

    FIN-001: Monetary parameters 'balance' and 'interest_rate' typed as float.
    FIN-002: One-directional truncation 'int()' applied to monetary calculation.
    FIN-003: Discarded fraction captured in 'skimmed_cents' but never referenced again.
    """
    raw_interest = (balance * interest_rate) / 12.0
    whole_cents_interest = int(raw_interest)

    # Orphaned remainder — captured but never reconciled or returned
    skimmed_cents = raw_interest - whole_cents_interest

    updated_balance = balance + whole_cents_interest
    return updated_balance


def process_batch_monthly_fees(account_ledgers: list) -> None:
    """Processes monthly account maintenance fees across customer ledgers.

    FIN-001: Local 'fee_amount' variable typed as float.
    FIN-002: One-directional truncation 'math.floor()' applied to monetary calculation.
    FIN-003: Discarded fraction captured in 'leftover_fraction' but never read again.
    """
    for ledger in account_ledgers:
        fee_amount: float = ledger.get("monthly_fee", 15.75)
        discount_rate: float = ledger.get("discount", 0.05)

        net_fee = fee_amount * (1.0 - discount_rate)
        truncated_fee = math.floor(net_fee)

        # Discarded fractional cents stored in un-read variable
        leftover_fraction = net_fee - truncated_fee

        ledger["account_balance"] -= truncated_fee


def calculate_loan_amortization_installment(principal_amount: float, annual_rate: float, tenure_months: int) -> float:
    """Calculates EMI installment for loan amortization schedule.

    FIN-001: Monetary parameter 'principal_amount' typed as float.
    FIN-002: Truncation with int() on monthly payment output.
    """
    monthly_rate = annual_rate / 12.0 / 100.0
    numerator = principal_amount * monthly_rate * ((1.0 + monthly_rate) ** tenure_months)
    denominator = ((1.0 + monthly_rate) ** tenure_months) - 1.0

    raw_emi = numerator / denominator
    final_emi = int(raw_emi)

    # Shaved cents captured in variable without ledger reconciliation
    unreconciled_cents = raw_emi - final_emi

    return float(final_emi)
