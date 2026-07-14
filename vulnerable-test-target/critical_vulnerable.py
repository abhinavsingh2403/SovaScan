# ==============================================================================
# SovaScan Demo Critical Vulnerability Target File
# This file contains critical security vulnerabilities across multiple vectors:
# 1. SAST (Command Injection & SQL Injection)
# 2. Hardcoded Credentials (Exposed RSA Private Key)
# 3. Compliance Violations (Plaintext Credit Card CVV/PIN Storage)
# ==============================================================================

import os
import subprocess
import sqlite3

# ------------------------------------------------------------------------------
# 1. SAST: CRITICAL COMMAND INJECTION (Bandit B602 / Semgrep)
# ------------------------------------------------------------------------------
def execute_system_check(target_host: str) -> None:
    """Executes a system ping target using raw string shell execution.
    This allows arbitrary command execution if shell=True is enabled.
    """
    # CRITICAL: User input is directly interpolated into a shell command!
    command = f"ping -c 4 {target_host}"
    print(f"[DEBUG] Running command: {command}")
    subprocess.Popen(command, shell=True)


# ------------------------------------------------------------------------------
# 2. SAST: CRITICAL SQL INJECTION (Bandit B608 / Semgrep)
# ------------------------------------------------------------------------------
def query_user_records(auth_input: str) -> list:
    """Queries user database records using direct string interpolation.
    This is highly vulnerable to raw SQL injection payloads.
    """
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    # CRITICAL: Hardcoded raw SQL query with unescaped user parameters!
    query = f"SELECT * FROM accounts WHERE username = '{auth_input}' AND is_active = 1"
    cursor.execute(query)
    return cursor.fetchall()


# ------------------------------------------------------------------------------
# 3. SECRETS: HARDCODED PRIVATE RSA KEYS (SovaScan Secrets Crawler)
# ------------------------------------------------------------------------------
# CRITICAL: Leaking exposed cryptographic keys in repository source code!
SSH_ROOT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MOCK_SSH_PRIVATE_KEY_CONTENT_FOR_SOVASCAN_VULNERABILITY_DETECTION_TESTING
-----END RSA PRIVATE KEY-----"""


# ------------------------------------------------------------------------------
# 4. COMPLIANCE: STORAGE OF CARD PIN & CVV (PCI-DSS & RBI-CSF Violations)
# ------------------------------------------------------------------------------
class PaymentCardTransaction:
    """Simulates a payment gateway payload storage module."""
    def __init__(self, holder_name: str, pan: str, cvv_code: str, pin: str):
        self.holder = holder_name
        # CRITICAL: Storing plaintext Primary Account Number (PAN)
        self.credit_card_number = pan
        # CRITICAL: Storing plaintext Card Verification Value (CVV)
        self.cvv = cvv_code
        # CRITICAL: Storing plaintext Cardholder Personal Identification Number (PIN)
        self.card_pin = pin


if __name__ == "__main__":
    print("SovaScan Critical Vulnerabilities file loaded.")
