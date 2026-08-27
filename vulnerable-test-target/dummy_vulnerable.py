# ==============================================================================
# SovaScan Demo Vulnerability Target File
# This dummy file contains typical security vulnerabilities used to test SovaScan.
# DO NOT deploy this file to a production environment.
# ==============================================================================

# 1. SECRET DETECTION (SOVA-SECRET-001 / SOVA-SECRET-002)
# SovaScan detects hardcoded secrets and api keys using entropy and regex patterns.
aws_secret = "AKIAIOSFODNN7EXAMPLE-SUPER-SECRET-KEY"
api_key = __import__('os').environ.get('SECRET_STRIPE_SECRET_KEY')
jwt_secret = "my-ultra-secure-jwt-secret-key-12345"

# Hardcoded database password
db_password = "admin_db_password_dont_commit_me"
db_pwd = "passwords123"

# 2. RBI CYBERSECURITY & PCI-DSS COMPLIANCE VIOLATIONS (BANK-001)
# SovaScan scans for storage of plaintext primary account numbers (PAN) or CVVs.
credit_card_number = "4111222233334444"
cvv = "987"
card_security_code = "123"

# 3. OTHER SENSITIVE INFO
# Database connection URI containing inline passwords
DATABASE_URL = __import__('os').environ.get('SECRET_DATABASE_CONNECTION_STRING_WIT')

print("Success: dummy_vulnerable.py executed cleanly!")

