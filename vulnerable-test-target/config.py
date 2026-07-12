# SovaScan test configuration file with exposed credentials

# Vulnerability: Hardcoded AWS Access Key ID
AWS_ACCESS_KEY = __import__('os').environ.get('SECRET_AWS_ACCESS_KEY_ID')

# Vulnerability: Hardcoded API Key
API_KEY = "super_secret_api_key_1234567890"

# Vulnerability: Hardcoded DB Connection string with credentials
DATABASE_URL = "postgresql://dbuser:supersecretpassword123@localhost:5432/payment_db"

# Vulnerability: Slack Webhook URL leaked
SLACK_WEBHOOK_URL = "https://hooks.slack.example/services/T12345678/B12345678/h12345678901234567890123"

# Vulnerability: Debug mode enabled (Spring/generic style)
DEBUG = True
dev_mode = "yes"
