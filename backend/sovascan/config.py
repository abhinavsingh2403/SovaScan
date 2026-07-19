"""SovaScan configuration management using Pydantic Settings."""

import ipaddress
import pathlib
import socket
from functools import lru_cache
from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file.

    All settings can be overridden via environment variables with the same
    name (case-insensitive). A .env file in the project root is also
    automatically loaded if present.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = "sqlite:///./sovascan.db"

    # Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    SLACK_WEBHOOK_URL: str = ""
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # External vulnerability APIs
    OSV_API_URL: str = "https://api.osv.dev/v1"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""

    # Scan settings
    SCAN_TIMEOUT: int = 300
    MAX_FILE_SIZE: int = 10_000_000  # 10 MB

    # Rules directory
    RULES_DIR: str = str(
        pathlib.Path(__file__).parent / "rules"
    )

    @property
    def database_url_for_engine(self) -> str:
        """Return the DATABASE_URL, handling SQLite-specific adjustments.

        SQLAlchemy 2.0 requires 'sqlite+aiosqlite' for async or
        'sqlite:///' for sync. This property ensures compatibility.
        """
        url = self.DATABASE_URL
        if url.startswith("sqlite:///") and "check_same_thread" not in url:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}check_same_thread=False"
        return url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance.

    The instance is created once and reused for the lifetime of the process.
    Environment variables and .env values are read at creation time.

    Returns:
        Settings: The application settings singleton.
    """
    return Settings()


def is_safe_webhook_url(url: str) -> bool:
    """Validate that the URL uses HTTPS and resolves to a public, non-internal IP address.

    This prevents SSRF (Server-Side Request Forgery) attacks.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        # 1. Enforce HTTPS only (Slack/Teams webhooks are secure)
        if parsed.scheme.lower() != "https":
            return False

        host = parsed.hostname
        if not host:
            return False

        # 2. Prevent common SSRF host bypasses (e.g., localhost, loopback)
        if host.lower() in ("localhost", "localhost.localdomain", "127.0.0.1", "[::1]", "0.0.0.0"):
            return False

        # 3. Resolve hostname to all associated IPs to check them
        # (This protects against DNS Rebinding and split-horizon DNS)
        try:
            addr_info = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False  # Failed to resolve host

        for info in addr_info:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                # Check if it's loopback, private, link-local, multicast, or unspecified
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return False
            except ValueError:
                # If it's not a valid IP, fail closed
                return False

        return True
    except Exception:
        return False


def mask_slack_webhook(url: str) -> str:
    """Mask sensitive tokens inside a Slack Webhook URL."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) >= 3 and path_parts[0] == "services":
            # path_parts[1] is T..., path_parts[2] is B..., path_parts[3] is token
            masked_parts = ["services"]
            for part in path_parts[1:]:
                if len(part) > 4:
                    masked_parts.append(part[:3] + "..." + "*" * 4)
                else:
                    masked_parts.append("*" * len(part))
            masked_path = "/" + "/".join(masked_parts)
            return parsed._replace(path=masked_path).geturl()
    except Exception:
        pass
    if len(url) > 15:
        return url[:12] + "..." + "*" * 8
    return "*" * len(url)


def mask_database_url(url: str) -> str:
    """Mask credential details inside a database connection URI."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if parsed.password:
            # Mask the password
            netloc = parsed.netloc.replace(f":{parsed.password}@", f":{'*' * 8}@", 1)
            return parsed._replace(netloc=netloc).geturl()
    except Exception:
        pass
    return url
