"""SovaScan configuration management using Pydantic Settings."""

import pathlib
from functools import lru_cache

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
