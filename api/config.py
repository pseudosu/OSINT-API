import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

# Define paths
BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / "api_keys.env"

# Try to load from .env file first (this won't override existing env vars)
if ENV_FILE.exists():
    print(f"Loading environment from: {ENV_FILE}")
    load_dotenv(ENV_FILE)
else:
    print(f"Env file not found at: {ENV_FILE}, using environment variables only")


class Settings(BaseSettings):
    APP_NAME: str = "OSINT Aggregator API"
    # Use redis as the hostname when in Docker
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # API keys - get from environment or blank
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_API_KEY: str = os.getenv("ALIENVAULT_API_KEY", "")

    # Default rate limits
    VT_RATE_LIMIT: int = 4
    ABUSEIPDB_RATE_LIMIT: int = 60
    ALIENVAULT_RATE_LIMIT: int = 100

    # Connection pool limits
    MAX_CONNECTIONS: int = 100
    MAX_KEEPALIVE: int = 20
    REQUEST_TIMEOUT: float = 30.0

    # Cache settings
    CACHE_EXPIRATION: int = 3600

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE) if ENV_FILE.exists() else None,
        env_file_encoding="utf-8"
    )


settings = Settings()

# Print debug information to help diagnose
print(f"Redis host: {settings.REDIS_HOST}")
print(f"VT API Key available: {'Yes' if settings.VT_API_KEY else 'No'}")
print(f"AbuseIPDB API Key available: {'Yes' if settings.ABUSEIPDB_API_KEY else 'No'}")
print(f"AlienVault API Key available: {'Yes' if settings.ALIENVAULT_API_KEY else 'No'}")