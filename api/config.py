import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "OSINT Aggregator API"
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: str = os.getenv("REDIS_PORT", 6379)
    REDIS_DB: int = int(os.getenv("REDIS_DB", 0))

    #API keys
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_API_KEY: str = os.getenv("ALIENVAULT_API_KEY", "")

    #Define some default rate limits, can be changed depending on the license we have
    VT_RATE_LIMIT: int = 4
    ABUSEIPDB_RATE_LIMIT: int = 60
    ALIENVAULT_RATE_LIMIT: int = 100

    # Connection pool limits
    MAX_CONNECTIONS: int = 100
    MAX_KEEPALIVE: int = 20
    REQUEST_TIMEOUT: float = 30.0

    #Cache settings
    CACHE_EXPIRATION: int = 3600

settings = Settings()