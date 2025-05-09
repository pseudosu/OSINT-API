import httpx
from fastapi_cache.decorator import cache
from app.config import settings
from app.core.helpers import safe_api_call, get_semaphore, RateLimiter

abuseipdb_rate_limiter = RateLimiter(settings.VT_RATE_LIMIT)
abuseipdb_semaphore = get_semaphore("abuseipdb", settings.ABUSEIPDB_RATE_LIMIT)

@abuseipdb_rate_limiter
@cache(expire=settings.CACHE_EXPIRATION)
async def lookup_indicator(client: httpx.AsyncClient, indicator: str):

    async with abuseipdb_semaphore:
        result = await safe_api_call(
            client.get,
            f"https://www.abuseipdb.com/check/{indicator}/json?key={settings.ABUSEIPDB_API_KEY}"
        )
        return result