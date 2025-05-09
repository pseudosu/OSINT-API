from ctypes import HRESULT
from http.client import responses

import httpx
from fastapi_cache.decorator import cache
from app.config import settings
from app.core.helpers import safe_api_call, get_semaphore, RateLimiter

vt_rate_limiter = RateLimiter(settings.VT_RATE_LIMIT)
vt_semaphore = get_semaphore("virustotal", settings.VT_RATE_LIMIT)

@vt_rate_limiter
@cache(expire=settings.CACHE_EXPIRATION)
async def lookup_indicator(client: httpx.AsyncClient, indicator: str):
    """Lookup the indicator"""
    async def _do_lookup():
        response = await client.get(
            f"https://virustotal.com/api/v3/indicators/{indicator}",
            headers={"x-apikey": settings.VT_API_KEY}
        )
        response.raise_for_status()
        return response.json()

    async with vt_semaphore:
        result = await safe_api_call(_do_lookup())
        return result