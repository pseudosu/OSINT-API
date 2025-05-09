
import httpx
from fastapi_cache.decorator import cache
from api.config import settings
from api.core.helpers import safe_api_call, get_semaphore, RateLimiter, determine_indicator_type

vt_rate_limiter = RateLimiter(settings.VT_RATE_LIMIT)
vt_semaphore = get_semaphore("virustotal", settings.VT_RATE_LIMIT)


@cache(expire=settings.CACHE_EXPIRATION)
async def lookup_indicator(client: httpx.AsyncClient, indicator: str):
    """Look up an indicator in VirusTotal"""

    # Check if client is None
    if client is None:
        return {"error": "HTTP client not initialized"}

    # Determine the indicator type and corresponding endpoint
    indicator_type = determine_indicator_type(indicator)
    if indicator_type is None:
        return {"error": f"Could not determine the type of indicator: {indicator}"}

    async def do_lookup():
        try:
            # For IP, domain, or file hash
            endpoint = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"

            response = await client.get(
                endpoint,
                headers={"x-apikey": settings.VT_API_KEY}
            )

            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"error": "Invalid VirusTotal API key"}
            elif e.response.status_code == 404:
                return {"error": f"Indicator '{indicator}' not found in VirusTotal"}
            else:
                return {"error": f"VirusTotal API error: HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": f"VirusTotal lookup error: {str(e)}"}

    async with vt_semaphore:
        return await safe_api_call(do_lookup)