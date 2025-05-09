import httpx
import ipaddress
import re
from fastapi_cache.decorator import cache
from api.config import settings
from api.core.helpers import safe_api_call, get_semaphore, RateLimiter

abuseipdb_rate_limiter = RateLimiter(settings.VT_RATE_LIMIT)
abuseipdb_semaphore = get_semaphore("abuseipdb", settings.ABUSEIPDB_RATE_LIMIT)


def is_ip_address(indicator):
    """Check if the indicator is a valid IP address"""
    try:
        ipaddress.ip_address(indicator)
        return True
    except ValueError:
        return False


def is_domain(indicator):
    """Check if the indicator is a valid domain name"""
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_pattern, indicator))


@abuseipdb_rate_limiter
@cache(expire=settings.CACHE_EXPIRATION)
async def lookup_indicator(client: httpx.AsyncClient, indicator: str):
    """Lookup the indicator in AbuseIPDB"""

    # Check if client is None
    if client is None:
        return {"error": "HTTP client not initialized"}

    # Check indicator type
    is_ip = is_ip_address(indicator)

    if not is_ip:
        return {"error": "AbuseIPDB only supports IP addresses via the API"}

    async def do_lookup():
        try:
            if is_ip:
                # For IP address: Use check endpoint
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={
                        "ipAddress": indicator,
                        "maxAgeInDays": 90,
                        "verbose": True
                    },
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    }
                )
            else:
                # For domain: Use domain-check endpoint
                return {"error": "AbuseIPDB only supports IP addresses via the API"}

            response.raise_for_status()
            # Process and filter the response
            result = response.json()

            # For IP addresses, filter and format the response
            if is_ip and "data" in result:
                # Get risk assessment based on abuse confidence score
                abuse_score = result["data"].get("abuseConfidenceScore", 0)
                if abuse_score >= 80:
                    risk = "High Risk"
                elif abuse_score >= 30:
                    risk = "Medium Risk"
                else:
                    risk = "Low Risk"

                # Get category names for the reports
                category_map = {
                    1: "DNS Compromise",
                    2: "DNS Poisoning",
                    3: "Fraud Orders",
                    4: "DDoS Attack",
                    5: "FTP Brute-Force",
                    6: "Ping of Death",
                    7: "Phishing",
                    8: "Fraud VoIP",
                    9: "Open Proxy",
                    10: "Web Spam",
                    11: "Email Spam",
                    12: "Blog Spam",
                    13: "VPN IP",
                    14: "Port Scan",
                    15: "Hacking",
                    16: "SQL Injection",
                    17: "Spoofing",
                    18: "Brute-Force",
                    19: "Bad Web Bot",
                    20: "Exploited Host",
                    21: "Web App Attack",
                    22: "SSH",
                    23: "IoT Targeted",
                }

                # Create a more readable summary
                categories_summary = {}
                if "reports" in result["data"] and result["data"]["reports"]:
                    # Count reports by category
                    for report in result["data"]["reports"]:
                        if "categories" in report:
                            for category_id in report["categories"]:
                                category_name = category_map.get(category_id, f"Category {category_id}")
                                if category_name not in categories_summary:
                                    categories_summary[category_name] = 0
                                categories_summary[category_name] += 1

                # Sort categories by count
                sorted_categories = sorted(
                    categories_summary.items(),
                    key=lambda x: x[1],
                    reverse=True
                )

                filtered_data = {
                    "summary": {
                        "ipAddress": result["data"].get("ipAddress"),
                        "risk_assessment": risk,
                        "abuseConfidenceScore": abuse_score,
                        "totalReports": result["data"].get("totalReports", 0),
                        "lastReportedAt": result["data"].get("lastReportedAt"),
                    },
                    "location": {
                        "countryName": result["data"].get("countryName"),
                        "countryCode": result["data"].get("countryCode"),
                    },
                    "network": {
                        "usageType": result["data"].get("usageType"),
                        "domain": result["data"].get("domain"),
                        "isTor": result["data"].get("isTor", False),
                        "isWhitelisted": result["data"].get("isWhitelisted", False),
                    },
                    "reportCategories": dict(sorted_categories[:5]),  # Top 5 categories
                }

                return filtered_data

            # For domains, format the response similarly
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 422:
                # Try to get error details from the response
                try:
                    error_detail = e.response.json()
                    return {"error": f"Invalid request to AbuseIPDB: {error_detail.get('errors', ['Unknown error'])}"}
                except:
                    return {"error": "Invalid format or other validation error"}
            elif e.response.status_code == 401:
                return {"error": "Invalid AbuseIPDB API key"}
            else:
                return {"error": f"AbuseIPDB API error: HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": f"AbuseIPDB lookup error: {str(e)}"}

            # For domains, return the response directly (it's already compact)
            return result

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 422:
                # Try to get error details from the response
                try:
                    error_detail = e.response.json()
                    return {"error": f"Invalid request to AbuseIPDB: {error_detail.get('errors', ['Unknown error'])}"}
                except:
                    return {"error": "Invalid format or other validation error"}
            elif e.response.status_code == 401:
                return {"error": "Invalid AbuseIPDB API key"}
            else:
                return {"error": f"AbuseIPDB API error: HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": f"AbuseIPDB lookup error: {str(e)}"}

    async with abuseipdb_semaphore:
        result = await safe_api_call(do_lookup)
        return result