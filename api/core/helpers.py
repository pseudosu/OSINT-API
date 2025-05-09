import asyncio
import ipaddress
import json
import re
import time
from functools import wraps
from typing import Callable, Dict, Any


#Semaphore registry to limit concurrent requests to each service
semaphores: Dict[str, asyncio.Semaphore] = {}

def get_semaphore(name: str, limit: int) -> asyncio.Semaphore:
    """Get or create a semaphore for a specific service"""
    if name not in semaphores:
            semaphores[name] = asyncio.Semaphore(limit)
    return semaphores[name]

async def safe_api_call(api_func: Callable, *args, **kwargs) -> Dict[str, Any]:
    try:
        coro = api_func(*args, **kwargs)
        return await asyncio.wait_for(coro, timeout=10.0)
    except asyncio.TimeoutError:
        return {"error": "Request timed out"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}

class RateLimiter:
    """Rate limiter to control requests per minute to external APIs"""
    def __init__(self, calls_per_minute: int):
        self.calls_per_minute = calls_per_minute
        self.interval = 60.0 / calls_per_minute
        self.last_call = 0
        self.lock = asyncio.Lock()

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async with self.lock:
                elapsed = time.time() - self.last_call
                if elapsed < self.interval:
                    await asyncio.sleep(self.interval - elapsed)
                self.last_call = time.time()
            return await func(*args, **kwargs)
        return wrapper


def safe_encode(value):
    """Safely encode a value to bytes if it's not already bytes"""
    if isinstance(value, bytes):
        return value
    elif isinstance(value, str):
        return value.encode('utf-8')
    else:
        return str(value).encode('utf-8')


def safe_decode(value):
    """Safely decode bytes to string if needed"""
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


async def store_task_result(redis, task_id: str, indicator: str, result: dict):
    """Store a task result in Redis with proper byte handling"""
    try:
        # Convert result to JSON string
        result_json = json.dumps(result)
        task_key = safe_encode(f"task:{task_id}")
        indicator_key = safe_encode(indicator)
        result_value = safe_encode(result_json)

        # Store in Redis
        await redis.hset(task_key, indicator_key, result_value)
    except Exception as e:
        print(f"Error storing task result: {str(e)}")
        # Continue without failing


async def get_task_results(redis, task_id: str):
    """Get all results for a task with proper byte handling"""
    results = {}
    try:
        # Get all results from Redis
        task_key = safe_encode(f"task:{task_id}")
        all_data = await redis.hgetall(task_key)

        # Process each key-value pair
        for key, value in all_data.items():
            try:
                # Always treat key as bytes for the startswith check
                if isinstance(key, bytes):
                    # Skip metadata fields (starting with _)
                    if not key.startswith(b'_'):
                        key_str = safe_decode(key)
                        value_str = safe_decode(value)
                        results[key_str] = json.loads(value_str)
                else:
                    # For string keys (shouldn't happen with decode_responses=False)
                    if not str(key).startswith('_'):
                        results[str(key)] = json.loads(str(value))
            except Exception as e:
                # Handle parsing errors but continue processing
                key_str = safe_decode(key) if isinstance(key, bytes) else str(key)
                results[key_str] = {"error": f"Failed to parse data: {str(e)}"}
    except Exception as e:
        print(f"Error getting task results: {str(e)}")

    return results

def determine_indicator_type(indicator):
    """Determine the type of indicator (IP, domain, hash)"""
    # Check for IP address
    try:
        ipaddress.ip_address(indicator)
        return "ip_addresses"
    except ValueError:
        pass

    # Check for domain
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, indicator):
        return "domains"

    # Check for file hash (MD5, SHA-1, SHA-256)
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha1_pattern = r"^[a-fA-F0-9]{40}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"

    if re.match(md5_pattern, indicator) or re.match(sha1_pattern, indicator) or re.match(sha256_pattern, indicator):
        return "files"

    # If we can't determine the type, return an error indicator
    return None