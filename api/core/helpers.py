import asyncio
import time
from functools import wraps
from typing import Callable, Dict, Any

from app.core.app import redis_connection

#Semaphore registry to limit concurrent requests to each service
semaphores: Dict[str, asyncio.Semaphore] = {}

def get_semaphore(name: str, limit: int) -> asyncio.Semaphore:
    """Get or create a semaphore for a specific service"""
    if name not in semaphores:
            semaphores[name] = asyncio.Semaphore(limit)
    return semaphores[name]

async def safe_api_call(api_func: Callable, *args, timeout: float= 10.0, **kwargs) -> Dict[str, Any]:
    try:
        return await asyncio.wait_for(api_func(*args, **kwargs), timeout=timeout)
    except asyncio.TimeoutError:
        return {"error": "Requet timed out"}
    except Exception as e:
        return {"error": str(e)}

class RateLimiter:
    """Rate limiter to control requests per minute to external APIs"""
    def __init__(self, calls_per_minute: int):
        self.calls_per_minute = calls_per_minute
        self.interval = 60.0 / calls_per_minute
        self.last_call = 0
        self.lock = asyncio.Lock()

    async def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async with self.lock:
                elapsed = time.time() - self.last_call
                if elapsed < self.interval:
                    await asyncio.sleep(self.interval - elapsed)
                self.last_call = time.time()
            return await func(*args, **kwargs)
        return wrapper

async def store_task_result(task_id, indicator, result):
    import json
    await redis_connection.hset(f"task:{task_id}", indicator, json.dumps(result))

async def get_task_results(redis, task_id):

    results = await redis.hgetall(f"task:{task_id}")
    import json

    return {k: json.loads(v) for k, v in results.items()}