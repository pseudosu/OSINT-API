from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
import redis.asyncio as aioredis
from api.config import settings
import asyncio

# Import the shared app state
from api.core.state import app_state


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting application initialization...")

    # Initialize HTTP client first, as it has fewer dependencies
    try:
        print("Initializing HTTP client...")
        app_state.http_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=settings.MAX_CONNECTIONS,
                max_keepalive_connections=settings.MAX_KEEPALIVE
            ),
            timeout=settings.REQUEST_TIMEOUT,
            verify=True
        )
        print("HTTP client initialized successfully")
    except Exception as e:
        print(f"Error initializing HTTP client: {e}")
        # Initialize a basic client as fallback
        app_state.http_client = httpx.AsyncClient()
        print("Using fallback HTTP client")

    # Initialize Redis with retry logic
    print(f"Attempting to connect to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    for attempt in range(5):  # Try 5 times
        try:
            app_state.redis = aioredis.Redis.from_url(
                f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
                encoding="utf8",
                decode_responses=False,
                db=settings.REDIS_DB,
                max_connections=10,
            )

            # Test Redis connection
            ping_result = await app_state.redis.ping()
            print(f"Redis connection established, ping result: {ping_result}")

            # Initialize cache
            FastAPICache.init(
                RedisBackend(app_state.redis),
                prefix="osint-cache:"
            )

            print("Application startup complete with Redis")
            break
        except Exception as e:
            print(f"Redis connection attempt {attempt + 1} failed: {e}")
            if app_state.redis:
                await app_state.redis.close()
                app_state.redis = None

            if attempt < 4:  # Don't sleep on the last attempt
                await asyncio.sleep(2)  # Wait before retrying

    if not app_state.redis:
        print("WARNING: Could not connect to Redis after multiple attempts")

    # Verify the state before yielding
    print(
        f"State before yielding: HTTP client: {'OK' if app_state.http_client else 'MISSING'}, Redis: {'OK' if app_state.redis else 'MISSING'}")

    yield

    # Cleanup on shutdown
    if app_state.http_client:
        await app_state.http_client.aclose()

    if app_state.redis:
        await app_state.redis.close()

    print("Application shutdown complete")


app = FastAPI(
    title="OSINT Aggregator API",
    description="API for aggregating data from various OSINT sources",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# Dependency functions
def get_redis():
    if not app_state.redis:
        raise RuntimeError("Redis connection not available")
    return app_state.redis


def get_http_client():
    if not app_state.http_client:
        print("HTTP client state:", app_state.http_client)
        raise RuntimeError("HTTP client not available")
    return app_state.http_client


@app.get("/")
async def root():
    redis_status = "unavailable"
    http_client_status = "unavailable"

    try:
        if app_state.redis and await app_state.redis.ping():
            redis_status = "connected"
    except Exception as e:
        redis_status = f"error: {str(e)}"

    try:
        if app_state.http_client:
            http_client_status = "initialized"
    except Exception as e:
        http_client_status = f"error: {str(e)}"

    return {
        "message": "OSINT Aggregator API is running",
        "docs": "/docs",
        "redis_status": redis_status,
        "http_client_status": http_client_status,
        "endpoints": [
            "/api/v1/lookup/{indicator}",
            "/api/v1/bulk_lookup",
            "/api/v1/status/{task_id}"
        ]
    }
