import httpx
import aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend

from app.config import settings

async_client = httpx.AsyncClient(
    limits=httpx.Limits(
        max_connections=settings.MAX_CONNECTIONS,
        max_keepalive_connections=settings.MAX_KEEPALIVE
    ),
    timeout=settings.REQUEST_TIMEOUT
)

redis_connection = None

def create_app() -> FastAPI:
    """Create and configure the FastAPI libary"""
    app = FastAPI(title=settings.APP_NAME)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    @app.on_event("startup")
    async def startup():
        global redis_connection
        redis_connection = aioredis.from_url(
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
            encoding="utf8",
            decode_responses=True,
            db=settings.REDIS_DB
        )
        FastAPICache.init(RedisBackend(redis_connection), prefix="osint-cache:")

    @app.on_event("shutdown")
    async def shutdown():
        await async_client.aclose()
        if redis_connection:
            await redis_connection.close()

    return app