import asyncio
from fastapi import Request
import uvicorn
from app.api.endpoints import osint
from app.core.app import create_app

app = create_app()

app.include_router(osint.router, prefix="/api/v1", tags=["osint"])



@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = asyncio.get_event_loop().time()
    response = await call_next(request)
    process_time = asyncio.get_event_loop().time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)