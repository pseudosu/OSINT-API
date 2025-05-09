from typing import List
from fastapi import APIRouter, BackgroundTasks, Depends, Request
import httpx
import uuid
import asyncio
import json

from fastapi_cache.decorator import cache
from pydantic import BaseModel

from api.core.helpers import determine_indicator_type
from api.services import virustotal, abuseipdb

# Import the shared state directly
from api.core.state import app_state
# Still use the dependency for HTTP client
from api.core.app import get_http_client

router = APIRouter()


async def store_task_result(redis, task_id: str, indicator: str, result: dict):
    """Store a task result in Redis"""
    # Convert result to JSON string
    result_json = json.dumps(result)
    # Store in Redis
    await redis.hset(f"task:{task_id}", indicator, result_json)


async def get_task_results(redis, task_id: str):
    """Get all results for a task"""
    # Get all results from Redis
    all_data = await redis.hgetall(f"task:{task_id}")

    # Filter out metadata fields and convert JSON
    results = {}
    for key, value in all_data.items():
        # Skip metadata fields (starting with _)
        if isinstance(key, bytes):
            key = key.decode()

        if isinstance(value, bytes):
            value = value.decode()

        if not key.startswith('_'):
            try:
                results[key] = json.loads(value)
            except json.JSONDecodeError:
                results[key] = {"error": f"Failed to parse result data for {key}"}

    return results


@router.get("/lookup/{indicator}")
@cache(expire=3600)
async def lookup_indicator(
        indicator: str,
        request: Request = None,
        client: httpx.AsyncClient = Depends(get_http_client)
):
    """Look up an indicator from all supported sources"""

    # Determine indicator type
    indicator_type = determine_indicator_type(indicator)

    # Always query VirusTotal
    vt_task = virustotal.lookup_indicator(client, indicator)

    # Initialize response
    response = {
        "indicator": indicator,
        "sources": {}
    }

    # Only query AbuseIPDB for IP addresses or domains
    if indicator_type in ["ip_addresses", "domains"]:
        abuseipdb_task = abuseipdb.lookup_indicator(client, indicator)
        results = await asyncio.gather(vt_task, abuseipdb_task)

        response["sources"]["virustotal"] = results[0]
        response["sources"]["abuseipdb"] = results[1]
    else:
        # Just query VirusTotal for other types
        vt_result = await vt_task
        response["sources"]["virustotal"] = vt_result
        response["sources"]["abuseipdb"] = {"error": "AbuseIPDB only supports IP addresses and domains"}

    return response


class IndicatorList(BaseModel):
    indicators: List[str]


# This function will be executed directly, not as a background task
async def process_indicators_concurrently(indicators, client, redis, task_id):
    """Process indicators concurrently with a semaphore to limit concurrency"""
    task_key = f"task:{task_id}"

    try:
        # Create a semaphore to limit concurrent processing
        # This controls how many indicators are processed at once
        semaphore = asyncio.Semaphore(5)  # Process 5 indicators at a time

        async def process_indicator(indicator):
            # Use semaphore to limit concurrency
            async with semaphore:
                try:
                    # Get the lookup result
                    result = await lookup_indicator(indicator, None, client)

                    # Store result in Redis
                    await redis.hset(task_key, indicator, json.dumps(result))

                    # Increment processed count
                    await redis.hincrby(task_key, "_processed", 1)

                    print(f"Processed: {indicator}")
                except Exception as e:
                    print(f"Error processing {indicator}: {str(e)}")
                    error_msg = {"error": f"Failed to process: {str(e)}"}
                    await redis.hset(task_key, indicator, json.dumps(error_msg))
                    await redis.hincrby(task_key, "_processed", 1)

        # Create tasks for all indicators
        tasks = [process_indicator(indicator) for indicator in indicators]

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)

        # Mark task as complete
        await redis.hset(task_key, "_processing", "0")
        print(f"Bulk processing complete for task {task_id}")

    except Exception as e:
        print(f"Critical error in bulk processing: {str(e)}")
        await redis.hset(task_key, "_error", str(e))
        await redis.hset(task_key, "_processing", "0")


@router.post("/bulk_lookup")
async def bulk_lookup(
        data: IndicatorList,
        client: httpx.AsyncClient = Depends(get_http_client)
):
    """Submit a list of indicators for bulk lookup"""
    try:
        # Get Redis directly from app_state
        redis = app_state.redis
        if not redis:
            return {"status": "error", "error": "Redis connection not available"}

        task_id = str(uuid.uuid4())
        task_key = f"task:{task_id}"

        # Initialize task in Redis
        await redis.hset(task_key, "_processing", "1")
        await redis.hset(task_key, "_total", str(len(data.indicators)))
        await redis.hset(task_key, "_processed", "0")

        # Start processing immediately in the background
        # This doesn't use FastAPI's background_tasks to avoid potential issues
        asyncio.create_task(process_indicators_concurrently(data.indicators, client, redis, task_id))

        # Return response immediately
        return {"task_id": task_id, "status": "processing"}
    except Exception as e:
        print(f"Error initiating bulk lookup: {str(e)}")
        return {"status": "error", "error": str(e)}


@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """Get the status of a bulk search from Redis"""
    try:
        # Get Redis directly from app_state
        redis = app_state.redis
        if not redis:
            return {"task_id": task_id, "status": "error", "error": "Redis connection not available"}

        task_key = f"task:{task_id}"

        # Check if the task exists in Redis
        task_exists = await redis.exists(task_key)

        if not task_exists:
            return {"task_id": task_id, "status": "not_found"}

        # Get processing status and progress
        processing = await redis.hget(task_key, "_processing")
        total = await redis.hget(task_key, "_total")
        processed = await redis.hget(task_key, "_processed")

        # Handle type conversions properly
        if isinstance(processing, bytes):
            processing = processing.decode()

        if isinstance(total, bytes):
            total = total.decode()

        if isinstance(processed, bytes):
            processed = processed.decode()

        if total:
            total = int(total)
        else:
            total = 0

        if processed:
            processed = int(processed)
        else:
            processed = 0

        progress = (processed / total * 100) if total > 0 else 0

        # Check if processing is still happening
        if processing == "1":
            # Task is still processing
            return {
                "task_id": task_id,
                "status": "processing",
                "progress": {
                    "processed": processed,
                    "total": total,
                    "percent": round(progress, 2)
                }
            }

        # Get error if any
        error = await redis.hget(task_key, "_error")
        if error:
            if isinstance(error, bytes):
                error = error.decode()
            return {"task_id": task_id, "status": "error", "error": error}

        # Get all results
        all_data = await redis.hgetall(task_key)
        results = {}

        for key, value in all_data.items():
            # Handle byte conversion
            if isinstance(key, bytes):
                key = key.decode()

            if isinstance(value, bytes):
                value = value.decode()

            # Skip metadata fields
            if key.startswith("_"):
                continue

            try:
                # Parse the JSON
                results[key] = json.loads(value)
            except Exception as e:
                print(f"Error processing result for {key}: {str(e)}")
                results[key] = {"error": f"Failed to parse data: {str(e)}"}

        # Return completed status with results
        return {
            "task_id": task_id,
            "status": "completed",
            "indicators_processed": len(results),
            "results": results
        }
    except Exception as e:
        print(f"Error in get_task_status: {str(e)}")
        return {"task_id": task_id, "status": "error", "error": f"Error: {str(e)}"}