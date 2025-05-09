import datetime
import ipaddress
from typing import List, Dict, Any, Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, Request, HTTPException
import httpx
import uuid
import asyncio
import json
from pydantic import BaseModel

from api.core.helpers import determine_indicator_type, safe_decode, safe_encode
from api.services import virustotal, abuseipdb
from api.core.app import get_http_client, get_redis

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
        if not key.startswith('_'):
            try:
                results[key] = json.loads(value)
            except json.JSONDecodeError:
                results[key] = {"error": f"Failed to parse result data for {key}"}

    return results


@router.get("/lookup/{indicator}")
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


@router.post("/bulk_lookup")
async def bulk_lookup(
        data: IndicatorList,
        background_tasks: BackgroundTasks,
        client: httpx.AsyncClient = Depends(get_http_client)
):
    """Submit a list of indicators for bulk lookup"""
    try:
        redis = get_redis()
        task_id = str(uuid.uuid4())
        task_key = f"task:{task_id}".encode()

        # Initialize task in Redis
        await redis.hset(task_key, b"_processing", b"1")

        async def process_bulk():
            try:
                for i, indicator in enumerate(data.indicators):
                    try:
                        print(f"Processing indicator {i + 1}/{len(data.indicators)}: {indicator}")
                        print(f"Indicator type: {type(indicator)}")

                        # Get the lookup result
                        result = await lookup_indicator(indicator, None, client)

                        # Convert to JSON for storage
                        result_json = json.dumps(result)
                        print(f"Result JSON type: {type(result_json)}")

                        # Create the indicator key
                        indicator_key = indicator.encode()
                        print(f"Indicator key type: {type(indicator_key)}")

                        # Store directly in Redis
                        await redis.hset(task_key, indicator_key, result_json.encode())
                        print(f"Successfully stored indicator {indicator}")
                    except Exception as e:
                        print(f"ERROR processing indicator {indicator}: {str(e)}")
                        print(f"Error type: {type(e)}")
                        # Store the error
                        error_msg = f"Failed to process: {str(e)}"
                        await redis.hset(
                            task_key,
                            indicator.encode(),
                            json.dumps({"error": error_msg}).encode()
                        )

                # Mark as complete when done
                await redis.hset(task_key, b"_processing", b"0")
            except Exception as e:
                print(f"Critical error in bulk processing: {str(e)}")
                await redis.hset(task_key, b"_error", str(e).encode())
                await redis.hset(task_key, b"_processing", b"0")

        background_tasks.add_task(process_bulk)
        return {"task_id": task_id, "status": "processing"}
    except Exception as e:
        print(f"Error initiating bulk lookup: {str(e)}")
        return {"status": "error", "error": str(e)}


@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """Get the status of a bulk search from Redis"""
    try:
        redis = get_redis()
        task_key = f"task:{task_id}".encode()

        # Check if the task exists in Redis
        task_exists = await redis.exists(task_key)

        if not task_exists:
            return {"task_id": task_id, "status": "not_found"}

        # Check if processing is complete
        processing = await redis.hget(task_key, b"_processing")
        if processing == b"1":
            # Task is still processing
            return {"task_id": task_id, "status": "processing"}

        # Get error if any
        error = await redis.hget(task_key, b"_error")
        if error:
            return {"task_id": task_id, "status": "error", "error": error.decode()}

        # Get all results
        all_data = await redis.hgetall(task_key)
        results = {}

        for key, value in all_data.items():
            # Skip metadata fields
            if key.startswith(b'_'):
                continue

            try:
                # Decode the key and value
                key_str = key.decode()
                value_str = value.decode()
                # Parse the JSON
                results[key_str] = json.loads(value_str)
            except Exception as e:
                print(f"Error processing result for {key}: {str(e)}")
                # Add error info but continue processing other results
                try:
                    key_str = key.decode() if isinstance(key, bytes) else str(key)
                    results[key_str] = {"error": f"Failed to parse data: {str(e)}"}
                except:
                    # Last resort fallback
                    results[f"unknown_{len(results)}"] = {"error": "Unparseable data"}

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