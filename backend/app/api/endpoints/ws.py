import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
import redis.asyncio as redis
import os

from app.db.session import get_db
from app.models.scan_log import ScanLog
from app.models.scan import Scan

router = APIRouter()
discovery_router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

async def heartbeat(websocket: WebSocket):
    """
    Send a ping every 20 seconds to keep the connection alive.
    """
    try:
        while True:
            await asyncio.sleep(20)
            await websocket.send_text(json.dumps({"stage": "PING", "message": "keepalive"}))
    except Exception:
        pass

@discovery_router.websocket("/{job_id}")
async def discovery_logs_websocket(websocket: WebSocket, job_id: int):
    """
    WebSocket endpoint for live discovery logs.
    URL: /api/discovery-feed/{job_id}
    """
    await websocket.accept()
    print(f"Client connected to Discovery WebSocket for job {job_id}")
    
    r = redis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"discovery_logs_{job_id}"
    await pubsub.subscribe(channel)
    
    hb_task = asyncio.create_task(heartbeat(websocket))
    
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
    except WebSocketDisconnect:
        print(f"Client disconnected from WebSocket for discovery {job_id}")
    except Exception as e:
        print(f"Discovery WebSocket error for job {job_id}: {e}")
    finally:
        hb_task.cancel()
        await pubsub.unsubscribe(channel)
        await r.close()

@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: int, db: Session = Depends(get_db)):
    """
    Fetch all logs for a specific scan.
    """
    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at.asc()).all()
    return logs

@router.websocket("/{scan_id}/ws")
async def scan_logs_websocket(websocket: WebSocket, scan_id: int):
    """
    WebSocket endpoint for live scan logs.
    """
    await websocket.accept()
    
    # Connect to Redis for Pub/Sub
    r = redis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"scan_logs_{scan_id}"
    await pubsub.subscribe(channel)
    
    # Start heartbeat task
    hb_task = asyncio.create_task(heartbeat(websocket))
    
    try:
        # Listen for messages from Redis and push to WebSocket
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
    except WebSocketDisconnect:
        print(f"Client disconnected from WebSocket for scan {scan_id}")
    finally:
        hb_task.cancel()
        await pubsub.unsubscribe(channel)
        await r.close()

@router.websocket("/groups/{group_id}/ws")
async def scan_group_logs_websocket(websocket: WebSocket, group_id: int):
    """
    WebSocket endpoint for live logs of a whole scan group (campaign).
    """
    await websocket.accept()
    
    r = redis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"scan_group_logs_{group_id}"
    await pubsub.subscribe(channel)
    
    # Start heartbeat task
    hb_task = asyncio.create_task(heartbeat(websocket))
    
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
    except WebSocketDisconnect:
        print(f"Client disconnected from WebSocket for scan group {group_id}")
    finally:
        hb_task.cancel()
        await pubsub.unsubscribe(channel)
        await r.close()

@router.get("/groups/{group_id}/logs")
def get_scan_group_logs(group_id: int, db: Session = Depends(get_db)):
    """
    Fetch all logs for all scans in a specific campaign.
    """
    # Join ScanLog with Scan to filter by group_id
    logs = db.query(ScanLog).join(ScanLog.scan).filter(ScanLog.scan.has(group_id=group_id)).order_by(ScanLog.created_at.asc()).all()
    return logs
