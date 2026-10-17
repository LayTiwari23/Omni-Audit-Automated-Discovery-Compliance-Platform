import redis
import json
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.scan_log import ScanLog

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

def log_to_db(db: Session, scan_id: int, stage: str, message: str):
    """
    Save a log message to the database.
    """
    log_entry = ScanLog(
        scan_id=scan_id,
        stage=stage,
        message=message,
        created_at=datetime.now()
    )
    db.add(log_entry)
    db.commit()
    return log_entry

def broadcast_log(scan_id: int = None, stage: str = "INFO", message: str = "", group_id: int = None, discovery_id: int = None):
    """
    Broadcast a log message via Redis Pub/Sub.
    """
    payload = {
        "scan_id": scan_id,
        "group_id": group_id,
        "discovery_id": discovery_id,
        "stage": stage,
        "message": message,
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    }
    
    # Broadcast to individual scan channel
    if scan_id:
        scan_channel = f"scan_logs_{scan_id}"
        redis_client.publish(scan_channel, json.dumps(payload))
    
    # Broadcast to group channel if group_id is provided
    if group_id:
        group_channel = f"scan_group_logs_{group_id}"
        redis_client.publish(group_channel, json.dumps(payload))

    # Broadcast to discovery channel if discovery_id is provided
    if discovery_id:
        discovery_channel = f"discovery_logs_{discovery_id}"
        redis_client.publish(discovery_channel, json.dumps(payload))

def log_event(db: Session, scan_id: int = None, stage: str = "INFO", message: str = "", group_id: int = None, discovery_id: int = None):
    """
    Log to both DB (if available) and broadcast via Redis.
    
    NOTE: 'LIVE' stage logs are NOT saved to DB to avoid flooding.
    They are only broadcast for real-time UI display.
    """
    # 1. Log to DB (only if a valid session is provided and stage is NOT 'LIVE' and scan_id is present)
    if db and stage != 'LIVE' and scan_id:
        try:
            log_to_db(db, scan_id, stage, message)
        except Exception as e:
            print(f"Error logging to DB: {e}")
    
    # 2. Try to find group_id if not provided and db is available
    if not group_id and db and scan_id:
        try:
            from sqlalchemy import text
            result = db.execute(text("SELECT group_id FROM scans WHERE id = :sid"), {"sid": scan_id}).fetchone()
            if result:
                group_id = result[0]
        except Exception:
            pass

    # 3. Always Broadcast via Redis
    try:
        broadcast_log(scan_id, stage, message, group_id, discovery_id)
    except Exception as e:
        print(f"Error broadcasting log: {e}")

    # 4. Also print to terminal (optional: skip printing LIVE lines to avoid terminal spam)
    if stage != 'LIVE':
        label = f"Scan {scan_id}" if scan_id else f"Discovery {discovery_id}"
        print(f"[{stage}] {label}: {message}")
