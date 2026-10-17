import os
from celery import Celery
from app.db import base # Register models

# Get Redis URL from environment (default for local dev)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery(
    "compliance",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["workers.scan_worker", "scheduler.tasks", "workers.discovery_worker"]   # where tasks will be defined
)

# Optional configuration
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Kolkata",
    enable_utc=False,
    task_track_started=True,
    task_time_limit=3600,      # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
)
