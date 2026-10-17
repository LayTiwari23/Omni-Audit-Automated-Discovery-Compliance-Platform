from celery import shared_task
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
import croniter
import json
from celery_app import celery
from workers.scan_worker import run_scan_task

# Import Base which now handles model registration
from app.db.base import Base
from app.models.scan_schedule import ScanSchedule
from app.models.scan_group import ScanGroup
from app.utils.target_expander import expand_targets

DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

def _create_and_launch_scan(db, user_id, target, engine_name, campaign_id, metadata=None):
    """Helper to insert scan record and launch Celery task."""
    from app.models.scan import Scan
    now = datetime.now(timezone.utc)
    
    # Engine name validation
    if not engine_name or engine_name.lower() == "unsupported":
        print(f"Skipping scan for {target}: Engine '{engine_name}' is not supported.")
        return

    # Use ORM instead of raw SQL for better JSONB handling
    new_scan = Scan(
        user_id=user_id,
        domain=target,
        scan_type=engine_name.lower(),
        group_id=campaign_id,
        status='PENDING',
        progress_percent=0,
        created_at=now,
        updated_at=now,
        scan_metadata=metadata # SQLAlchemy handles the JSONB conversion
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    print(f"Launched scan {new_scan.id} for {target} using {engine_name}")
    run_scan_task.delay(new_scan.id, target, engine_name.lower())

@shared_task
def run_scheduled_scan(schedule_id: int):
    """Execute a scheduled scan."""
    db = SessionLocal()
    try:
        # Fetch schedule
        schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
        if not schedule or not schedule.enabled:
            return

        print(f"Executing scheduled campaign: {schedule.name} (ID: {schedule_id})")

        # 1. Create a ScanGroup (Campaign)
        campaign_name = f"{schedule.name} (Scheduled)"
        
        # Convert now to IST for description (UTC + 5:30)
        ist_now = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
        
        campaign = ScanGroup(
            user_id=schedule.user_id,
            name=campaign_name,
            description=schedule.description or f"Scheduled run on {ist_now.strftime('%Y-%m-%d %H:%M')} IST",
            created_at=datetime.now(timezone.utc)
        )
        db.add(campaign)
        db.commit()
        db.refresh(campaign)

        # 2. Handle Scans
        common_metadata = {"schedule_id": schedule.id}
        
        if schedule.scan_type.lower() == 'auto':
            # AUTO MODE: Fresh discovery per target
            targets = expand_targets(schedule.target)
            for target in targets:
                _create_and_launch_scan(db, schedule.user_id, target, 'auto', campaign.id, metadata=common_metadata)
        elif schedule.selections:
            # If we have explicit selections stored, use them
            for sel in schedule.selections:
                target = sel.get("target")
                engine_name = sel.get("engine")
                port = sel.get("port")
                service = sel.get("service")
                version = sel.get("version")
                
                if not target or not engine_name:
                    continue
                    
                metadata = {**common_metadata, "port": port, "service": service, "version": version}
                _create_and_launch_scan(
                    db, schedule.user_id, target,
                    engine_name, campaign.id, metadata=metadata
                )
        else:
            # SPECIFIC MODE: Fallback to engine list
            targets = expand_targets(schedule.target)
            engine_list = [e.strip().lower() for e in schedule.scan_type.split(',')]
            for target in targets:
                for eng in engine_list:
                    _create_and_launch_scan(db, schedule.user_id, target, eng, campaign.id, metadata=common_metadata)

        # Update next_run based on cron
        try:
            now = datetime.now(timezone.utc)
            cron = croniter.croniter(schedule.cron_expression, now)
            schedule.next_run = cron.get_next(datetime)
            
            # Check if this is a "One-time" schedule (specific day and month)
            # A one-time cron usually has a fixed day (not *) and fixed month (not *)
            parts = schedule.cron_expression.split()
            if len(parts) == 5:
                dom, month = parts[2], parts[3]
                if dom != '*' and month != '*':
                    # It's a yearly/one-time scan. Disable it after the first run.
                    schedule.enabled = False
                    print(f"One-time schedule {schedule_id} completed and disabled.")
            
            db.commit()
            print(f"Schedule {schedule_id} updated. Next run: {schedule.next_run}")
        except Exception as e:
            print(f"Error calculating next run for schedule {schedule_id}: {e}")
    finally:
        db.close()

@celery.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    # This task runs every minute to check for due schedules
    sender.add_periodic_task(60.0, check_schedules.s(), name='check-schedules')

@shared_task
def check_schedules():
    """Check for due schedules and launch them."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        schedules = db.execute(
            text("SELECT id FROM scan_schedules WHERE enabled = TRUE AND next_run <= :now"),
            {"now": now}
        ).fetchall()
        for (sid,) in schedules:
            print(f"Schedule {sid} is due! Triggering...")
            run_scheduled_scan.delay(sid)
    finally:
        db.close()
