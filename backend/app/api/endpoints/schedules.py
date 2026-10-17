from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timezone
from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.scan_schedule import ScanSchedule
import croniter

router = APIRouter()

class ScheduleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target: str
    scan_type: str
    scan_mode: str = "command_only"
    cron_expression: str
    discovery_job_id: Optional[int] = None
    selections: Optional[List[dict]] = None

class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    scan_mode: Optional[str] = None
    cron_expression: Optional[str] = None
    enabled: Optional[bool] = None
    discovery_job_id: Optional[int] = None
    selections: Optional[List[dict]] = None

class ScheduleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    target: str
    scan_type: str
    scan_mode: str
    cron_expression: str
    enabled: bool
    discovery_job_id: Optional[int]
    selections: Optional[List[dict]] = None
    next_run: Optional[datetime] = None
    last_run_status: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

@router.post("/schedules", response_model=ScheduleResponse)
def create_schedule(
    data: ScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Validate cron expression
    try:
        now = datetime.now(timezone.utc)
        cron = croniter.croniter(data.cron_expression, now)
        next_run = cron.get_next(datetime)
        
        # FIX: If the next_run is exactly 1 year away and today is the same date,
        # it means the user set a time for "today" that has already passed.
        # We should set it to 'now' so it triggers immediately.
        if (next_run - now).days >= 364:
             # Check if it would have matched today (simple check)
             # If the cron matches today's month/day, it's likely a "passed today" case
             next_run = now 
             
    except Exception:
        raise HTTPException(400, "Invalid cron expression")

    schedule = ScanSchedule(
        user_id=current_user.id,
        name=data.name,
        description=data.description,
        target=data.target,
        scan_type=data.scan_type,
        scan_mode=data.scan_mode,
        cron_expression=data.cron_expression,
        discovery_job_id=data.discovery_job_id,
        selections=data.selections,
        next_run=next_run,
        enabled=True,
        created_at=datetime.now(timezone.utc)
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.get("/schedules", response_model=List[ScheduleResponse])
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Return all schedules for the authenticated user."""
    schedules = db.query(ScanSchedule).filter(ScanSchedule.user_id == current_user.id).all()
    
    # Enrich with last run status
    from app.models.scan import Scan
    from sqlalchemy import cast, String
    from sqlalchemy.dialects.postgresql import JSONB
    
    enriched = []
    for s in schedules:
        item = ScheduleResponse.model_validate(s)
        
        # Find latest scan for this schedule using JSONB metadata (Postgres specific ->> operator)
        from sqlalchemy import text
        latest_scan = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            text("scan_metadata->>'schedule_id' = :sid")
        ).params(sid=str(s.id)).order_by(Scan.created_at.desc()).first()
        
        if latest_scan:
            item.last_run_status = latest_scan.status
            
        enriched.append(item)
        
    return enriched

@router.get("/schedules/{schedule_id}", response_model=ScheduleResponse)
def get_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id)
    if not current_user.is_admin:
        query = query.filter(ScanSchedule.user_id == current_user.id)
        
    schedule = query.first()
    if not schedule:
        raise HTTPException(404)
    return schedule

@router.put("/schedules/{schedule_id}", response_model=ScheduleResponse)
def update_schedule(
    schedule_id: int,
    data: ScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.user_id == current_user.id
    ).first()
    if not schedule:
        raise HTTPException(404)
    # Validate cron if provided
    if data.cron_expression is not None:
        try:
            croniter.croniter(data.cron_expression)
        except Exception:
            raise HTTPException(400, "Invalid cron expression")
    
    # Update fields
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(schedule, field, value)
    
    # Recalculate next_run if cron changed or enabled changed to true
    if data.cron_expression is not None or (data.enabled is True and not schedule.enabled):
        try:
            now = datetime.now(timezone.utc)
            cron = croniter.croniter(schedule.cron_expression, now)
            schedule.next_run = cron.get_next(datetime)
        except Exception:
            pass
    schedule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.user_id == current_user.id
    ).first()
    if not schedule:
        raise HTTPException(404)
    db.delete(schedule)
    db.commit()
    return {"ok": True}