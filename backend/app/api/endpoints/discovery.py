from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional

from app.api.deps import get_db, get_current_user, check_target_permission
from app.models.user import User
from app.services.discovery_service import DiscoveryService
from app.utils.target_expander import expand_targets
from workers.discovery_worker import run_discovery_task
from app.models.discovery import DiscoveryJob, DiscoveryStatus

router = APIRouter()

class DiscoveryStartRequest(BaseModel):
    input_type: str  # 'list', 'range', 'file'
    raw_input: str

class DiscoveryStatusResponse(BaseModel):
    id: int
    status: str
    total_targets: int
    processed_targets: int
    created_at: str
    updated_at: Optional[str]

class DiscoveryResultResponse(BaseModel):
    id: int
    target_ip: Optional[str]
    target_domain: Optional[str]
    port: int
    state: str
    service: str
    engine: str
    version_info: Optional[str]
    error: Optional[str]
    scans: List[dict] = []

@router.post("/discover", response_model=dict)
def start_discovery(
    req: DiscoveryStartRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a discovery job."""
    # PERMISSION CHECK
    targets = expand_targets(req.raw_input)
    for target in targets:
        check_target_permission(db, current_user, target)
        
    service = DiscoveryService(db)
    job_id = service.start_discovery(current_user.id, req.input_type, req.raw_input)
    # Run discovery in background
    run_discovery_task.delay(job_id)
    return {"job_id": job_id}

@router.get("/discover/{job_id}/status", response_model=DiscoveryStatusResponse)
def get_discovery_status(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id, DiscoveryJob.user_id == current_user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return {
        "id": job.id,
        "status": job.status.value,
        "total_targets": job.total_targets,
        "processed_targets": job.processed_targets,
        "created_at": job.created_at.isoformat(),
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
    }

@router.get("/discover/{job_id}/results", response_model=List[DiscoveryResultResponse])
def get_discovery_results(
    job_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id, DiscoveryJob.user_id == current_user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    service = DiscoveryService(db)
    return service.get_discovery_results(job_id)
