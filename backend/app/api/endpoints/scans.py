from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone

from app.api.deps import get_db, get_current_user, check_target_permission
from app.models.user import User
from app.models.scan import Scan
from workers.scan_worker import run_scan_task

router = APIRouter()

class ScanStartRequest(BaseModel):
    selections: List[dict]  # each dict: {"target": str, "port": int, "engine": str}
    email_options: Optional[dict] = None  # {"from": str, "to": str}

@router.post("/start", response_model=List[dict])
def start_scans(
    req: ScanStartRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start multiple scans concurrently."""
    created_scans = []
    for sel in req.selections:
        target = sel["target"]
        engine = sel["engine"]
        
        # PERMISSION CHECK
        check_target_permission(db, current_user, target)

        
        # Determine email options if any
        email_from = None
        email_to = None
        if req.email_options:
            email_from = req.email_options.get("from")
            email_to = req.email_options.get("to")

        # Create scan record
        new_scan = Scan(
            user_id=current_user.id,
            domain=target,
            scan_type=engine,
            status="RUNNING",
            progress_percent=0,
            scan_metadata={"port": sel.get("port"), "email_from": email_from, "email_to": email_to},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        
        # Launch worker task
        run_scan_task.delay(
            new_scan.id, 
            target, 
            engine,
            email_from=email_from,
            email_to=email_to
        )
        
        created_scans.append({"id": new_scan.id, "target": target, "engine": engine})
    
    return created_scans
