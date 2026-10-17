import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.api import deps
from app.models.user import User
from app.models.scan_group import ScanGroup
from app.models.scan import Scan
from app.models.discovery import DiscoveryJob
from app.schemas.scan import ScanResponse
from app.services.discovery_service import DiscoveryService
from app.utils.campaign_report_generator import generate_campaign_report
from app.utils.target_expander import expand_targets
from app.api.deps import get_db, get_current_user, check_target_permission
from workers.discovery_worker import run_discovery_task
from workers.scan_worker import run_scan_task

router = APIRouter()

class ScanGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ScanGroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: str
    scan_count: int
    completed_count: int
    failed_count: int
    avg_compliance: float
    engines: List[str]

class DiscoveryRequest(BaseModel):
    raw_input: str

class StartScansRequest(BaseModel):
    selections: List[dict]
    email_options: Optional[dict] = None

@router.post("/scan_groups", response_model=ScanGroupResponse)
def create_scan_group(
    *,
    db: Session = Depends(get_db),
    group_in: ScanGroupCreate,
    current_user: User = Depends(get_current_user),
):
    group = ScanGroup(name=group_in.name, description=group_in.description, user_id=current_user.id)
    db.add(group)
    db.commit()
    db.refresh(group)
    return _group_to_response(db, group)

@router.get("/scan_groups", response_model=List[ScanGroupResponse])
def list_scan_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return all scan groups for the authenticated user that have at least one scan."""
    groups = db.query(ScanGroup).filter(ScanGroup.user_id == current_user.id).order_by(ScanGroup.created_at.desc()).all()
    # Only include groups that have at least one scan
    active_groups = [g for g in groups if len(g.scans) > 0]
    return [_group_to_response(db, g) for g in active_groups]

@router.get("/scan_groups/{group_id}", response_model=ScanGroupResponse)
def get_scan_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanGroup).filter(ScanGroup.id == group_id)
    if not current_user.is_admin:
        query = query.filter(ScanGroup.user_id == current_user.id)
    
    group = query.first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return _group_to_response(db, group)

@router.get("/scan_groups/{group_id}/scans", response_model=List[ScanResponse])
def get_group_scans(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanGroup).filter(ScanGroup.id == group_id)
    if not current_user.is_admin:
        query = query.filter(ScanGroup.user_id == current_user.id)
    
    group = query.first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group.scans

@router.delete("/scan_groups/{group_id}/scans/{scan_id}")
def delete_group_scan(
    group_id: int,
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Scan).filter(Scan.id == scan_id, Scan.group_id == group_id)
    if not current_user.is_admin:
        query = query.filter(Scan.user_id == current_user.id)
        
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"detail": "Scan deleted"}

@router.delete("/scan_groups/{group_id}")
def delete_scan_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    group = db.query(ScanGroup).filter(ScanGroup.id == group_id, ScanGroup.user_id == current_user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Cascade delete will handle scans and results
    db.delete(group)
    db.commit()
    return {"detail": "Scan group and all associated scans deleted"}

@router.post("/scan_groups/{group_id}/discover", response_model=dict)
def start_group_discovery(
    group_id: int,
    req: DiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    group = db.query(ScanGroup).filter(ScanGroup.id == group_id, ScanGroup.user_id == current_user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # PERMISSION CHECK
    targets = expand_targets(req.raw_input)
    for target in targets:
        check_target_permission(db, current_user, target)

        
    service = DiscoveryService(db)
    job_id = service.start_discovery(current_user.id, "list", req.raw_input, group_id=group_id)
    run_discovery_task.delay(job_id)
    return {"job_id": job_id}

@router.post("/scan_groups/{group_id}/scans/start", response_model=List[ScanResponse])
def start_group_scans(
    group_id: int,
    req: StartScansRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    group = db.query(ScanGroup).filter(ScanGroup.id == group_id, ScanGroup.user_id == current_user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    created_scans = []
    for sel in req.selections:
        target = sel["target"]
        engine = sel["engine"]
        
        # PERMISSION CHECK
        check_target_permission(db, current_user, target)

        
        scan = Scan(
            user_id=current_user.id,
            domain=target,
            scan_type=engine,
            group_id=group.id,
            status="PENDING",
            scan_metadata={
                "port": sel.get("port"), 
                "service": sel.get("service"),
                "email_options": req.email_options if engine == "email" else None
            },
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        run_scan_task.delay(scan.id, target, engine, 
                           email_from=req.email_options.get("from") if req.email_options else None,
                           email_to=req.email_options.get("to") if req.email_options else None)
        created_scans.append(scan)
    return created_scans

@router.get("/scan_groups/{group_id}/report")
def generate_campaign_report_endpoint(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        group = db.query(ScanGroup).filter(ScanGroup.id == group_id, ScanGroup.user_id == current_user.id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Campaign not found")
        
        scans = [s for s in group.scans if s.status == "COMPLETED"]
        if not scans:
            # Check if there are ANY scans to provide a better error message
            if not group.scans:
                raise HTTPException(status_code=400, detail="No scans found in this campaign")
            else:
                raise HTTPException(status_code=400, detail="No scans have COMPLETED yet in this campaign. Please wait for scans to finish.")
        
        # Fetch discovery results for this group
        discovery_job = db.query(DiscoveryJob).filter(DiscoveryJob.group_id == group_id).order_by(DiscoveryJob.created_at.desc()).first()
        discovery_results = discovery_job.results if discovery_job else []
        
        # If no discovery results found, check if this is a scheduled campaign and look at parent schedule
        if not discovery_results and group.name.endswith("(Scheduled)"):
            # Try to find the parent schedule by name (prefix) and user_id
            sched_name = group.name.replace(" (Scheduled)", "")
            from app.models.scan_schedule import ScanSchedule
            parent_sched = db.query(ScanSchedule).filter(
                ScanSchedule.name == sched_name,
                ScanSchedule.user_id == current_user.id
            ).first()
            
            if parent_sched and parent_sched.discovery_job_id:
                # Use results from the setup-time discovery
                parent_job = db.query(DiscoveryJob).filter(DiscoveryJob.id == parent_sched.discovery_job_id).first()
                if parent_job:
                    discovery_results = parent_job.results

        pdf_bytes = generate_campaign_report(group, scans, discovery_results, db)
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=campaign_{group.id}_report.pdf",
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except Exception as e:
        import logging
        error_msg = str(e) or "Internal Server Error"
        logging.getLogger(__name__).error(f"Error in campaign report endpoint: {error_msg}", exc_info=True)
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=error_msg)

@router.get("/scan_groups/compare/all")
def compare_campaigns(
    group1_id: int = Query(..., alias="group1"),
    group2_id: int = Query(..., alias="group2"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    g1 = db.query(ScanGroup).filter(ScanGroup.id == group1_id, ScanGroup.user_id == current_user.id).first()
    g2 = db.query(ScanGroup).filter(ScanGroup.id == group2_id, ScanGroup.user_id == current_user.id).first()
    
    if not g1 or not g2:
        raise HTTPException(status_code=404, detail="One or both campaigns not found")
    
    # Calculate avg compliance for both
    def get_avg(group):
        scans = [s for s in group.scans if s.status == "COMPLETED"]
        if not scans: return 0.0
        return sum(s.compliance_percent or 0 for s in scans) / len(scans)
    
    avg1 = round(get_avg(g1), 2)
    avg2 = round(get_avg(g2), 2)
    
    # Group scans by (domain, scan_type) to match them
    def group_scans(group):
        return {(s.domain, s.scan_type): s for s in group.scans if s.status == "COMPLETED"}
    
    map1 = group_scans(g1)
    map2 = group_scans(g2)
    
    improved = []
    worsened = []
    unchanged = []
    
    # For common targets, we can do a deeper check-level comparison if requested, 
    # but for "Full Campaign Comparison" we might just compare their percentages.
    # However, to match the single-scan comparison UI, let's look at matched scans.
    
    all_keys = set(map1.keys()) | set(map2.keys())
    for key in all_keys:
        s1 = map1.get(key)
        s2 = map2.get(key)
        
        p1 = s1.compliance_percent if s1 else 0.0
        p2 = s2.compliance_percent if s2 else 0.0
        
        entry = {
            "target": key[0],
            "type": key[1],
            "scan1_id": s1.id if s1 else None,
            "scan2_id": s2.id if s2 else None,
            "pct1": p1,
            "pct2": p2,
            "diff": round(p2 - p1, 2)
        }
        
        if p2 > p1:
            improved.append(entry)
        elif p2 < p1:
            worsened.append(entry)
        else:
            unchanged.append(entry)
            
    return {
        "group1_id": g1.id,
        "group1_name": g1.name,
        "group1_avg": avg1,
        "group2_id": g2.id,
        "group2_name": g2.name,
        "group2_avg": avg2,
        "difference": round(avg2 - avg1, 2),
        "improved_scans": sorted(improved, key=lambda x: x["diff"], reverse=True),
        "worsened_scans": sorted(worsened, key=lambda x: x["diff"]),
        "unchanged_scans": unchanged,
        "is_campaign_comparison": True
    }

def _group_to_response(db: Session, group: ScanGroup) -> dict:
    scans = group.scans
    total = len(scans)
    completed = sum(1 for s in scans if s.status == "COMPLETED")
    failed = sum(1 for s in scans if s.status == "FAILED")
    avg = sum(s.compliance_percent or 0 for s in scans) / total if total else 0
    engines = list(set(s.scan_type for s in scans))
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "created_at": group.created_at.isoformat(),
        "scan_count": total,
        "completed_count": completed,
        "failed_count": failed,
        "avg_compliance": round(avg, 1),
        "engines": engines
    }
