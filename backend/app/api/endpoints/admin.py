from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from datetime import datetime, timedelta
import os
import redis

from app.db.session import get_db
from app.api import deps
from app.models.user import User
from app.models.scan import Scan
from app.models.scan_result import ScanRawResult
from app.models.admin import AuditLog, SystemSetting, GlobalBlacklist, AdminBroadcast, DynamicCheck

router = APIRouter()

# --- 1. Advanced Analytics ---

@router.get("/stats/compliance-heatmap")
def get_compliance_heatmap(
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user),
):
    """
    Returns average compliance scores grouped by user/department.
    """
    results = db.query(
        User.username,
        func.avg(Scan.compliance_percent).label("avg_score"),
        func.count(Scan.id).label("scan_count")
    ).join(Scan).group_by(User.id).all()
    
    return [{"group": r.username or "Unknown", "score": float(r.avg_score or 0), "count": r.scan_count} for r in results]

@router.get("/stats/engine-performance")
def get_engine_performance(
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user),
):
    """
    Returns success/failure rates per engine.
    Excludes 'auto' as it is a meta-type.
    """
    total_scans = db.query(
        Scan.scan_type,
        func.count(Scan.id).label("total")
    ).filter(Scan.scan_type != 'auto').group_by(Scan.scan_type).all()
    
    failed_scans = db.query(
        Scan.scan_type,
        func.count(Scan.id).label("failed")
    ).filter(Scan.status == 'FAILED', Scan.scan_type != 'auto').group_by(Scan.scan_type).all()
    
    fail_map = {r.scan_type: r.failed for r in failed_scans}
    
    return [
        {
            "engine": r.scan_type.upper(),
            "total": r.total,
            "failed": fail_map.get(r.scan_type, 0),
            "success_rate": round(((r.total - fail_map.get(r.scan_type, 0)) / r.total) * 100, 2) if r.total > 0 else 0
        }
        for r in total_scans
    ]

@router.get("/stats/queue-depth")
def get_queue_depth(
    admin_user: User = Depends(deps.get_current_admin_user),
):
    """
    Returns live visual of Celery queue depth.
    """
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        client = redis.from_url(redis_url)
        pending = client.llen("celery")
        return {"queued": pending, "active": 0}
    except Exception as e:
        return {"queued": 0, "active": 0, "error": str(e)}

# --- 2. Activity Auditing ---

@router.get("/audit-logs", response_model=List[Dict[str, Any]])
def get_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "user": l.user.username if l.user else "System",
            "action": l.action,
            "target": f"{l.target_type}:{l.target_id}" if l.target_type else "Global",
            "details": l.details,
            "timestamp": l.created_at,
            "ip": l.ip_address
        }
        for l in logs
    ]

# --- 3. Governance & Global Controls ---

@router.get("/blacklist", response_model=List[Dict[str, Any]])
def get_blacklist(
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    items = db.query(GlobalBlacklist).all()
    return [
        {
            "id": i.id,
            "target": i.target,
            "reason": i.reason,
            "created_at": i.created_at
        }
        for i in items
    ]

@router.post("/blacklist")
def add_to_blacklist(
    target: str,
    reason: str = None,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    entry = GlobalBlacklist(target=target, reason=reason)
    db.add(entry)
    db.commit()
    return {"status": "added"}

@router.delete("/blacklist/{id}")
def remove_from_blacklist(
    id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    db.query(GlobalBlacklist).filter(GlobalBlacklist.id == id).delete()
    db.commit()
    return {"status": "removed"}

# --- 4. Maintenance ---

@router.post("/maintenance/cleanup")
def perform_cleanup(
    days: int = 90,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    """
    Deletes scans older than X days.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    count = db.query(Scan).filter(Scan.created_at < cutoff).delete()
    db.commit()
    return {"deleted_count": count}

@router.get("/broadcasts")
def get_broadcasts(
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    broadcasts = db.query(AdminBroadcast).all()
    return [
        {
            "id": b.id,
            "message": b.message,
            "level": b.level,
            "is_active": b.is_active,
            "expires_at": b.expires_at,
            "created_at": b.created_at
        }
        for b in broadcasts
    ]

@router.post("/broadcasts")
def create_broadcast(
    message: str,
    level: str = "info",
    expires_in_hours: int = 24,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
    b = AdminBroadcast(message=message, level=level, expires_at=expires_at)
    db.add(b)
    db.commit()
    return {"status": "created"}

# --- 5. Dynamic Checks Management ---

@router.get("/dynamic-checks")
def get_dynamic_checks(
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    """
    Retrieve all dynamic compliance checks.
    """
    return db.query(DynamicCheck).all()

import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
from fastapi import APIRouter, Depends, HTTPException, status, Query

# ... (rest of imports)

class CreateDynamicCheckRequest(BaseModel):
    engine:           str
    tool_name:        str = "nmap"
    check_name:       str
    command_template: str
    success_criteria: str
    severity:         str = "INFO"
    cvss_score:       float = Field(0.0, ge=0.0, le=10.0)
    timeout:          int = Field(300, ge=5, le=1800)
    remediation_text: Optional[str] = None

    @validator('command_template')
    def validate_command(cls, v, values):
        # Basic shell injection prevention
        forbidden = [';', '&&', '||', '|', '`', '$']
        if any(c in v for c in forbidden):
            raise ValueError("Command contains forbidden shell characters")
        
        # Ensure at least one placeholder is present for nmap
        if values.get('tool_name') == 'nmap' and '{domain}' not in v and '{dns_ip}' not in v:
            raise ValueError("Nmap command must contain {domain} or {dns_ip} placeholder")
        return v

    @validator('success_criteria')
    def validate_regex(cls, v):
        try:
            re.compile(v)
        except re.error:
            raise ValueError("Invalid regular expression")
        return v

@router.post("/dynamic-checks")
def create_dynamic_check(
    body: CreateDynamicCheckRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    """
    Create a new dynamic compliance check with auto-generated ID.
    """
    # 1. Generate Check ID: <ENGINE>_<NAME_SLUG>_<UUID_SHORT>
    import uuid
    slug = re.sub(r'[^a-z0-9]', '', body.check_name.lower())[:10]
    short_id = str(uuid.uuid4())[:4]
    check_id_string = f"{body.engine.upper()}_{slug}_{short_id}"

    check = DynamicCheck(
        **body.dict(),
        check_id_string=check_id_string
    )
    db.add(check)
    db.commit()
    db.refresh(check)
    return check

@router.post("/dynamic-checks/validate-regex")
def validate_custom_regex(
    regex: str = Query(...),
    sample_output: str = Query(...)
):
    """
    Test a regex against a sample output string with whitespace normalization.
    """
    try:
        # Match production behavior: collapse spaces
        normalized = re.sub(r' +', ' ', sample_output)
        pattern = re.compile(regex, re.IGNORECASE | re.MULTILINE)
        match = pattern.search(normalized)
        return {
            "valid": True,
            "matches": bool(match),
            "match_text": match.group(0) if match else None
        }
    except re.error as e:
        return {"valid": False, "error": str(e)}

@router.put("/dynamic-checks/{id}")
def update_dynamic_check(
    id: int,
    body: Dict[str, Any],
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    """
    Update an existing dynamic check.
    """
    check = db.query(DynamicCheck).filter(DynamicCheck.id == id).first()
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    
    for key, value in body.items():
        if hasattr(check, key):
            setattr(check, key, value)
    
    db.commit()
    db.refresh(check)
    return check

@router.delete("/dynamic-checks/{id}")
def delete_dynamic_check(
    id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(deps.get_current_admin_user)
):
    """
    Delete a dynamic check.
    """
    db.query(DynamicCheck).filter(DynamicCheck.id == id).delete()
    db.commit()
    return {"status": "deleted"}
