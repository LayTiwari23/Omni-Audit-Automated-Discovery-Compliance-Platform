"""
Reports API — All Scan Endpoints
File: backend/app/api/endpoints/reports.py
"""

from __future__ import annotations

import csv
import io
import os
import signal
import json
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, UploadFile, File, Form, Response, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import get_current_user_id
from app.api.deps import get_db, get_current_user, check_target_permission
from app.models.user import User
from app.models.admin import AuditLog
from app.utils.domain_validator import validate_domain
from app.utils.report_generator import generate_report
from app.utils.target_expander import expand_targets, is_valid_target

router = APIRouter()

# Registry of running background scans: {scan_id: celery_task_id}
_running: dict[int, str] = {}

# Max raw output characters
RAW_OUTPUT_MAX_CHARS = 100000

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class CreateScanRequest(BaseModel):
    domain:     str  # Keep as 'domain' for backward compatibility but treat as potentially multi-target
    scan_type:  str = "web"
    email_from: Optional[str] = None
    email_to:   Optional[str] = None

class ScanStatusResponse(BaseModel):
    status:           str
    progress_percent: float
    error_message:    Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clean_domain(raw: str) -> str:
    """Strip protocol and path from a user-supplied domain string."""
    d = raw.strip()
    for prefix in ("https://", "http://"):
        if d.lower().startswith(prefix):
            d = d[len(prefix):]
    return d.split("/")[0].strip()


def _to_yn(value: str) -> str:
    """Convert internal PASS/FAIL to display Y/N."""
    return "Y" if value == "PASS" else "N"


def _ownership_or_404(db: Session, scan_id: int, user_id: int) -> dict:
    """
    Return scan row as dict or raise 404/403.
    Admins can access any report.
    """
    row = db.execute(
        text("""
            SELECT id, user_id, domain, status,
                   progress_percent, error_message, created_at, scan_type, scan_metadata
            FROM   scans
            WHERE  id = :id
        """),
        {"id": scan_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Check if admin
    is_admin = db.execute(
        text("SELECT is_admin FROM users WHERE id = :uid"),
        {"uid": user_id}
    ).scalar()

    if not is_admin and row[1] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "id":               row[0],
        "user_id":          row[1],
        "domain":           row[2],
        "status":           row[3],
        "progress_percent": row[4] or 0.0,
        "error_message":    row[5],
        "created_at":       row[6],
        "scan_type":        row[7],
        "scan_metadata":    row[8] if row[8] else {},
    }


def _user_scan_number(db: Session, scan_id: int, user_id: int) -> int:
    """
    Return the sequential report number for this user.
    """
    row = db.execute(
        text("""
            SELECT COUNT(*)
            FROM   scans
            WHERE  user_id = :uid
              AND  id      <= :sid
        """),
        {"uid": user_id, "sid": scan_id},
    ).fetchone()
    return row[0] if row else 1


def _compliance_pct(db: Session, scan_id: int) -> Optional[float]:
    """Calculate compliance % from scan_raw_results."""
    row = db.execute(
        text("""
            SELECT COUNT(*)                                    AS total,
                   SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS passed
            FROM   scan_raw_results
            WHERE  scan_id = :sid
        """),
        {"sid": scan_id},
    ).fetchone()
    if not row or not row[0]:
        return None
    return round(row[1] / row[0] * 100, 2)


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/compare
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/compare")
def compare_reports(
    scan1: int = Query(..., description="First scan ID"),
    scan2: int = Query(..., description="Second scan ID"),
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    if scan1 == scan2:
        raise HTTPException(status_code=400, detail="Select two different scans")

    s1 = _ownership_or_404(db, scan1, user_id)
    s2 = _ownership_or_404(db, scan2, user_id)

    if s1["scan_type"] != s2["scan_type"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot compare {s1['scan_type']} scan with {s2['scan_type']} scan. Scan types must match."
        )
    
    if s1["domain"] != s2["domain"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot compare scan for {s1['domain']} with scan for {s2['domain']}. Targets must match."
        )

    for s in (s1, s2):
        if s["status"] != "COMPLETED":
            raise HTTPException(
                status_code=400,
                detail=f"Scan {s['id']} is not COMPLETED",
            )

    def _results(sid: int) -> dict[int, str]:
        rows = db.execute(
            text("SELECT check_id, result FROM scan_raw_results WHERE scan_id = :sid"),
            {"sid": sid},
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def _names(sid: int) -> dict[int, str]:
        rows = db.execute(
            text("SELECT check_id, check_name FROM scan_raw_results WHERE scan_id = :sid"),
            {"sid": sid},
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    r1    = _results(scan1)
    r2    = _results(scan2)
    names = _names(scan1)

    if not r1 or not r2:
        # Fallback if names empty
        if not names:
            names = _names(scan2)

    pct1 = _compliance_pct(db, scan1) or 0.0
    pct2 = _compliance_pct(db, scan2) or 0.0

    improved  = []
    worsened  = []
    unchanged = []

    for check_id in sorted(set(r1) | set(r2)):
        v1   = r1.get(check_id, "FAIL")
        v2   = r2.get(check_id, "FAIL")
        name = names.get(check_id, f"Check {check_id}")

        entry = {
            "check_id":   check_id,
            "check_name": name,
            "scan1":      _to_yn(v1),
            "scan2":      _to_yn(v2),
        }

        if v1 == "FAIL" and v2 == "PASS":
            improved.append(entry)
        elif v1 == "PASS" and v2 == "FAIL":
            worsened.append(entry)
        else:
            unchanged.append({**entry, "result": _to_yn(v1)})

    return {
        "scan1_id":         scan1,
        "scan1_domain":     s1["domain"],
        "scan1_type":       s1.get("scan_type", "web"),
        "scan1_percent":    pct1,
        "scan2_id":         scan2,
        "scan2_domain":     s2["domain"],
        "scan2_type":       s2.get("scan_type", "web"),
        "scan2_percent":    pct2,
        "difference":       round(pct2 - pct1, 2),
        "improved_checks":  improved,
        "worsened_checks":  worsened,
        "unchanged_checks": unchanged,
    }

@router.get("/compare/download")
def download_comparison_report(
    scan1: int = Query(..., description="First scan ID"),
    scan2: int = Query(..., description="Second scan ID"),
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    from app.utils.comparison_report_generator import generate_comparison_report
    
    # Permission checks (implicit in ownership_or_404)
    s1 = _ownership_or_404(db, scan1, user_id)
    s2 = _ownership_or_404(db, scan2, user_id)

    if s1["scan_type"] != s2["scan_type"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot compare {s1['scan_type']} scan with {s2['scan_type']} scan."
        )

    if s1["domain"] != s2["domain"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot compare scan for {s1['domain']} with scan for {s2['domain']}."
        )

    try:

        pdf_bytes = generate_comparison_report(scan1, scan2, db)
        filename = f"comparison_report_{scan1}_{scan2}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/{id}
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{report_id}")
def get_report(
    report_id: int,
    user_id:   int = Depends(get_current_user_id),
    db:        Session = Depends(get_db),
):
    """
    Get a single scan's metadata and its findings.
    """
    scan = _ownership_or_404(db, report_id, user_id)
    scan_no = _user_scan_number(db, report_id, user_id)
    compliance = _compliance_pct(db, report_id)
    
    results_rows = db.execute(
        text("""
            SELECT check_id, check_name, result, severity, cvss_score, 
                   decision_logic, remediation_text, command_executed, raw_output
            FROM   scan_raw_results
            WHERE  scan_id = :sid
            ORDER BY check_id
        """),
        {"sid": report_id},
    ).fetchall()
    
    results = []
    for r in results_rows:
        results.append({
            "check_id":           r[0],
            "check_name":         r[1],
            "result":             r[2],
            "severity":           r[3],
            "cvss_score":         r[4],
            "decision_logic":     r[5],
            "remediation_text":   r[6],
            "command_executed":   r[7],
            "raw_output":         r[8],
        })

    # Fetch edit history
    history_rows = db.execute(
        text("""
            SELECT h.id, h.check_id, h.field_name, h.old_value, h.new_value, h.created_at, u.username
            FROM   scan_edit_history h
            LEFT JOIN users u ON h.edited_by = u.id
            WHERE  h.scan_id = :sid
            ORDER BY h.created_at DESC
        """),
        {"sid": report_id},
    ).fetchall()
    
    history = []
    for h in history_rows:
        history.append({
            "id": h[0],
            "check_id": h[1],
            "field_name": h[2],
            "old_value": h[3],
            "new_value": h[4],
            "created_at": h[5],
            "username": h[6]
        })

    return {
        **scan,
        "user_scan_no":      scan_no,
        "compliance_percent": compliance,
        "results":            results,
        "edit_history":       history
    }

# ─────────────────────────────────────────────────────────────────────────────
# PUT /reports/{id}/results/{check_id}
# ─────────────────────────────────────────────────────────────────────────────

from app.schemas.scan_result import ScanRawResultUpdate
from app.models.scan_result import ScanRawResult, ScanEditHistory
from app.models.scan import Scan

@router.put("/{report_id}/results/{check_id}")
def update_report_result(
    report_id: int,
    check_id: str,
    data: ScanRawResultUpdate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Manually override a specific check result in a report.
    """
    # 1. Ownership check
    scan_obj = db.query(Scan).filter(Scan.id == report_id).first()
    if not scan_obj or (not _ownership_or_404(db, report_id, user_id)):
         raise HTTPException(404, "Report not found")

    # 2. Fetch the raw result
    raw_res = db.query(ScanRawResult).filter(
        ScanRawResult.scan_id == report_id,
        ScanRawResult.check_id == check_id
    ).first()
    
    if not raw_res:
        raise HTTPException(404, "Check result not found")

    # 3. Apply updates and record history
    fields_to_update = data.model_dump(exclude_unset=True)
    for field, new_val in fields_to_update.items():
        old_val = getattr(raw_res, field)
        if str(old_val) != str(new_val):
            # Record in history
            history = ScanEditHistory(
                scan_id=report_id,
                check_id=check_id,
                field_name=field,
                old_value=str(old_val) if old_val is not None else None,
                new_value=str(new_val) if new_val is not None else None,
                edited_by=user_id
            )
            db.add(history)
            # Update field
            setattr(raw_res, field, new_val)

    db.commit()

    # 4. Recalculate overall compliance for the scan
    new_compliance = _compliance_pct(db, report_id)
    db.execute(
        text("UPDATE scans SET compliance_percent = :pct WHERE id = :sid"),
        {"pct": new_compliance, "sid": report_id}
    )
    db.commit()

    return {"status": "success", "compliance_percent": new_compliance}


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/{id}/details
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{report_id}/details")
def get_details(
    report_id:   int,
    include_raw: bool = Query(False, description="Include full raw tool output"),
    user_id:     int  = Depends(get_current_user_id),
    db:          Session = Depends(get_db),
):
    """
    Full report detail for the original UI.
    """
    scan         = _ownership_or_404(db, report_id, user_id)
    user_scan_no = _user_scan_number(db, report_id, user_id)

    # Check rows
    col_select = (
        "check_id, check_name, tool_name, command_executed, "
        "raw_output, decision_logic, result, created_at, "
        "cvss_score, severity, cve_id, "
        "remediation_text, remediation_example, remediation_reference"
        if include_raw else
        "check_id, check_name, tool_name, command_executed, "
        "decision_logic, result, created_at, "
        "cvss_score, severity, cve_id, "
        "remediation_text, remediation_example, remediation_reference"
    )

    rows = db.execute(
        text(f"SELECT {col_select} FROM scan_raw_results WHERE scan_id = :sid ORDER BY check_id"),
        {"sid": report_id},
    ).fetchall()

    checks = []
    for row in rows:
        if include_raw:
            cid, cname, tool, cmd, raw, logic, res, ts, cvss, sev, cve, rem_t, rem_ex, rem_ref = row
            checks.append({
                "check_id":       cid,
                "check_name":     cname,
                "tool_name":      tool,
                "command":        cmd,
                "raw_output":     raw,
                "decision_logic": logic,
                "result":         _to_yn(res),
                "created_at":     ts,
                "cvss_score":     cvss,
                "severity":       sev,
                "cve_id":         cve,
                "remediation_text": rem_t,
                "remediation_example": rem_ex,
                "remediation_reference": rem_ref,
            })
        else:
            cid, cname, tool, cmd, logic, res, ts, cvss, sev, cve, rem_t, rem_ex, rem_ref = row
            checks.append({
                "check_id":       cid,
                "check_name":     cname,
                "tool_name":      tool,
                "command":        cmd,
                "decision_logic": logic,
                "result":         _to_yn(res),
                "created_at":     ts,
                "cvss_score":     cvss,
                "severity":       sev,
                "cve_id":         cve,
                "remediation_text": rem_t,
                "remediation_example": rem_ex,
                "remediation_reference": rem_ref,
            })

    total   = len(checks)
    passed  = sum(1 for c in checks if c["result"] == "Y")
    failed  = total - passed
    pct     = round(passed / total * 100, 2) if total else 0.0

    from app.utils.ip_utils import get_public_ip

    # Fetch edit history for this scan
    history_rows = db.execute(
        text("""
            SELECT h.id, h.check_id, h.field_name, h.old_value, h.new_value, h.created_at, u.username
            FROM   scan_edit_history h
            LEFT JOIN users u ON h.edited_by = u.id
            WHERE  h.scan_id = :sid
            ORDER BY h.created_at DESC
        """),
        {"sid": report_id},
    ).fetchall()
    
    history = []
    for h in history_rows:
        history.append({
            "id": h[0],
            "check_id": h[1],
            "field_name": h[2],
            "old_value": h[3],
            "new_value": h[4],
            "created_at": h[5],
            "username": h[6]
        })

    return {
        "id":               report_id,
        "user_scan_no":     user_scan_no,
        "domain":           scan["domain"],
        "scan_type":        scan["scan_type"],
        "status":           scan["status"],
        "progress_percent": scan["progress_percent"],
        "error_message":    scan["error_message"],
        "created_at":       scan["created_at"],
        "scan_metadata":    scan["scan_metadata"],
        "scanner_ip":       get_public_ip(),
        "compliance_stats": {
            "total_checks":       total,
            "passed":             passed,
            "failed":             failed,
            "compliance_score":   f"{passed} / {total}",
            "compliance_percent": pct,
        },
        "results": checks,
        "edit_history": history
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports
# ─────────────────────────────────────────────────────────────────────────────

@router.get("")
def list_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return all reports for the authenticated user (or impersonated user)."""
    rows = db.execute(
        text("""
            SELECT id, domain, scan_type, status, progress_percent, error_message, created_at, user_id, scan_metadata
            FROM   scans
            WHERE  user_id = :uid
            ORDER  BY created_at DESC
        """),
        {"uid": current_user.id},
    ).fetchall()

    result = []
    # Count scans for sequential numbering
    total_count = len(rows)

    for idx, row in enumerate(rows):
        scan_id          = row[0]
        domain           = row[1]
        scan_type        = row[2]
        status           = row[3]
        progress_percent = row[4]
        error_message    = row[5]
        created_at       = row[6]
        meta_raw         = row[8]
        
        user_scan_no = total_count - idx

        compliance_pct = None
        if status == "COMPLETED":
            compliance_pct = _compliance_pct(db, scan_id)

        result.append({
            "id":                scan_id,
            "user_scan_no":      user_scan_no,
            "domain":            domain,
            "scan_type":         scan_type,
            "status":            status,
            "progress_percent":  progress_percent or 0.0,
            "error_message":     error_message,
            "created_at":        created_at,
            "compliance_percent": compliance_pct,
            "scan_metadata":     meta_raw if meta_raw else {},
        })

    return result


# ─────────────────────────────────────────────────────────────────────────────
# POST /reports
# ─────────────────────────────────────────────────────────────────────────────

@router.post("")
def create_report(
    body:             CreateScanRequest,
    current_user:     User = Depends(get_current_user),
    db:               Session = Depends(get_db),
):
    """
    Initiate one or more security scans.
    Supports comma-separated targets, CIDR, and ranges.
    """
    targets = expand_targets(body.domain)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")

    created_scans = []
    from workers.scan_worker import run_scan_task

    for target in targets:
        # Basic validation per target
        clean_t = _clean_domain(target)
        
        # PERMISSION CHECK
        check_target_permission(db, current_user, clean_t)
        
        # If it's an IP, validate_domain might fail if it tries DNS lookup on an IP that doesn't resolve reverse DNS
        # but socket.gethostbyname usually handles IPs fine.
        is_valid, error_msg = validate_domain(clean_t)
        if not is_valid:
            # For bulk, we might want to skip invalid instead of failing entire request
            if len(targets) > 1:
                continue
            raise HTTPException(status_code=400, detail=f"Invalid target '{clean_t}': {error_msg}")

        row = db.execute(
            text("""
                INSERT INTO scans (user_id, domain, scan_type, status, progress_percent, created_at, updated_at)
                VALUES (:uid, :domain, :scan_type , 'RUNNING', 0, :now, :now)
                RETURNING id
            """),
            {"uid": current_user.id, "domain": clean_t, "scan_type": body.scan_type, "now": datetime.now(timezone.utc)},
        ).fetchone()
        scan_id = row[0]
        db.commit()

        user_scan_no = _user_scan_number(db, scan_id, current_user.id)
        
        task = run_scan_task.delay(
            scan_id, 
            clean_t, 
            body.scan_type,
            email_from=body.email_from,
            email_to=body.email_to
        )
        _running[scan_id] = task.id
        
        created_scans.append({
            "id":           scan_id,
            "user_scan_no": user_scan_no,
            "domain":       clean_t,
            "status":       "RUNNING",
        })

    if not created_scans:
        raise HTTPException(status_code=400, detail="All provided targets were invalid")

    # If it's just one, return it directly for backward compatibility with older frontend
    return created_scans[0] if len(created_scans) == 1 else created_scans


@router.post("/upload")
async def upload_targets(
    scan_type:  str = Form("web"),
    email_from: Optional[str] = Form(None),
    email_to:   Optional[str] = Form(None),
    file:       UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db:         Session = Depends(get_db),
):
    """
    Initiate scans from an uploaded file containing targets.
    """
    if not file.filename.lower().endswith(('.txt', '.csv')):
        raise HTTPException(status_code=400, detail="Only .txt and .csv files are supported")

    content = await file.read()
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    targets = expand_targets(text_content)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found in file")

    created_scans = []
    from workers.scan_worker import run_scan_task

    for target in targets:
        clean_t = _clean_domain(target)
        
        # PERMISSION CHECK
        try:
            check_target_permission(db, current_user, clean_t)
        except HTTPException:
            continue # Skip targets not allowed during bulk upload
            
        is_valid, _ = validate_domain(clean_t)
        if not is_valid:
            continue

        row = db.execute(
            text("""
                INSERT INTO scans (user_id, domain, scan_type, status, progress_percent, created_at, updated_at)
                VALUES (:uid, :domain, :scan_type , 'RUNNING', 0, :now, :now)
                RETURNING id
            """),
            {"uid": current_user.id, "domain": clean_t, "scan_type": scan_type, "now": datetime.now(timezone.utc)},
        ).fetchone()
        scan_id = row[0]
        db.commit()

        task = run_scan_task.delay(
            scan_id, 
            clean_t, 
            scan_type,
            email_from=email_from,
            email_to=email_to
        )
        _running[scan_id] = task.id
        created_scans.append({"id": scan_id, "domain": clean_t})

    return {
        "message": f"Successfully initiated {len(created_scans)} scans",
        "scans": created_scans
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/{id}/status
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{report_id}/status", response_model=ScanStatusResponse)
def get_status(
    report_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    scan = _ownership_or_404(db, report_id, user_id)
    return ScanStatusResponse(
        status=scan["status"],
        progress_percent=scan["progress_percent"],
        error_message=scan["error_message"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /reports/{id}/stop
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/{report_id}/stop")
def stop_report(
    report_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    scan = _ownership_or_404(db, report_id, user_id)
    if scan["status"] != "RUNNING":
        raise HTTPException(status_code=400, detail="Scan not running")

    db.execute(text("UPDATE scans SET status = 'CANCELLED' WHERE id = :id"), {"id": report_id})
    db.commit()

    task_id = _running.get(report_id)
    if task_id:
        from celery_app import celery
        celery.control.revoke(task_id, terminate=True)
        _running.pop(report_id, None)

    return {"message": "Scan cancelled", "status": "CANCELLED"}


# ─────────────────────────────────────────────────────────────────────────────
# POST /reports/{id}/resume
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/{report_id}/resume")
def resume_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Resume (restart) a scan that was cancelled or failed.
    """
    scan = _ownership_or_404(db, report_id, current_user.id)
    
    # PERMISSION CHECK
    check_target_permission(db, current_user, scan["domain"])
    
    if scan["status"] == "RUNNING":
        raise HTTPException(status_code=400, detail="Scan is already running")

    # Reset scan status
    db.execute(
        text("UPDATE scans SET status = 'RUNNING', progress_percent = 0, error_message = NULL, updated_at = :now WHERE id = :id"),
        {"id": report_id, "now": datetime.now(timezone.utc)}
    )
    # Clear old results
    db.execute(text("DELETE FROM scan_raw_results WHERE scan_id = :id"), {"id": report_id})
    db.execute(text("DELETE FROM scan_results WHERE scan_id = :id"), {"id": report_id})
    db.commit()

    from workers.scan_worker import run_scan_task
    task = run_scan_task.delay(
        report_id, 
        scan["domain"], 
        scan["scan_type"]
    )
    _running[report_id] = task.id

    return {"message": "Scan resumed", "status": "RUNNING"}


# ─────────────────────────────────────────────────────────────────────────────
# PATCH /reports/{id}/results/{check_id}
# ─────────────────────────────────────────────────────────────────────────────

class UpdateResultRequest(BaseModel):
    result:           Optional[str] = None
    severity:         Optional[str] = None
    decision_logic:   Optional[str] = None

@router.patch("/{report_id}/results/{check_id}")
def update_report_result(
    report_id: int,
    check_id:  str,
    body:      UpdateResultRequest,
    request:   Request,
    current_user: User = Depends(get_current_user),
    db:        Session = Depends(get_db),
):
    """
    Update a specific scan result check. Admin only.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Find the specific raw result row with current values
    row = db.execute(
        text("""
            SELECT id, result, severity, decision_logic, check_name 
            FROM scan_raw_results 
            WHERE scan_id = :sid AND check_id = :cid
        """),
        {"sid": report_id, "cid": check_id}
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Check result not found")

    update_parts = []
    params = {"sid": report_id, "cid": check_id}
    changes = {}

    if body.result is not None:
        new_res = "PASS" if body.result.upper() in ("Y", "PASS", "YES") else "FAIL"
        if new_res != row.result:
            changes["Status"] = {"old": row.result, "new": new_res}
            update_parts.append("result = :res")
            params["res"] = new_res
    
    if body.severity is not None:
        new_sev = body.severity.upper()
        if new_sev != row.severity:
            changes["Severity"] = {"old": row.severity, "new": new_sev}
            update_parts.append("severity = :sev")
            params["sev"] = new_sev
        
    if body.decision_logic is not None:
        if body.decision_logic != row.decision_logic:
            changes["Remarks"] = {"old": row.decision_logic, "new": body.decision_logic}
            update_parts.append("decision_logic = :logic")
            params["logic"] = body.decision_logic

    if not update_parts:
        return {"message": "No changes provided"}

    update_query = f"""
        UPDATE scan_raw_results 
        SET {", ".join(update_parts)}
        WHERE scan_id = :sid AND check_id = :cid
    """
    
    db.execute(text(update_query), params)
    
    # Log the change
    audit_details = {
        "check_id": check_id,
        "check_name": row.check_name,
        "changes": changes
    }
    audit = AuditLog(
        user_id=current_user.id,
        action="EDIT_SCAN_RESULT",
        target_type="SCAN_RESULT",
        target_id=str(report_id),
        details=json.dumps(audit_details),
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()

    # Recalculate summary and update scans table
    all_results = db.execute(
        text("SELECT result FROM scan_raw_results WHERE scan_id = :sid"),
        {"sid": report_id}
    ).fetchall()

    if all_results:
        total = len(all_results)
        passed = sum(1 for r in all_results if r[0] == "PASS")
        inconclusive = sum(1 for r in all_results if r[0] == "INCONCLUSIVE")
        failed = total - passed - inconclusive
        pct = round(passed / total * 100) if total else 0
        status = "Y" if passed == total else "N"

        # Update scan_results (summary table)
        # Note: We use the engine type from the scan to make the remarks consistent
        scan_type_row = db.execute(
            text("SELECT scan_type FROM scans WHERE id = :sid"),
            {"sid": report_id}
        ).fetchone()
        stype = scan_type_row[0] if scan_type_row else "Scan"
        remarks = f"{stype.capitalize()} compliance: {passed}/{total} checks passed ({pct}%) | Failed: {failed} | Inconclusive: {inconclusive}"

        db.execute(
            text("""
                UPDATE scan_results 
                SET status = :st, passed_checks = :pas, failed_checks = :fai, total_checks = :tot, remarks = :rem
                WHERE scan_id = :sid
            """),
            {"st": status, "pas": passed, "fai": failed, "tot": total, "rem": remarks, "sid": report_id}
        )

        # Update scans table
        db.execute(
            text("UPDATE scans SET compliance_percent = :pct, updated_at = :ts WHERE id = :sid"),
            {"pct": pct, "ts": datetime.now(), "sid": report_id}
        )
        db.commit()

    return {"message": "Result updated successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/{id}/edits
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{report_id}/edits")
def get_report_edits(
    report_id: int,
    user_id:   int = Depends(get_current_user_id),
    db:        Session = Depends(get_db),
):
    """
    Fetch manual override history for a report.
    """
    # Verify ownership or admin
    _ownership_or_404(db, report_id, user_id)

    logs = db.query(AuditLog, User.email)\
        .join(User, AuditLog.user_id == User.id)\
        .filter(AuditLog.target_type == "SCAN_RESULT")\
        .filter(AuditLog.target_id == str(report_id))\
        .order_by(AuditLog.created_at.desc())\
        .all()

    results = []
    for log, email in logs:
        try:
            details = json.loads(log.details)
        except:
            details = log.details

        results.append({
            "id": log.id,
            "admin_email": email,
            "action": log.action,
            "details": details,
            "created_at": log.created_at
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /reports/{id}
# ─────────────────────────────────────────────────────────────────────────────

@router.delete("/{report_id}")
def delete_report(
    report_id: int,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    _ownership_or_404(db, report_id, user_id)
    db.execute(text("DELETE FROM scan_raw_results WHERE scan_id = :id"), {"id": report_id})
    db.execute(text("DELETE FROM scan_results      WHERE scan_id = :id"), {"id": report_id})
    db.execute(text("DELETE FROM scans             WHERE id      = :id"), {"id": report_id})
    db.commit()
    return {"message": "Report deleted successfully"}


# ─────────────────────────────────────────────────────────────────────────────
# GET /reports/{id}/download
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    user_id:   int = Depends(get_current_user_id),
    db:        Session = Depends(get_db),
):
    scan = _ownership_or_404(db, report_id, user_id)
    if scan["status"] != "COMPLETED":
        raise HTTPException(status_code=400, detail="Scan not completed")

    try:
        pdf_bytes = generate_report(report_id, db=db)
        user_scan_no = _user_scan_number(db, report_id, user_id)
        filename = f"Report_{user_scan_no}_{scan['domain'].replace('/', '_')}.pdf"

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
