"""
VPN scanning engine orchestrator.
Updates progress, logs forensic events, stores results.
"""

import socket
import traceback
import re
from typing import List, Optional
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.models.scan import Scan
from app.models.scan_result import ScanRawResult, ScanResult
from app.models.admin import DynamicCheck
from app.utils.logger import log_event
from .checks import CHECK_CLASSES, BaseVPNCheck, CheckContext, CheckResult
from .commands import CommandCache


def run_vpn_engine(db: Session, scan_id: int, target: str, port: int) -> None:
    """
    Main entry point for the VPN scanning engine.
    - Executes predefined checks, parses results, stores raw + summary data.
    - Updates scan progress and emits UI log events.
    """
    try:
        # 1. Initial progress and event
        _update_progress(db, scan_id, 5.0)
        log_event(db, scan_id, "INIT", "VPN engine initialising.")

        # Resolve target to IP
        try:
            target_ip = _resolve_target(target)
            log_event(db, scan_id, "INFO", f"Resolved target {target} to IP: {target_ip}")
        except Exception as e:
            log_event(db, scan_id, "ERROR", f"Target resolution failed: {e}")
            target_ip = target

        # 2. Retrieve dynamic checks for this engine (from admin panel)
        dynamic_checks = (
            db.query(DynamicCheck)
            .filter(DynamicCheck.engine == 'vpn', DynamicCheck.is_active == True)
            .all()
        )

        # Predefined checks from CHECK_CLASSES
        predefined_check_ids = list(CHECK_CLASSES.keys())
        total_checks = len(predefined_check_ids) + len(dynamic_checks)

        if total_checks == 0:
            log_event(db, scan_id, "INFO", "No VPN checks defined.")
            _update_progress(db, scan_id, 100.0)
            _set_status(db, scan_id, "COMPLETED")
            return

        log_event(db, scan_id, "START", f"Starting {total_checks} VPN check(s) on {target_ip}.")

        # 3. Instantiate command cache (shared across checks)
        cache = CommandCache()
        results: List[CheckResult] = []
        completed = 0

        # 4. Execute predefined checks
        for cid in predefined_check_ids:
            check_class = CHECK_CLASSES.get(cid)
            if not check_class:
                continue

            # Create context for this check
            ctx = CheckContext(
                db=db,
                scan_id=scan_id,
                target=target_ip,
                port=port or 0,
                command_cache=cache,
            )

            # Instantiate and run the check
            check_inst: BaseVPNCheck = check_class()
            log_event(db, scan_id, "CHECK", f"Running check {cid} ({check_inst.check_name})...")
            
            try:
                result: CheckResult = check_inst.run(ctx)
                results.append(result)
                
                # Store raw result (forensic record)
                _write_raw_result(db, scan_id, result)
                
                log_event(db, scan_id, "RESULT", f"{cid} → {result.status}: {result.logic}")
            except Exception as e:
                db.rollback()
                log_event(db, scan_id, "ERROR", f"Error in check {cid}: {e}")

            # Update progress
            completed += 1
            progress = 5.0 + (completed / total_checks) * 90.0
            _update_progress(db, scan_id, progress)

        # 5. Execute dynamic checks (if any)
        for dc in dynamic_checks:
            try:
                log_event(db, scan_id, "CHECK", f"Running dynamic check: {dc.check_name}")
                
                # Format command - support {ip}, {domain}, {port}
                cmd = dc.command_template.format(
                    ip=target_ip,
                    domain=target, 
                    port=port or 0
                )
                
                # Run command
                meta = cache.get_or_run(cmd, timeout=dc.timeout)
                output = meta['output']
                
                # Match success criteria (Regex)
                normalized_output = re.sub(r' +', ' ', output)
                is_pass = bool(re.search(dc.success_criteria, normalized_output, re.IGNORECASE | re.MULTILINE))
                status = "PASS" if is_pass else "FAIL"
                
                cr = CheckResult(
                    check_id              = dc.check_id_string,
                    check_name            = dc.check_name,
                    status                = status,
                    logic                 = f"Dynamic check. Success criteria '{dc.success_criteria}' matched: {is_pass}",
                    details               = f"=== EXECUTION INFO ===\nCommand: {cmd}\nStart (UTC): {meta['start_time']}\nEnd (UTC): {meta['end_time']}\nDuration: {meta['duration']:.2f} sec\n======================\n\n{output}",
                    command_executed      = cmd,
                    cvss_score            = dc.cvss_score,
                    cvss_vector           = dc.severity,
                    remediation           = dc.remediation_text or "",
                    execution_start       = meta['start_time'],
                    execution_end         = meta['end_time'],
                    execution_duration    = meta['duration']
                )
                results.append(cr)
                _write_raw_result(db, scan_id, cr)
                log_event(db, scan_id, "RESULT", f"Dynamic check {dc.check_name}: {status}")
            except Exception as e:
                db.rollback()
                log_event(db, scan_id, "ERROR", f"Dynamic check {dc.check_name} failed: {e}")
            finally:
                completed += 1
                progress = 5.0 + (completed / total_checks) * 90.0
                _update_progress(db, scan_id, progress)

        # 6. Finalise summary
        _write_summary(db, scan_id, results)
        _update_progress(db, scan_id, 100.0)
        _set_status(db, scan_id, "COMPLETED")
        db.commit()
        log_event(db, scan_id, "DONE", "VPN engine completed all checks.")

    except Exception as exc:
        db.rollback()
        error_msg = f"VPN engine fatal error: {exc}\n{traceback.format_exc()}"
        log_event(db, scan_id, "CRITICAL", f"VPN engine failed: {exc}")
        _set_status(db, scan_id, "FAILED", error_message=error_msg[:2000])
        db.commit()


def _resolve_target(target: str) -> str:
    """Resolve domain to IP; if already IP, return as is."""
    # Simple IP pattern check
    if all(c.isdigit() or c == '.' for c in target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target '{target}' to an IP address.")


def _update_progress(db: Session, scan_id: int, value: float) -> None:
    """Helper to set the progress_percent column on the scans table."""
    db.query(Scan).filter(Scan.id == scan_id).update({"progress_percent": value, "updated_at": datetime.now(timezone.utc)})
    db.flush()


def _set_status(db: Session, scan_id: int, status: str, error_message: str = None) -> None:
    """Helper to set the status and error message on the scans table."""
    update_data = {"status": status, "updated_at": datetime.now(timezone.utc)}
    if error_message:
        update_data["error_message"] = error_message
    db.query(Scan).filter(Scan.id == scan_id).update(update_data)
    db.flush()


def _write_raw_result(db: Session, scan_id: int, result: CheckResult) -> None:
    """Write detailed result to scan_raw_results table."""
    rem_text = ""
    rem_ref = ""
    rem_ex = ""
    if isinstance(result.remediation, dict):
        rem_text = result.remediation.get("fix", "")
        rem_ref = result.remediation.get("reference", "")
        rem_ex = result.remediation.get("example", "")
    elif isinstance(result.remediation, str):
        rem_text = result.remediation

    raw = ScanRawResult(
        scan_id=scan_id,
        check_id=result.check_id,
        check_name=result.check_name,
        tool_name="vpn_engine", # Simplified
        command_executed=result.command_executed or "See details", 
        raw_output=result.details,
        decision_logic=result.logic,
        result=result.status,
        cvss_score=result.cvss_score,
        severity="High" if result.status == "FAIL" else "INFO", # Simplified
        remediation_text=rem_text,
        remediation_example=rem_ex,
        remediation_reference=rem_ref,
        execution_start=result.execution_start,
        execution_end=result.execution_end,
        execution_duration=result.execution_duration,
        created_at=datetime.utcnow()
    )
    db.add(raw)
    db.flush()


def _write_summary(db: Session, scan_id: int, results: List[CheckResult]) -> None:
    """Write high-level summary to scan_results and update scan compliance percent."""
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    failed = total - passed
    pct = round(passed / total * 100) if total else 0
    status = "Y" if passed == total else "N"

    summary = ScanResult(
        scan_id=scan_id,
        status=status,
        remarks=f"VPN compliance: {passed}/{total} checks passed ({pct}%)",
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed
    )
    db.add(summary)
    
    db.query(Scan).filter(Scan.id == scan_id).update({"compliance_percent": float(pct)})
    db.flush()
