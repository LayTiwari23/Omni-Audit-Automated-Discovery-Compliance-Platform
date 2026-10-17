"""
engine.py — Network (UTM/Switch/Router) compliance engine orchestrator.
"""

from __future__ import annotations

import socket
import threading
import traceback
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import text

from app.utils.logger import log_event
from app.models.admin import DynamicCheck
from .checks import ALL_CHECKS, TOTAL_CHECKS, CheckResult, NetworkCheckContext
from .commands import CommandCache, check_tool_exists


PROGRESS_START = 5.0
PROGRESS_END = 95.0

REQUIRED_TOOLS = ["nmap"]


def _now() -> datetime:
    return datetime.now()


def _update_progress(db, scan_id: int, percent: float) -> None:
    db.execute(
        text("UPDATE scans SET progress_percent = :p, updated_at = :ts WHERE id = :sid"),
        {"p": round(min(max(percent, 0.0), 100.0), 2), "ts": _now(), "sid": scan_id},
    )
    db.commit()


def _set_status(db, scan_id: int, status: str, error_message: Optional[str] = None) -> None:
    db.execute(
        text("UPDATE scans SET status = :s, updated_at = :ts, error_message = :em WHERE id = :sid"),
        {"s": status, "ts": _now(), "em": error_message, "sid": scan_id},
    )
    db.commit()


def _write_raw_result(db, scan_id: int, cr: CheckResult) -> None:
    db.execute(
        text("""
            INSERT INTO scan_raw_results
                (scan_id, check_id, check_name, tool_name, command_executed,
                 raw_output, decision_logic, result, cvss_score, severity, cve_id,
                 remediation_text, remediation_example, remediation_reference,
                 execution_start, execution_end, execution_duration)
            VALUES (:sid, :cid, :cn, :tn, :cmd, :ro, :dl, :res, :cvss, :sev, :cve,
                    :rem_t, :rem_ex, :rem_ref, :start, :end, :dur)
        """),
        {
            "sid": scan_id,
            "cid": cr.check_id,
            "cn": cr.check_name,
            "tn": cr.tool_name,
            "cmd": cr.command_executed,
            "ro": cr.raw_output,
            "dl": cr.decision_logic,
            "res": cr.result,
            "cvss": cr.cvss_score,
            "sev": cr.severity,
            "cve": cr.cve_id,
            "rem_t": cr.remediation_text,
            "rem_ex": cr.remediation_example,
            "rem_ref": cr.remediation_reference,
            "start": cr.execution_start,
            "end": cr.execution_end,
            "dur": cr.execution_duration,
        },
    )
    db.commit()


def _write_summary(db, scan_id: int, results: List[CheckResult]) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.result == "PASS")
    failed = total - passed
    pct = round(passed / total * 100) if total else 0
    status = "Y" if passed == total else "N"

    db.execute(
        text("""
            INSERT INTO scan_results
                (scan_id, compliance_id, status, remarks,
                 total_checks, passed_checks, failed_checks)
            VALUES (:sid, NULL, :st, :rem, :tot, :pas, :fai)
        """),
        {
            "sid": scan_id,
            "st": status,
            "rem": f"Network compliance: {passed}/{total} checks passed ({pct}%)",
            "tot": total,
            "pas": passed,
            "fai": failed,
        },
    )
    
    db.execute(
        text("UPDATE scans SET compliance_percent = :pct, updated_at = :ts WHERE id = :sid"),
        {"pct": pct, "ts": _now(), "sid": scan_id}
    )
    db.commit()


def _check_tools() -> None:
    missing = []
    for tool in REQUIRED_TOOLS:
        if not check_tool_exists(tool):
            missing.append(tool)
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")


def _resolve_target(target: str) -> str:
    """Resolve domain to IP; if already IP, return as is."""
    # Simple IP pattern check
    if all(c.isdigit() or c == '.' for c in target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target '{target}' to an IP address.")


def run_network_engine(
    db,
    scan_id: int,
    target: str,
    port: int = None,
    max_workers: int = 6,
) -> None:
    """
    Run network (UTM/Switch/Router) checks and write results to DB.
    """
    try:
        log_event(db, scan_id, "INIT", "Initializing Network compliance engine...")
        _update_progress(db, scan_id, 0.0)

        log_event(db, scan_id, "CHECK", "Running tool pre-flight checks...")
        _check_tools()

        log_event(db, scan_id, "START", f"Starting Network scan for target: {target}")
        target_ip = _resolve_target(target)
        log_event(db, scan_id, "INFO", f"Resolved target to IP: {target_ip}")

        # Fetch dynamic checks from DB
        dynamic_checks = db.query(DynamicCheck).filter(
            DynamicCheck.engine == 'network', 
            DynamicCheck.is_active == True
        ).all()

        total_dc = len(dynamic_checks)
        total_work = TOTAL_CHECKS + total_dc
        progress_per_check = (PROGRESS_END - PROGRESS_START) / total_work if total_work else 0
        _update_progress(db, scan_id, PROGRESS_START)

        def log_cb(stage, msg):
            log_event(None, scan_id, stage, msg)

        cache = CommandCache(log_callback=log_cb)
        results: List[CheckResult] = []
        completed = 0
        lock = threading.Lock()

        def run_one(check_cls) -> CheckResult:
            ctx = NetworkCheckContext(target_ip=target_ip, cache=cache, port=port)
            try:
                cr = check_cls(ctx).run()
                log_event(None, scan_id, "RESULT", f"{cr.check_name}: {cr.result}")
            except Exception as exc:
                cr = CheckResult(
                    check_id=getattr(check_cls, "check_id", "NET-??"),
                    check_name=getattr(check_cls, "check_name", "Unknown"),
                    tool_name="error",
                    command_executed="N/A",
                    raw_output=traceback.format_exc(),
                    decision_logic=f"Check failed with exception: {exc}",
                    result="FAIL",
                )
                log_event(None, scan_id, "ERROR", f"Check {getattr(check_cls, 'check_name', 'Unknown')} failed: {exc}")
            return cr

        log_event(db, scan_id, "INFO", f"Submitting {len(ALL_CHECKS)} Network checks to thread pool...")
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_check = {pool.submit(run_one, cls): cls for cls in ALL_CHECKS}
            for future in as_completed(future_to_check):
                cr = future.result()
                with lock:
                    results.append(cr)
                    completed += 1
                    progress = PROGRESS_START + completed * progress_per_check
                    _update_progress(db, scan_id, progress)

        # Run dynamic checks
        for dc in dynamic_checks:
            try:
                log_event(None, scan_id, "CHECK", f"Running dynamic check: {dc.check_name}")
                
                # Format command - support {domain}, {dns_ip}, {port}
                cmd = dc.command_template.format(
                    domain=target, 
                    dns_ip=target_ip, 
                    port=port or 0 # port might be None for network engine
                )
                
                # Run command
                meta = cache.get_or_run(cmd.split(), timeout=dc.timeout)
                output = meta['output']
                
                # Match success criteria (Regex)
                normalized_output = re.sub(r' +', ' ', output)
                is_pass = bool(re.search(dc.success_criteria, normalized_output, re.IGNORECASE | re.MULTILINE))
                result = "PASS" if is_pass else "FAIL"
                
                cr = CheckResult(
                    check_id              = dc.check_id_string,
                    check_name            = dc.check_name,
                    tool_name             = dc.tool_name or "custom",
                    command_executed      = cmd,
                    raw_output            = f"=== EXECUTION INFO ===\nCommand: {cmd}\nOutput:\n\n{output}",
                    decision_logic        = f"Dynamic check. Success criteria '{dc.success_criteria}' matched: {is_pass}",
                    result                = result,
                    cvss_score            = dc.cvss_score,
                    severity              = dc.severity,
                    remediation_text      = dc.remediation_text or "",
                    execution_start       = meta.get('start_time'),
                    execution_end         = meta.get('end_time'),
                    execution_duration    = meta.get('duration', 0.0)
                )
                results.append(cr)
                log_event(None, scan_id, "RESULT", f"Dynamic check {dc.check_name}: {result}")
            except Exception as e:
                log_event(None, scan_id, "ERROR", f"Dynamic check {dc.check_name} failed: {e}")
            finally:
                completed += 1
                progress = PROGRESS_START + completed * progress_per_check
                _update_progress(db, scan_id, progress)

        # Write results to DB
        log_event(db, scan_id, "SUMMARY", "Finalizing Network scan results...")
        for cr in results:
            _write_raw_result(db, scan_id, cr)

        _write_summary(db, scan_id, results)
        _update_progress(db, scan_id, 100.0)
        _set_status(db, scan_id, "COMPLETED")
        log_event(db, scan_id, "DONE", "Network compliance scan completed.")

    except Exception as exc:
        error_msg = f"Network engine fatal error: {exc}\n{traceback.format_exc()}"
        print(error_msg)
        log_event(db, scan_id, "CRITICAL", f"Network engine failed: {exc}")
        try:
            _set_status(db, scan_id, "FAILED", error_message=error_msg[:2000])
        except Exception:
            pass
        raise
