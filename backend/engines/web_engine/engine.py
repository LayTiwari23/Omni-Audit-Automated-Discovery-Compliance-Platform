"""
engine.py - Web Engine orchestrator.
"""

import traceback
import re
from datetime import datetime, timezone
from sqlalchemy import text
from .commands import CommandCache
from app.utils.logger import log_event
from app.models.admin import DynamicCheck
from .checks import (
    check_01_port_lockdown, check_02_http_only, check_03_https_operational,
    check_04_server_version, check_05_software_version, check_06_etag,
    check_07_xss_protection, check_08_xframe_options, check_09_hsts,
    check_10_csp, check_11_cookie_flags, check_12_cookie_samesite,
    check_13_cache_control, check_14_http_methods, check_15_cms_admin_exposed,
    check_16_tls_versions, check_17_weak_ciphers, check_18_poodle,
    check_19_logjam, check_20_heartbleed, check_21_crime,
    check_22_ccs_injection, check_23_anon_ciphers, check_24_freak,
    check_25_drown, check_26_forward_secrecy, check_27_http10_blocked,
    check_28_dns_caa
)

class WebEngine:
    def __init__(self):
        self.checks = [
            check_01_port_lockdown, check_02_http_only, check_03_https_operational,
            check_04_server_version, check_05_software_version, check_06_etag,
            check_07_xss_protection, check_08_xframe_options, check_09_hsts,
            check_10_csp, check_11_cookie_flags, check_12_cookie_samesite,
            check_13_cache_control, check_14_http_methods, check_15_cms_admin_exposed,
            check_16_tls_versions, check_17_weak_ciphers, check_18_poodle,
            check_19_logjam, check_20_heartbleed, check_21_crime,
            check_22_ccs_injection, check_23_anon_ciphers, check_24_freak,
            check_25_drown, check_26_forward_secrecy, check_27_http10_blocked,
            check_28_dns_caa
        ]

    def run(self, db, scan_id, domain, port=None):
        # Create a log callback that routes back to log_event
        def log_cb(stage, msg):
            log_event(None, scan_id, stage, msg)

        cache = CommandCache(log_callback=log_cb)
        results = []
        target_display = f"{domain}:{port}" if port else domain
        try:
            log_event(db, scan_id, "INIT", f"Initializing WebEngine for {target_display}")
            self._update_progress(db, scan_id, 5.0)
            
            log_event(db, scan_id, "START", f"Starting web compliance checks on {target_display}...")
            self._update_progress(db, scan_id, 10.0)

            # Fetch dynamic checks from DB
            dynamic_checks = db.query(DynamicCheck).filter(
                DynamicCheck.engine == 'web', 
                DynamicCheck.is_active == True
            ).all()

            total_checks = len(self.checks) + len(dynamic_checks)
            log_event(db, scan_id, "INFO", f"Submitting {total_checks} web checks ({len(self.checks)} hardcoded, {len(dynamic_checks)} dynamic) to execution loop...")
            
            # 1. Run hardcoded checks
            for i, check_fn in enumerate(self.checks):
                check_name = check_fn.__name__.replace('check_', '').replace('_', ' ').title()
                try:
                    log_event(None, scan_id, "CHECK", f"Running hardcoded check {i+1}/{total_checks}: {check_name}")
                    res = check_fn(domain, cache, port=port)
                    results.append(res)
                    self._write_raw_result(db, scan_id, res)
                    
                    status_text = "PASS" if res["result"] == "PASS" else "FAIL"
                    log_event(None, scan_id, "RESULT", f"Check '{check_name}' finished with status: {status_text}")
                except Exception as e:
                    log_event(None, scan_id, "ERROR", f"Error in check '{check_name}': {str(e)}")
                
                progress = 10.0 + (i + 1) * (80.0 / total_checks)
                self._update_progress(db, scan_id, progress)

            # 2. Run dynamic checks
            for i, dc in enumerate(dynamic_checks):
                idx = len(self.checks) + i
                try:
                    log_event(None, scan_id, "CHECK", f"Running dynamic check {idx+1}/{total_checks}: {dc.check_name}")
                    
                    # Format command with standard placeholders
                    cmd = dc.command_template.format(
                        domain=domain, 
                        port=port or 443,
                        dns_ip=target_display # Fallback to IP if domain not available or use domain
                    )
                    
                    # Run command
                    meta = cache.get_or_run(cmd.split(), timeout=dc.timeout)
                    output = meta['output']
                    
                    # Match success criteria (Regex)
                    # Normalize output: collapse multiple spaces into one for robust matching
                    normalized_output = re.sub(r' +', ' ', output)
                    is_pass = bool(re.search(dc.success_criteria, normalized_output, re.IGNORECASE | re.MULTILINE))
                    result = "PASS" if is_pass else "FAIL"
                    
                    # Build result dict
                    res = {
                        "check_id": dc.check_id_string,
                        "check_name": dc.check_name,
                        "tool_name": dc.tool_name or "custom",
                        "command_executed": cmd,
                        "raw_output": f"=== EXECUTION INFO ===\nCommand: {cmd}\nOutput:\n\n{output}",
                        "decision_logic": f"Dynamic check. Success criteria '{dc.success_criteria}' matched: {is_pass}",
                        "result": result,
                        "cvss_score": dc.cvss_score,
                        "severity": dc.severity,
                        "cve_id": None,
                        "remediation_text": dc.remediation_text or "No remediation provided for this dynamic check.",
                        "remediation_example": "",
                        "remediation_reference": "",
                        "execution_start": meta.get('start_time'),
                        "execution_end": meta.get('end_time'),
                        "execution_duration": meta.get('duration', 0.0)
                    }
                    
                    results.append(res)
                    self._write_raw_result(db, scan_id, res)
                    log_event(None, scan_id, "RESULT", f"Dynamic check '{dc.check_name}' finished with status: {result}")
                except Exception as e:
                    log_event(None, scan_id, "ERROR", f"Error in dynamic check '{dc.check_name}': {str(e)}")
                
                progress = 10.0 + (idx + 1) * (80.0 / total_checks)
                self._update_progress(db, scan_id, progress)

            log_event(db, scan_id, "SUMMARY", "Calculating compliance summary...")
            self._write_summary(db, scan_id, results)
            self._update_progress(db, scan_id, 100.0)
            self._set_status(db, scan_id, "COMPLETED")
            log_event(db, scan_id, "DONE", "Web compliance scan completed successfully.")
        except Exception as e:
            err = f"WebEngine error: {e}\n{traceback.format_exc()}"
            log_event(db, scan_id, "CRITICAL", f"WebEngine encountered a critical error: {str(e)}")
            self._set_status(db, scan_id, "FAILED", err[:2000])
            raise

    def _update_progress(self, db, scan_id, percent):
        db.execute(text("UPDATE scans SET progress_percent = :p, updated_at = :ts WHERE id = :sid"),
                   {"p": round(percent, 2), "ts": datetime.now(), "sid": scan_id})
        db.commit()

    def _set_status(self, db, scan_id, status, error=None):
        db.execute(text("UPDATE scans SET status = :s, error_message = :e, updated_at = :ts WHERE id = :sid"),
                   {"s": status, "e": error, "ts": datetime.now(), "sid": scan_id})
        db.commit()

    def _write_raw_result(self, db, scan_id, r):
        db.execute(text(
            "INSERT INTO scan_raw_results (scan_id, check_id, check_name, tool_name, command_executed, "
            "raw_output, decision_logic, result, cvss_score, severity, cve_id, "
            "remediation_text, remediation_example, remediation_reference, "
            "execution_start, execution_end, execution_duration) "
            "VALUES (:sid, :cid, :cn, :tn, :cmd, :ro, :dl, :res, :cvss, :sev, :cve, :rt, :re, :rr, :start, :end, :dur)"
        ), {
            "sid": scan_id, "cid": r["check_id"], "cn": r["check_name"], "tn": r["tool_name"],
            "cmd": r["command_executed"], "ro": r["raw_output"], "dl": r["decision_logic"],
            "res": r["result"], "cvss": r["cvss_score"], "sev": r["severity"], "cve": r["cve_id"],
            "rt": r["remediation_text"], "re": r["remediation_example"], "rr": r["remediation_reference"],
            "start": r.get("execution_start"),
            "end": r.get("execution_end"),
            "dur": r.get("execution_duration", 0.0)
        })
        db.commit()


    def _write_summary(self, db, scan_id, results):
        total = len(results)
        passed = sum(1 for r in results if r["result"] == "PASS")
        failed = total - passed
        pct = round(passed / total * 100) if total else 0
        status = "Y" if passed == total else "N"
        remarks = f"Web compliance: {passed}/{total} checks passed ({pct}%)"
        
        db.execute(text(
            "INSERT INTO scan_results (scan_id, compliance_id, status, remarks, total_checks, passed_checks, failed_checks) "
            "VALUES (:sid, NULL, :st, :rem, :tot, :pas, :fai)"
        ), {"sid": scan_id, "st": status, "rem": remarks, "tot": total, "pas": passed, "fai": failed})
        
        db.execute(text(
            "UPDATE scans SET compliance_percent = :pct, updated_at = :ts WHERE id = :sid"
        ), {"pct": pct, "ts": datetime.now(), "sid": scan_id})
        db.commit()
