"""
engine.py — Email compliance engine orchestrator with aggregation.

Changes:
  - ANY_PASS_CHECKS: checks where PASS on any server → overall PASS.
  - INCONCLUSIVE results counted separately in aggregation and summary.
  - Exception fallbacks produce INCONCLUSIVE instead of FAIL.
"""

from __future__ import annotations
import ipaddress
import threading
import traceback
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import dns.resolver
from sqlalchemy import text

from app.utils.logger import log_event
from app.models.admin import DynamicCheck
from .commands import CommandCache, check_tool_exists
from .checks import (
    DOMAIN_WIDE_CHECKS,
    PER_SERVER_CHECKS,
    TOTAL_CHECKS,
    CheckResult,
    EmailCheckContext,
    EmailCheck,
)


PROGRESS_START = 5.0
PROGRESS_END   = 95.0

REQUIRED_TOOLS = ["dig", "openssl", "nc", "swaks", "nmap", "telnet"]

# For these check IDs, PASS on ANY server is sufficient for overall PASS.
# All other checks use fail-if-any-server-fails logic.
ANY_PASS_CHECKS: Set[str] = {"4", "5"}   # TLS Support, SMTP-AUTH Disclosure
# (At least one server being reachable/configured correctly is a meaningful signal.)


def _now() -> datetime:
    return datetime.now()


def _update_progress(db, scan_id: int, percent: float) -> None:
    db.execute(
        text(
            "UPDATE scans SET progress_percent = :p, updated_at = :ts "
            "WHERE id = :sid"
        ),
        {"p": round(min(max(percent, 0.0), 100.0), 2), "ts": _now(), "sid": scan_id},
    )
    db.commit()


def _set_status(db, scan_id: int, status: str, error_message: Optional[str] = None) -> None:
    db.execute(
        text(
            "UPDATE scans "
            "SET status = :s, updated_at = :ts, error_message = :em "
            "WHERE id = :sid"
        ),
        {"s": status, "ts": _now(), "em": error_message, "sid": scan_id},
    )
    db.commit()


def _write_raw_result(db, scan_id: int, cr: CheckResult) -> None:
    db.execute(
        text(
            "INSERT INTO scan_raw_results "
            "(scan_id, check_id, check_name, tool_name, command_executed, "
            " raw_output, decision_logic, result, cvss_score, severity, cve_id, "
            " remediation_text, remediation_example, remediation_reference, "
            " execution_start, execution_end, execution_duration) "
            "VALUES (:sid, :cid, :cn, :tn, :cmd, :ro, :dl, :res, :cvss, :sev, :cve, "
            " :rem_t, :rem_ex, :rem_ref, :start, :end, :dur)"
        ),
        {
            "sid": scan_id,
            "cid": cr.check_id,
            "cn":  cr.check_name,
            "tn":  cr.tool_name,
            "cmd": cr.command_executed,
            "ro":  cr.raw_output or "",
            "dl":  cr.decision_logic,
            "res": cr.result,
            "cvss": cr.cvss_score,
            "sev":  cr.severity,
            "cve":  cr.cve_id,
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
    total        = len(results)
    passed       = sum(1 for r in results if r.result == "PASS")
    inconclusive = sum(1 for r in results if r.result == "INCONCLUSIVE")
    failed       = total - passed - inconclusive
    pct          = round(passed / total * 100) if total else 0
    status       = "Y" if passed == total else "N"

    remarks = (
        f"Email compliance: {passed}/{total} checks passed ({pct}%)"
        f" | Failed: {failed} | Inconclusive: {inconclusive}"
    )

    db.execute(
        text(
            "INSERT INTO scan_results "
            "(scan_id, compliance_id, status, remarks, "
            " total_checks, passed_checks, failed_checks) "
            "VALUES (:sid, NULL, :st, :rem, :tot, :pas, :fai)"
        ),
        {
            "sid": scan_id,
            "st":  status,
            "rem": remarks,
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
    missing = [t for t in REQUIRED_TOOLS if not check_tool_exists(t)]
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")

'''
def _get_mx_servers(domain: str) -> List[str]:
    labels = domain.split('.')
    ips: set = set()

    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if not candidate:
            break
        try:
            mx_records = dns.resolver.resolve(candidate, 'MX', lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(f"Warning: MX lookup for {candidate} failed: {e}")
            continue

        for mx in mx_records:
            host = str(mx.exchange).rstrip('.')
            try:
                answers = dns.resolver.resolve(host, 'A', lifetime=5)
                for a in answers:
                    ips.add(a.address)
            except Exception as e:
                print(f"Warning: Could not resolve {host} to IP: {e}")

        if ips:
            break

    if not ips:
        raise ValueError(f"Could not find any MX server IPs for {domain}")
    return sorted(ips)
'''
def _get_mx_servers(domain: str) -> List[str]:
    """
    Return list of unique IPs of all MX servers for the domain.
    If the input is an IP address, treat it as the target mail server directly.
    """
    # Check if domain is actually an IP address
    try:
        ipaddress.ip_address(domain)
        return [domain]  # It's a valid IP – use it directly
    except ValueError:
        pass  # Not an IP, continue with MX resolution

    labels = domain.split('.')
    ips = set()

    # Walk up domain tree to find MX records
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if not candidate:
            break

        try:
            mx_records = dns.resolver.resolve(candidate, 'MX', lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(f"Warning: MX lookup for {candidate} failed: {e}")
            continue

        for mx in mx_records:
            host = str(mx.exchange).rstrip('.')
            try:
                answers = dns.resolver.resolve(host, 'A', lifetime=5)
                for a in answers:
                    ips.add(a.address)
            except Exception as e:
                print(f"Warning: Could not resolve {host} to IP: {e}")
                continue

        if ips:
            break

    if not ips:
        raise ValueError(f"Could not find any MX server IPs for {domain}")

    return sorted(ips)

def _aggregate_per_server_results(
    per_server_results: Dict[str, List[CheckResult]],
) -> List[CheckResult]:
    """
    per_server_results: {check_id: [CheckResult, ...]} (one result per server)

    Aggregation rules:
      - Checks in ANY_PASS_CHECKS: PASS if any server passed; FAIL only if all
        servers failed; INCONCLUSIVE if no server passed and at least one is
        inconclusive.
      - All other checks: FAIL if any server failed; INCONCLUSIVE if no failure
        but some server was inconclusive; PASS only if all pass.
    """
    aggregated: List[CheckResult] = []

    for check_id, results in per_server_results.items():
        if not results:
            continue

        first      = results[0]
        check_name = first.check_name
        tool_name  = first.tool_name

        raw_parts = []
        for r in results:
            server_label = r.command_executed.split()[-1] if r.command_executed else "?"
            raw_parts.append(f"===== Server: {server_label} =====\n{r.raw_output}")
        combined_raw = "\n\n".join(raw_parts)
        combined_cmd = "\n".join(r.command_executed for r in results)

        passes       = [r for r in results if r.result == "PASS"]
        fails        = [r for r in results if r.result == "FAIL"]
        inconclusives = [r for r in results if r.result == "INCONCLUSIVE"]

        if check_id in ANY_PASS_CHECKS:
            # Any-pass logic
            if passes:
                overall_result = "PASS"
                logic = (
                    f"PASS on {len(passes)} of {len(results)} server(s) "
                    f"(any-pass rule applies for this check)."
                )
            elif inconclusives and not fails:
                overall_result = "INCONCLUSIVE"
                logic = (
                    f"No server returned PASS; {len(inconclusives)} inconclusive. "
                    f"Reason: {inconclusives[0].decision_logic}"
                )
            else:
                overall_result = "FAIL"
                base_err = fails[0].decision_logic if fails else (inconclusives[0].decision_logic if inconclusives else "Unknown error")
                logic = f"All servers failed. Example: {base_err}"
        else:
            # Fail-if-any logic
            if fails:
                overall_result = "FAIL"
                failed_servers = ", ".join(r.command_executed.split()[-1] for r in fails)
                logic = f"Failed on: {failed_servers}. {fails[0].decision_logic}"
            elif inconclusives:
                overall_result = "INCONCLUSIVE"
                logic = (
                    f"Check inconclusive on {len(inconclusives)} server(s). "
                    f"Reason: {inconclusives[0].decision_logic}"
                )
            else:
                overall_result = "PASS"
                logic = f"All {len(results)} server(s) passed."

        # Copy CVSS and remediation data from one of the results if it failed or was inconclusive
        # This ensures the aggregated result has the same severity/score as the components.
        cvss_score = 0.0
        severity   = ""
        cve_id     = ""
        rem_text   = ""
        rem_ex     = ""
        rem_ref    = ""

        # Try to find a 'base' result that has metadata (favor fails then inconclusives)
        metadata_source = (fails[0] if fails else (inconclusives[0] if inconclusives else None))

        if overall_result in ["FAIL", "INCONCLUSIVE"] and metadata_source:
            base = metadata_source
            cvss_score = base.cvss_score
            severity   = base.severity
            cve_id     = base.cve_id
            rem_text   = base.remediation_text
            rem_ex     = base.remediation_example
            rem_ref    = base.remediation_reference

        aggregated.append(CheckResult(
            check_id              = check_id,
            check_name            = check_name,
            tool_name             = tool_name,
            command_executed      = combined_cmd,
            raw_output            = combined_raw,
            decision_logic        = logic,
            result                = overall_result,
            cvss_score            = cvss_score,
            severity              = severity,
            cve_id                = cve_id,
            remediation_text      = rem_text,
            remediation_example   = rem_ex,
            remediation_reference = rem_ref,
        ))

    return aggregated


def run_email_engine(
    db,
    scan_id:     int,
    domain:      str,
    selector:    str = "default",
    port:        Optional[int] = None,
    max_workers: int = 6,
    email_from:  Optional[str] = None,
    email_to:    Optional[str] = None,
) -> None:
    """Main entry point. Called from scan_manager.py."""
    smtp_port = port or 25
    try:
        log_event(db, scan_id, "INIT", "Initializing Email compliance engine...")
        _update_progress(db, scan_id, 0.0)

        log_event(db, scan_id, "CHECK", "Running tool pre-flight checks...")
        _check_tools()

        log_event(db, scan_id, "START", f"Starting Email scan for domain: {domain}")
        log_event(db, scan_id, "INFO", "Discovering MX server IPs...")
        mx_ips = _get_mx_servers(domain)
        log_event(db, scan_id, "INFO", f"Discovered MX server IPs: {', '.join(mx_ips)}")

        # Fetch dynamic checks from DB
        dynamic_checks = db.query(DynamicCheck).filter(
            DynamicCheck.engine == 'email', 
            DynamicCheck.is_active == True
        ).all()

        total_dc = len(dynamic_checks)
        total_servers      = len(mx_ips)
        domain_wide_count  = len(DOMAIN_WIDE_CHECKS)
        per_server_count   = len(PER_SERVER_CHECKS) + total_dc
        total_executions   = domain_wide_count + per_server_count * total_servers
        progress_per_step  = (PROGRESS_END - PROGRESS_START) / total_executions if total_executions else 0

        def log_cb(stage, msg):
            log_event(None, scan_id, stage, msg)

        cache     = CommandCache(log_callback=log_cb)
        completed = 0
        lock      = threading.Lock()

        # per_server_map keyed by check_id
        per_server_map: Dict[str, List[CheckResult]] = {
            c.check_id: [] for c in PER_SERVER_CHECKS
        }
        for dc in dynamic_checks:
            per_server_map[dc.check_id_string] = []

        all_results: List[CheckResult] = []

        # ── Domain-wide checks ───────────────────────────────────────────────
        # ... (domain wide checks unchanged) ...
        log_event(db, scan_id, "CHECK", "Running domain-wide email checks (SPF/DMARC/etc)...")
        ctx_domain = EmailCheckContext(
            domain=domain, mx_ips=mx_ips, cache=cache, selector=selector,
            email_from=email_from, email_to=email_to,
        )
        for check_cls in DOMAIN_WIDE_CHECKS:
            try:
                results = check_cls(ctx_domain).run()
                for cr in results:
                    all_results.append(cr)
                    log_event(None, scan_id, "RESULT", f"{cr.check_name}: {cr.result}")
            except Exception as e:
                cr = CheckResult(
                    check_id         = getattr(check_cls, "check_id", "EMAIL-??"),
                    check_name       = getattr(check_cls, "check_name", "Unknown"),
                    tool_name        = "error",
                    command_executed = "N/A",
                    raw_output       = traceback.format_exc(),
                    decision_logic   = f"Check raised an exception: {e}",
                    result           = "INCONCLUSIVE",
                )
                all_results.append(cr)
                log_event(None, scan_id, "ERROR", f"Domain check {getattr(check_cls, 'check_name', 'Unknown')} failed: {e}")
            finally:
                completed += 1
                _update_progress(db, scan_id, PROGRESS_START + completed * progress_per_step)

        # ── Per-server checks ────────────────────────────────────────────────
        def run_server_checks(ip: str) -> List[Tuple[str, CheckResult]]:
            log_event(None, scan_id, "START", f"Scanning MX server: {ip}:{smtp_port}")
            ctx_server = EmailCheckContext(
                domain=domain, mx_ips=mx_ips, cache=cache,
                selector=selector, current_ip=ip,
                email_from=email_from, email_to=email_to,
                smtp_port=smtp_port
            )
            results = []
            for check_cls in PER_SERVER_CHECKS:
                try:
                    cr_list = check_cls(ctx_server).run()
                    for cr in cr_list:
                        results.append((cr.check_id, cr))
                        log_event(None, scan_id, "RESULT", f"Server {ip} - {cr.check_name}: {cr.result}")
                except Exception as e:
                    cr = CheckResult(
                        check_id         = getattr(check_cls, "check_id", "EMAIL-??"),
                        check_name       = getattr(check_cls, "check_name", "Unknown"),
                        tool_name        = "error",
                        command_executed = f"Error for {ip}",
                        raw_output       = traceback.format_exc(),
                        decision_logic   = f"Check raised an exception: {e}",
                        result           = "INCONCLUSIVE",
                    )
                    results.append((cr.check_id, cr))
                    log_event(None, scan_id, "ERROR", f"Server {ip} check {getattr(check_cls, 'check_name', 'Unknown')} failed: {e}")
            
            # Dynamic Email checks
            for dc in dynamic_checks:
                try:
                    # Format command - support {domain}, {dns_ip}, {port}
                    # Also keep {mx_ip} for backward compatibility
                    cmd = dc.command_template.format(
                        domain=domain, 
                        dns_ip=ip, 
                        mx_ip=ip,
                        port=smtp_port
                    )

                    # Run command
                    meta = cache.get_or_run(cmd.split(), timeout=dc.timeout)
                    output = meta['output']

                    # Match success criteria (Regex)
                    normalized_output = re.sub(r' +', ' ', output)
                    is_pass = bool(re.search(dc.success_criteria, normalized_output, re.IGNORECASE | re.MULTILINE))
                    result = "PASS" if is_pass else "FAIL"

                    cr = CheckResult(
                        check_id         = dc.check_id_string,
                        check_name       = dc.check_name,
                        tool_name        = dc.tool_name or "custom",
                        command_executed = cmd,
                        raw_output       = f"=== EXECUTION INFO ===\nCommand: {cmd}\nOutput:\n\n{output}",
                        decision_logic   = f"Dynamic check. Success criteria '{dc.success_criteria}' matched: {is_pass}",
                        result           = result,
                        cvss_score       = dc.cvss_score,
                        severity         = dc.severity,
                        remediation_text = dc.remediation_text or "",
                        execution_start  = meta.get('start_time'),
                        execution_end    = meta.get('end_time'),
                        execution_duration = meta.get('duration', 0.0)
                    )
                    results.append((cr.check_id, cr))
                    log_event(None, scan_id, "RESULT", f"Server {ip} - {cr.check_name}: {cr.result}")
                except Exception as e:
                    cr = CheckResult(
                        check_id         = dc.check_id_string,
                        check_name       = dc.check_name,
                        tool_name        = "error",
                        command_executed = f"Dynamic check error for {ip}",
                        raw_output       = traceback.format_exc(),
                        decision_logic   = f"Dynamic check failed: {e}",
                        result           = "INCONCLUSIVE",
                    )
                    results.append((cr.check_id, cr))
                    log_event(None, scan_id, "ERROR", f"Server {ip} dynamic check {dc.check_name} failed: {e}")

            return results

        log_event(db, scan_id, "INFO", f"Submitting {total_servers} MX servers to thread pool...")
        with ThreadPoolExecutor(max_workers=min(max_workers, total_servers)) as pool:
            future_to_ip = {pool.submit(run_server_checks, ip): ip for ip in mx_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    server_results = future.result()
                except Exception as e:
                    server_results = []
                    for check_cls in PER_SERVER_CHECKS:
                        cr = CheckResult(
                            check_id         = getattr(check_cls, "check_id", "EMAIL-??"),
                            check_name       = getattr(check_cls, "check_name", "Unknown"),
                            tool_name        = "error",
                            command_executed = f"Batch error for {ip}",
                            raw_output       = traceback.format_exc(),
                            decision_logic   = f"Server scan failed: {e}",
                            result           = "INCONCLUSIVE",
                        )
                        server_results.append((cr.check_id, cr))

                with lock:
                    for check_id, cr in server_results:
                        per_server_map[check_id].append(cr)
                        completed += 1
                        _update_progress(
                            db, scan_id,
                            PROGRESS_START + completed * progress_per_step,
                        )

        # ── Aggregate per-server → one result per check ──────────────────────
        log_event(db, scan_id, "SUMMARY", "Aggregating results from all MX servers...")
        aggregated = _aggregate_per_server_results(per_server_map)
        all_results.extend(aggregated)

        for cr in all_results:
            _write_raw_result(db, scan_id, cr)

        _write_summary(db, scan_id, all_results)
        _update_progress(db, scan_id, 100.0)
        _set_status(db, scan_id, "COMPLETED")
        log_event(db, scan_id, "DONE", "Email compliance scan completed.")

    except Exception as exc:
        error_msg = f"Email engine fatal error: {exc}\n{traceback.format_exc()}"
        print(error_msg)
        log_event(db, scan_id, "CRITICAL", f"Email engine failed: {exc}")
        try:
            _set_status(db, scan_id, "FAILED", error_message=error_msg[:2000])
        except Exception:
            pass
        raise
