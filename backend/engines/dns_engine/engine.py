"""
engine.py — DNS compliance engine orchestrator with multi-server support.

Changes from original:
  - INCONCLUSIVE results are counted separately in aggregation and summary.
  - Aggregation treats INCONCLUSIVE as its own category (not PASS, not FAIL).
  - Summary remarks include inconclusive count.
"""

from __future__ import annotations
import ipaddress
import socket
import threading
import traceback
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

import dns.resolver
from sqlalchemy import text

from app.utils.logger import log_event
from app.models.admin import DynamicCheck
from .checks import (
    ALL_CHECKS,
    TOTAL_CHECKS,
    CheckResult,
    DnsCheck,
    DnsCheckContext,
)
from .commands import CommandCache, check_tool_exists, NMAP_TIMEOUT, DEFAULT_TIMEOUT


# ── Progress constants ────────────────────────────────────────────────────────
PROGRESS_START = 5.0
PROGRESS_END   = 95.0

REQUIRED_TOOLS = ["nmap", "dig", "dnsrecon"]


# ── DB helpers ────────────────────────────────────────────────────────────────

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


def _set_status(
    db,
    scan_id: int,
    status: str,
    error_message: Optional[str] = None,
) -> None:
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
        f"DNS compliance: {passed}/{total} checks passed ({pct}%)"
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


# ── DNS server discovery ──────────────────────────────────────────────────────
'''
def _get_dns_servers(domain: str) -> List[str]:
    """
    Return list of unique IPs of authoritative DNS servers for the domain.
    Walks up the domain tree until NS records are found.
    """
    labels = domain.split('.')
    ips = set()

    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if not candidate:
            break
        try:
            ns_records = dns.resolver.resolve(candidate, 'NS', lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(f"Warning: NS lookup for {candidate} failed: {e}")
            continue

        for ns in ns_records:
            host = str(ns.target).rstrip('.')
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
        raise ValueError(f"Could not find any authoritative DNS server IPs for {domain}")

    return sorted(ips)

'''
def _get_dns_servers(domain: str) -> List[str]:
    """
    Return list of unique IPs of authoritative DNS servers for the domain.
    If the input is an IP address, return it directly.
    """
    # Check if domain is actually an IP address
    try:
        ipaddress.ip_address(domain)
        # It's a valid IP – treat it as the target DNS server
        return [domain]
    except ValueError:
        pass  # Not an IP, continue with domain resolution

    labels = domain.split('.')
    ips = set()

    # Try progressively shorter domain suffixes
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if not candidate:
            break

        try:
            ns_records = dns.resolver.resolve(candidate, 'NS', lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(f"Warning: NS lookup for {candidate} failed: {e}")
            continue

        for ns in ns_records:
            host = str(ns.target).rstrip('.')
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
        raise ValueError(f"Could not find any authoritative DNS server IPs for {domain}")

    return sorted(ips)

# ── Pre-flight tool check ─────────────────────────────────────────────────────

def _check_tools() -> str:
    lines = ["=== DNS Engine Tool Pre-flight Check ==="]
    missing = []
    for tool in REQUIRED_TOOLS:
        found = check_tool_exists(tool)
        lines.append(f"  {'✓' if found else '✗'} {tool} — {'found' if found else 'MISSING'}")
        if not found:
            missing.append(tool)
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")
    return "\n".join(lines)


# ── Per-server scan ───────────────────────────────────────────────────────────

def _run_checks_for_ip(
    ip: str,
    domain: str,
    cache: CommandCache,
    selector: str,
    dns_port: int = 53,
    dynamic_checks: List[DynamicCheck] = None,
) -> List[CheckResult]:
    ctx = DnsCheckContext(domain=domain, dns_ip=ip, cache=cache, selector=selector, dns_port=dns_port)
    results: List[CheckResult] = []

    # 1. Hardcoded checks
    for check_cls in ALL_CHECKS:
        try:
            cr = check_cls(ctx).run()
        except Exception as exc:
            cr = CheckResult(
                check_id         = getattr(check_cls, "check_id", "DNS-??"),
                check_name       = getattr(check_cls, "check_name", "Unknown check"),
                tool_name        = "error",
                command_executed = "N/A — check raised an exception",
                raw_output       = traceback.format_exc(),
                decision_logic   = f"Check failed with exception: {exc}",
                result           = "INCONCLUSIVE",
            )
        results.append(cr)

    # 2. Dynamic checks
    if dynamic_checks:
        for dc in dynamic_checks:
            try:
                # Format command - support {domain}, {dns_ip}, {port}
                cmd = dc.command_template.format(
                    domain=domain, 
                    dns_ip=ip,
                    port=dns_port
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
                results.append(cr)
            except Exception as e:
                cr = CheckResult(
                    check_id         = dc.check_id_string,
                    check_name       = dc.check_name,
                    tool_name        = dc.tool_name or "error",
                    command_executed = "N/A — check raised an exception",
                    raw_output       = traceback.format_exc(),
                    decision_logic   = f"Dynamic check failed with exception: {e}",
                    result           = "INCONCLUSIVE",
                )
                results.append(cr)

    return results


# ── Aggregation ───────────────────────────────────────────────────────────────

def _aggregate_results(
    per_server_results: List[Tuple[str, List[CheckResult]]],
) -> List[CheckResult]:
    """
    Combine results from multiple servers into a single list of CheckResult
    (one per check). Rules per check:
      - If any server returns FAIL       → overall FAIL.
      - If no FAIL but any INCONCLUSIVE  → overall INCONCLUSIVE.
      - Only if ALL servers PASS         → overall PASS.
    Raw outputs and commands are concatenated with server IP headers.
    """
    check_map: dict[str, List[Tuple[str, CheckResult]]] = {}
    for ip, results in per_server_results:
        for cr in results:
            check_map.setdefault(cr.check_id, []).append((ip, cr))

    aggregated = []
    for check_id, items in check_map.items():
        first      = items[0][1]
        check_name = first.check_name
        tool_name  = first.tool_name

        raw_parts = [f"===== Server: {ip} =====\n{cr.raw_output}" for ip, cr in items]
        combined_raw = "\n\n".join(raw_parts)

        cmd_parts = [f"Server {ip}:\n{cr.command_executed}" for ip, cr in items]
        combined_cmd = "\n\n".join(cmd_parts)

        fails         = [(ip, cr) for ip, cr in items if cr.result == "FAIL"]
        inconclusives = [(ip, cr) for ip, cr in items if cr.result == "INCONCLUSIVE"]

        if fails:
            overall_result = "FAIL"
            logic = (
                f"Non-compliance detected on server(s): "
                f"{', '.join(ip for ip, _ in fails)}. "
                f"Example: {fails[0][1].decision_logic}"
            )
        elif inconclusives:
            overall_result = "INCONCLUSIVE"
            logic = (
                f"Check could not be verified on server(s): "
                f"{', '.join(ip for ip, _ in inconclusives)}. "
                f"Reason: {inconclusives[0][1].decision_logic}"
            )
        else:
            overall_result = "PASS"
            logic = f"All {len(items)} DNS server(s) passed this check."

        # Copy CVSS and remediation data from one of the results if it failed or was inconclusive
        # This ensures the aggregated result has the same severity/score as the components.
        cvss_score = 0.0
        severity   = ""
        cve_id     = ""
        rem_text   = ""
        rem_ex     = ""
        rem_ref    = ""

        # Try to find a 'base' result that has metadata (favor fails then inconclusives)
        metadata_source = (fails[0][1] if fails else (inconclusives[0][1] if inconclusives else None))

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

    aggregated.sort(key=lambda x: x.check_id)
    return aggregated


# ── Engine ────────────────────────────────────────────────────────────────────

def run_dns_engine(
    db,
    scan_id:     int,
    domain:      str,
    dns_ip:      Optional[str] = None,
    dns_port:    int = 53,
    selector:    str = "default",
    max_workers: int = 6,
) -> None:
    """
    Main entry point. Called from scan_manager.py.

    If dns_ip is provided, scans only that server.
    Otherwise, discovers authoritative DNS servers for the domain and scans all.
    """
    try:
        log_event(db, scan_id, "INIT", "Initializing DNS compliance engine...")
        _update_progress(db, scan_id, 0.0)

        log_event(db, scan_id, "CHECK", "Running tool pre-flight checks...")
        tool_report = _check_tools()
        print(tool_report)

        log_event(db, scan_id, "START", f"Starting DNS scan for domain: {domain}")
        if dns_ip:
            server_ips = [dns_ip]
            log_event(db, scan_id, "INFO", f"Using provided DNS server: {dns_ip} on port {dns_port}")
        else:
            log_event(db, scan_id, "INFO", "Discovering authoritative DNS servers...")
            server_ips = _get_dns_servers(domain)
            log_event(db, scan_id, "INFO", f"Discovered DNS servers: {', '.join(server_ips)}")

        if not server_ips:
            raise ValueError("No DNS server IPs available to scan.")

        total_servers = len(server_ips)
        total_work    = TOTAL_CHECKS * total_servers
        progress_per_check = (PROGRESS_END - PROGRESS_START) / total_work if total_work else 0

        _update_progress(db, scan_id, PROGRESS_START)

        # Fetch dynamic checks from DB
        dynamic_checks = db.query(DynamicCheck).filter(
            DynamicCheck.engine == 'dns', 
            DynamicCheck.is_active == True
        ).all()

        total_dc = len(dynamic_checks)
        total_servers = len(server_ips)
        total_work    = (TOTAL_CHECKS + total_dc) * total_servers
        progress_per_check = (PROGRESS_END - PROGRESS_START) / total_work if total_work else 0

        def log_cb(stage, msg):
            log_event(None, scan_id, stage, msg)

        cache = CommandCache(log_callback=log_cb)
        per_server_results: List[Tuple[str, List[CheckResult]]] = []
        completed_work = 0
        lock = threading.Lock()

        def scan_one_server(ip: str) -> Tuple[str, List[CheckResult]]:
            log_event(None, scan_id, "START", f"Scanning DNS server: {ip}:{dns_port}")
            results = _run_checks_for_ip(ip, domain, cache, selector, dns_port=dns_port, dynamic_checks=dynamic_checks)
            for cr in results:
                log_event(None, scan_id, "RESULT", f"Server {ip} - {cr.check_name}: {cr.result}")
            return ip, results

        log_event(db, scan_id, "INFO", f"Submitting {total_servers} DNS servers to thread pool...")
        with ThreadPoolExecutor(max_workers=min(max_workers, total_servers)) as pool:
            future_map = {pool.submit(scan_one_server, ip): ip for ip in server_ips}
            for future in as_completed(future_map):
                ip, results = future.result()
                per_server_results.append((ip, results))
                with lock:
                    completed_work += (TOTAL_CHECKS + total_dc)
                    progress = PROGRESS_START + completed_work * progress_per_check
                    _update_progress(db, scan_id, progress)

        log_event(db, scan_id, "SUMMARY", "Aggregating results from all DNS servers...")
        final_results = _aggregate_results(per_server_results)

        for cr in final_results:
            _write_raw_result(db, scan_id, cr)

        _write_summary(db, scan_id, final_results)
        _update_progress(db, scan_id, 100.0)
        _set_status(db, scan_id, "COMPLETED")
        log_event(db, scan_id, "DONE", "DNS compliance scan completed.")

    except Exception as exc:
        error_msg = f"DNS engine fatal error: {exc}\n{traceback.format_exc()}"
        print(error_msg)
        log_event(db, scan_id, "CRITICAL", f"DNS engine failed: {exc}")
        try:
            _set_status(db, scan_id, "FAILED", error_message=error_msg[:2000])
        except Exception:
            pass
        raise
