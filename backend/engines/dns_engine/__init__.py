"""
dns_engine — DNS compliance scanning engine.

Public API (everything scan_manager.py needs):

    from engines.dns_engine import run_dns_engine

    run_dns_engine(
        db       = db_session,
        scan_id  = 42,
        domain   = "example.com",
        dns_ip   = "1.2.3.4",    # optional — resolved from domain if omitted
        selector = "default",    # optional — DKIM selector
    )

The engine:
  - runs all 12 DNS compliance checks in parallel
  - writes results to scan_raw_results (one row per check)
  - writes a summary row to scan_results
  - updates scans.progress_percent after each check
  - sets scans.status = COMPLETED | FAILED on finish
"""

from .engine import run_dns_engine
from .checks import ALL_CHECKS, TOTAL_CHECKS, CheckResult, DnsCheckContext

__all__ = [
    "run_dns_engine",
    "ALL_CHECKS",
    "TOTAL_CHECKS",
    "CheckResult",
    "DnsCheckContext",
]
