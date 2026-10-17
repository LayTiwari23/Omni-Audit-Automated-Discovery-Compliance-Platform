"""
checks.py — FTP compliance check classes.
Forensic-grade logging enabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Any, Dict

from threat.cvss_service import get_cvss_for_check
from remediation.remediation_engine import get_remediation
from .commands import CommandCache, DEFAULT_TIMEOUT, NMAP_TIMEOUT
from .parser import (
    parse_check_1_open_ports,
    parse_check_2_ftp_availability,
    parse_check_3_ftp_version,
    parse_check_4_secure_channel,
    parse_check_5_anonymous_upload,
)


@dataclass
class FtpCheckContext:
    target_ip: str
    cache: CommandCache
    ftp_port: int = 21


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    tool_name: str
    command_executed: str
    raw_output: str
    decision_logic: str
    result: str  # "PASS" or "FAIL"
    # Timing fields
    execution_start:  Optional[Any] = None
    execution_end:    Optional[Any] = None
    execution_duration: float = 0.0
    # Threat/Remediation
    cvss_score: float = 0.0
    severity: str = ""
    cve_id: str = ""
    remediation_text: str = ""
    remediation_example: str = ""
    remediation_reference: str = ""

def format_forensic_output(meta: Dict[str, Any]) -> str:
    """Format the metadata into a terminal-style banner at the top."""
    return f"""=== EXECUTION INFO ===
Command: {meta.get('command')}
Start (UTC): {meta.get('start_time')}
End   (UTC): {meta.get('end_time')}
Duration: {meta.get('duration'):.2f} sec
======================

{meta.get('output')}"""


class FtpCheck:
    check_id: str = ""
    check_name: str = ""

    def __init__(self, ctx: FtpCheckContext) -> None:
        self.ctx = ctx

    def _make_result(self, tool_name: str, meta: Dict[str, Any], res: str, logic: str) -> CheckResult:
        cvss_data = {}
        remediation = {}
        if res == "FAIL":
            try:
                numeric_id = int(self.check_id)
                cvss_data = get_cvss_for_check(numeric_id, self.check_name)
                
                # Pass context for Dynamic AI Remediation if available
                finding_context = {
                    "check_name": self.check_name,
                    "raw_output": format_forensic_output(meta),
                    "summary": logic
                }
                remediation = get_remediation(numeric_id, finding_details=finding_context)
            except: pass
            
        return CheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            tool_name=tool_name,
            command_executed=meta.get('command', 'N/A'),
            raw_output=format_forensic_output(meta),
            decision_logic=logic,
            result=res,
            execution_start=meta.get('start_time'),
            execution_end=meta.get('end_time'),
            execution_duration=meta.get('duration', 0.0),
            cvss_score=cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id=cvss_data.get('cve_id', ''),
            remediation_text=remediation.get('fix', ''),
            remediation_example=remediation.get('example', ''),
            remediation_reference=remediation.get('reference', ''),
        )

    def run(self) -> CheckResult:
        raise NotImplementedError


class Check01OpenPorts(FtpCheck):
    check_id = "401"
    check_name = "List open ports on IP address"

    def run(self) -> CheckResult:
        # Include the specific port in nmap to verify it's open/visible
        args = ["nmap", "-Pn", "-sV", "-p", str(self.ctx.ftp_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_check_1_open_ports(meta['output'])
        return self._make_result("nmap", meta, result, logic)


class Check02FtpAvailability(FtpCheck):
    check_id = "402"
    check_name = "FTP service availability"

    def run(self) -> CheckResult:
        args = ["nmap", "-Pn", "-p", str(self.ctx.ftp_port), "--script", "ftp-anon,ftp-syst", self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_2_ftp_availability(meta['output'])
        return self._make_result("nmap", meta, result, logic)


class Check03FtpVersion(FtpCheck):
    check_id = "403"
    check_name = "FTP version not visible"

    def run(self) -> CheckResult:
        args = ["nmap", "-Pn", "-p", str(self.ctx.ftp_port), "--script", "ftp-anon,ftp-syst", self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_3_ftp_version(meta['output'])
        return self._make_result("nmap", meta, result, logic)


class Check04SecureChannel(FtpCheck):
    check_id = "404"
    check_name = "FTP accessible over secure channel"

    def run(self) -> CheckResult:
        ports = f"{self.ctx.ftp_port},22,990"
        args = ["nmap", "-Pn", "-sV", "-p", ports, self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_check_4_secure_channel(meta['output'])
        return self._make_result("nmap", meta, result, logic)


class Check05AnonymousUpload(FtpCheck):
    check_id = "405"
    check_name = "Anonymous FTP upload not allowed"

    def run(self) -> CheckResult:
        args = ["nmap", "-Pn", "-p", str(self.ctx.ftp_port), "--script", "ftp-anon,ftp-syst", self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_5_anonymous_upload(meta['output'])
        return self._make_result("nmap", meta, result, logic)


ALL_CHECKS: list[type[FtpCheck]] = [
    Check01OpenPorts,
    Check02FtpAvailability,
    Check03FtpVersion,
    Check04SecureChannel,
    Check05AnonymousUpload,
]
TOTAL_CHECKS = len(ALL_CHECKS)
