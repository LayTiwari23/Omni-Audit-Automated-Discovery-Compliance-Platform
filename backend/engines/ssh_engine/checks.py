"""
checks.py — SSH compliance check classes.
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
    parse_check_2_version_visibility,
    parse_check_3_protocol_v1,
    parse_check_4_strong_ciphers,
    parse_check_5_strong_kex,
    parse_check_6_strong_mac,
)


@dataclass
class SshCheckContext:
    target_ip: str
    ssh_port: int
    cache: CommandCache


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


class SshCheck:
    check_id: str = ""
    check_name: str = ""

    def __init__(self, ctx: SshCheckContext) -> None:
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


class Check01OpenPorts(SshCheck):
    check_id = "501"
    check_name = "List open ports on IP address"

    def run(self) -> CheckResult:
        # Include the specific port in nmap to verify it's open/visible
        args = ["nmap", "-Pn", "-sV", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_check_1_open_ports(meta['output'])
        return self._make_result("nmap", meta, result, logic)


class Check02SshVersion(SshCheck):
    check_id = "502"
    check_name = "SSH service version not visible"

    def run(self) -> CheckResult:
        args = ["ssh-audit", "-2", "-4", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_2_version_visibility(meta['output'])
        return self._make_result("ssh-audit", meta, result, logic)


class Check03ProtocolV1(SshCheck):
    check_id = "503"
    check_name = "SSH must NOT support protocol v1"

    def run(self) -> CheckResult:
        args = ["ssh-audit", "-2", "-4", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_3_protocol_v1(meta['output'])
        return self._make_result("ssh-audit", meta, result, logic)


class Check04StrongCiphers(SshCheck):
    check_id = "504"
    check_name = "Strong ciphers supported"

    def run(self) -> CheckResult:
        args = ["ssh-audit", "-2", "-4", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_4_strong_ciphers(meta['output'])
        return self._make_result("ssh-audit", meta, result, logic)


class Check05StrongKex(SshCheck):
    check_id = "505"
    check_name = "Strong key algorithms supported"

    def run(self) -> CheckResult:
        args = ["ssh-audit", "-2", "-4", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_5_strong_kex(meta['output'])
        return self._make_result("ssh-audit", meta, result, logic)


class Check06StrongMac(SshCheck):
    check_id = "506"
    check_name = "Strong MAC algorithms supported"

    def run(self) -> CheckResult:
        args = ["ssh-audit", "-2", "-4", "-p", str(self.ctx.ssh_port), self.ctx.target_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_check_6_strong_mac(meta['output'])
        return self._make_result("ssh-audit", meta, result, logic)


ALL_CHECKS: list[type[SshCheck]] = [
    Check01OpenPorts,
    Check02SshVersion,
    Check03ProtocolV1,
    Check04StrongCiphers,
    Check05StrongKex,
    Check06StrongMac,
]
TOTAL_CHECKS = len(ALL_CHECKS)
