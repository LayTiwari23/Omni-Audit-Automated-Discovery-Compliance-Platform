"""
checks.py — Email compliance check definitions.
Forensic-grade logging enabled.
"""

from __future__ import annotations

import socket
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Any, Dict

from threat.cvss_service import get_cvss_for_check
from remediation.remediation_engine import get_remediation
from .commands import CommandCache, DEFAULT_TIMEOUT, SMTP_TIMEOUT, output_has_execution_failure
from .parser import (
    parse_open_relay,
    parse_banner_version,
    parse_old_version,
    parse_smtp_tls,
    parse_helo_auth,
    parse_vrfy,
    parse_swaks_spoofing,
    parse_blacklist,
    parse_reverse_dns,
)

@dataclass
class EmailCheckContext:
    domain:     str
    mx_ips:     List[str]
    cache:      CommandCache
    selector:   str = "default"
    current_ip: str = ""
    email_from: Optional[str] = None
    email_to:   Optional[str] = None
    smtp_port:  int = 25

@dataclass
class CheckResult:
    check_id:         str
    check_name:       str
    tool_name:        str
    command_executed: str
    raw_output:       str
    decision_logic:   str
    result:           str   # "PASS", "FAIL", or "INCONCLUSIVE"
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

class EmailCheck:
    check_id:   str = ""
    check_name: str = ""

    def __init__(self, ctx: EmailCheckContext) -> None:
        self.ctx = ctx

    def _make_result(self, tool_name: str, meta: Dict[str, Any], res: str, logic: str) -> CheckResult:
        cvss_data = {}
        remediation = {}
        if res in ["FAIL", "INCONCLUSIVE"]:
            try:
                mapping_id = 1000 + int(self.check_id)
                cvss_data = get_cvss_for_check(mapping_id, self.check_name)
                
                # Pass context for Dynamic AI Remediation if available
                finding_context = {
                    "check_name": self.check_name,
                    "raw_output": format_forensic_output(meta),
                    "summary": logic
                }
                remediation = get_remediation(mapping_id, finding_details=finding_context)
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

    def run(self) -> List[CheckResult]:
        raise NotImplementedError

# ── 1. Open Relay Protection ──────────────────────────────────────────────────
class Check01OpenRelay(EmailCheck):
    check_id   = "1"
    check_name = "Open Relay Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        mail_from = self.ctx.email_from or "external_test@gmail.com"
        mail_to   = self.ctx.email_to or "external_target@yahoo.com"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", mail_from, "--to", mail_to, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_open_relay(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 2. MTA Version Hiding ─────────────────────────────────────────────────────
class Check02MtaVersion(EmailCheck):
    check_id   = "2"
    check_name = "MTA Version Hiding"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        port = self.ctx.smtp_port
        nmap_args = ["nmap", "-sV", "-p", str(port), ip]
        meta = self.ctx.cache.get_or_run(nmap_args, timeout=DEFAULT_TIMEOUT)
        
        # Banner capture is manual socket, we manually create meta for it
        s_start = datetime.now()
        banner = ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5); sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors='ignore'); sock.close()
        except Exception as e: banner = f"Banner capture failed: {e}"
        s_end = datetime.now()
        
        combined_meta = {
            "command": f"nmap -sV -p {port} {ip} && [socket banner capture on port {port}]",
            "output": f"--- NMAP ---\n{meta['output']}\n\n--- BANNER ---\n{banner}",
            "start_time": meta['start_time'],
            "end_time": s_end,
            "duration": (s_end - meta['start_time']).total_seconds()
        }
        
        result, logic = parse_banner_version(meta['output'], banner)
        return [self._make_result("nmap/socket", combined_meta, result, logic)]

# ── 3. MTA Software Up-to-date ────────────────────────────────────────────────
class Check03MtaOldVersion(EmailCheck):
    check_id   = "3"
    check_name = "MTA Software Up-to-date"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        port = self.ctx.smtp_port
        meta = self.ctx.cache.get_or_run(["nmap", "-sV", "-p", str(port), ip], timeout=DEFAULT_TIMEOUT)
        result, logic = parse_old_version(meta['output'])
        return [self._make_result("nmap", meta, result, logic)]

# ── 4. TLS Support ────────────────────────────────────────────────────────────
class Check04MtaTls(EmailCheck):
    check_id   = "4"
    check_name = "TLS Support"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        port = self.ctx.smtp_port
        args = ["openssl", "s_client", "-starttls", "smtp", "-connect", f"{ip}:{port}", "-servername", self.ctx.domain]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_smtp_tls(meta['output'])
        return [self._make_result("openssl", meta, result, logic)]

# ── 5. SMTP-AUTH Restriction ──────────────────────────────────────────────────
class Check05SmtpAuth(EmailCheck):
    check_id   = "5"
    check_name = "SMTP-AUTH Restriction"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        port = self.ctx.smtp_port
        start = datetime.now()
        try:
            server = smtplib.SMTP(ip, port, timeout=SMTP_TIMEOUT)
            code, msg = server.ehlo(self.ctx.domain); server.quit()
            out = f"{code} {msg}"
        except Exception as e: out = f"Connection failed: {e}"
        end = datetime.now()
        
        meta = {
            "command": f"python:smtplib EHLO {self.ctx.domain} on port {port}",
            "output": out,
            "start_time": start,
            "end_time": end,
            "duration": (end - start).total_seconds()
        }
        result, logic = parse_helo_auth(out)
        return [self._make_result("smtplib", meta, result, logic)]

# ── 6. User Enumeration Prevention ─────────────────────────────────────────────
class Check06UserEnum(EmailCheck):
    check_id   = "6"
    check_name = "User Enumeration Prevention"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        port = self.ctx.smtp_port
        start = datetime.now()
        try:
            server = smtplib.SMTP(ip, port, timeout=SMTP_TIMEOUT)
            server.ehlo(self.ctx.domain)
            code, msg = server.docmd("VRFY", "root"); server.quit()
            out = f"{code} {msg}"
        except Exception as e: out = f"Connection failed: {e}"
        end = datetime.now()
        
        meta = {
            "command": f"python:smtplib VRFY root on port {port}",
            "output": out,
            "start_time": start,
            "end_time": end,
            "duration": (end - start).total_seconds()
        }
        result, logic = parse_vrfy(out)
        return [self._make_result("smtplib", meta, result, logic)]

# ── 7. Internal Domain Spoofing Protection ────────────────────────────────────
class Check07SpoofSameDomain(EmailCheck):
    check_id   = "7"
    check_name = "Internal Domain Spoofing Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        sender = f"test@{self.ctx.domain}"
        target = f"admin@{self.ctx.domain}"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", sender, "--to", target, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_swaks_spoofing(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 8. Hindi Punycode Domain Spoofing Protection ──────────────────────────────
class Check08SpoofPunycodeHindi(EmailCheck):
    check_id   = "8"
    check_name = "Hindi Punycode Domain Spoofing Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        puny_domain = f"xn--{self.ctx.domain.replace('.', '-')}.xn--p1ai" 
        sender = f"test@{puny_domain}"
        target = f"admin@{self.ctx.domain}"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", sender, "--to", target, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_swaks_spoofing(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 9. Subdomain to Domain Spoofing Protection ────────────────────────────────
class Check09SpoofSubdomainToDomain(EmailCheck):
    check_id   = "9"
    check_name = "Subdomain to Domain Spoofing Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        sender = f"test@sub.{self.ctx.domain}"
        target = f"admin@{self.ctx.domain}"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", sender, "--to", target, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_swaks_spoofing(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 10. Hindi Punycode Subdomain Spoofing Protection ──────────────────────────
class Check10SpoofPunycodeSubdomain(EmailCheck):
    check_id   = "10"
    check_name = "Hindi Punycode Subdomain Spoofing Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        puny_sub = f"xn--sub-{self.ctx.domain.split('.')[0]}.{self.ctx.domain}"
        sender = f"test@{puny_sub}"
        target = f"admin@sub.{self.ctx.domain}"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", sender, "--to", target, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_swaks_spoofing(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 11. Internal Subdomain Spoofing Protection ────────────────────────────────
class Check11SpoofSubdomainToSubdomain(EmailCheck):
    check_id   = "11"
    check_name = "Internal Subdomain Spoofing Protection"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        sender = f"test@sub.{self.ctx.domain}"
        target = f"admin@sub.{self.ctx.domain}"
        args = ["swaks", "--server", ip, "--port", str(self.ctx.smtp_port), "--from", sender, "--to", target, "--quit-after", "RCPT"]
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_swaks_spoofing(meta['output'])
        return [self._make_result("swaks", meta, result, logic)]

# ── 12. RBL/Blacklist Filtering ───────────────────────────────────────────────
class Check12Blacklist(EmailCheck):
    check_id   = "12"
    check_name = "RBL/Blacklist Filtering"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        blacklists = ["zen.spamhaus.org", "bl.spamcop.net"]
        rev = ".".join(reversed(ip.split('.')))
        
        all_meta = []
        for bl in blacklists:
            meta = self.ctx.cache.get_or_run(["dig", "+short", f"{rev}.{bl}"], timeout=DEFAULT_TIMEOUT)
            all_meta.append(meta)
        
        combined_meta = {
            "command": f"RBL lookups for {ip}",
            "output": "\n\n".join([f"--- {m['command']} ---\n{m['output']}" for m in all_meta]),
            "start_time": all_meta[0]['start_time'],
            "end_time": all_meta[-1]['end_time'],
            "duration": sum(m['duration'] for m in all_meta)
        }
        
        result, logic = parse_blacklist(combined_meta['output'])
        return [self._make_result("dig", combined_meta, result, logic)]

# ── 13. Forward and Reverse DNS Alignment ─────────────────────────────────────
class Check13DnsMatch(EmailCheck):
    check_id   = "13"
    check_name = "Forward and Reverse DNS Alignment"
    def run(self) -> List[CheckResult]:
        ip = self.ctx.current_ip
        ptr_meta = self.ctx.cache.get_or_run(["dig", "+short", "-x", ip], timeout=DEFAULT_TIMEOUT)
        hostname = ptr_meta['output'].strip().rstrip('.')
        
        a_meta = {"output": "", "command": "N/A", "start_time": datetime.now(), "end_time": datetime.now(), "duration": 0}
        if hostname: 
            a_meta = self.ctx.cache.get_or_run(["dig", "+short", hostname], timeout=DEFAULT_TIMEOUT)
            
        combined_meta = {
            "command": f"dig -x {ip} && dig {hostname}",
            "output": f"--- PTR ---\n{ptr_meta['output']}\n\n--- A ---\n{a_meta['output']}",
            "start_time": ptr_meta['start_time'],
            "end_time": a_meta['end_time'],
            "duration": ptr_meta['duration'] + a_meta['duration']
        }
        
        result, logic = parse_reverse_dns(ptr_meta['output'], a_meta['output'])
        return [self._make_result("dig", combined_meta, result, logic)]

# ── Registry ──────────────────────────────────────────────────────────────────

DOMAIN_WIDE_CHECKS = []
PER_SERVER_CHECKS = [
    Check01OpenRelay, Check02MtaVersion, Check03MtaOldVersion, Check04MtaTls,
    Check05SmtpAuth, Check06UserEnum, Check07SpoofSameDomain, Check08SpoofPunycodeHindi,
    Check09SpoofSubdomainToDomain, Check10SpoofPunycodeSubdomain, Check11SpoofSubdomainToSubdomain,
    Check12Blacklist, Check13DnsMatch
]
ALL_CHECKS = DOMAIN_WIDE_CHECKS + PER_SERVER_CHECKS
TOTAL_CHECKS = len(ALL_CHECKS)
