"""
checks.py — DNS compliance check definitions.

Each check is a dataclass that knows:
  - its numeric ID and frozen name
  - which commands to run (via the CommandCache)
  - how to call the parser to get PASS/FAIL/INCONCLUSIVE + logic text
  - what raw_output to store per check

Usage:
    cache   = CommandCache()
    context = DnsCheckContext(domain="example.com", dns_ip="1.2.3.4", cache=cache)
    check   = Check01OpenPorts(context)
    result  = check.run()   # → CheckResult
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from threat.cvss_service import get_cvss_for_check
from remediation.remediation_engine import get_remediation
from .commands import CommandCache, NMAP_TIMEOUT, DEFAULT_TIMEOUT, output_has_execution_failure
from .parser import (
    parse_open_ports,
    parse_dns_version,
    parse_recursion,
    parse_random_srcport,
    parse_dnssec,
    parse_dnssec_algorithm,
    parse_nsec_walking,
    parse_spf,
    parse_dmarc,
    parse_dkim,
    parse_caa,
    parse_zone_transfer,
)


# ── Shared scan context ───────────────────────────────────────────────────────

@dataclass
class DnsCheckContext:
    """Passed to every check — carries target info and the shared command cache."""
    domain:   str
    dns_ip:   str
    cache:    CommandCache
    selector: str = "default"   # DKIM selector — override if known
    dns_port: int = 53


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id:         str    # "DNS-01" … "DNS-12"
    check_name:       str
    tool_name:        str
    command_executed: str
    raw_output:       str
    decision_logic:   str
    result:           str    # "PASS", "FAIL", or "INCONCLUSIVE"
    # New timing fields
    execution_start:  Optional[any] = None
    execution_end:    Optional[any] = None
    execution_duration: float = 0.0
    # New fields
    cvss_score: float = 0.0
    severity: str = ""
    cve_id: str = ""
    # New remediation fields
    remediation_text: str = ""
    remediation_example: str = ""
    remediation_reference: str = ""


# ── Base class ────────────────────────────────────────────────────────────────

class DnsCheck:
    check_id:   str = ""
    check_name: str = ""

    def __init__(self, ctx: DnsCheckContext) -> None:
        self.ctx = ctx

    def run(self) -> CheckResult:
        raise NotImplementedError


# ── Fallback helper ───────────────────────────────────────────────────────────

def _run_with_fallback(
    ctx: DnsCheckContext,
    primary_args: list[str],
    fallback_args: list[str],
    parser_func,
    tool_name: str,
    check_id: str,
    check_name: str,
) -> CheckResult:
    """
    Run primary command (against authoritative server). If it fails due to
    execution failure (timeout, no servers), retry using 8.8.8.8 fallback.
    Appends a note to decision_logic indicating fallback was used.
    """
    # Inject port if tool is dig and port is non-standard
    if primary_args[0] == "dig" and ctx.dns_port != 53:
        # Add port argument correctly for dig
        # Check if -p already exists (it shouldn't, but safety first)
        if "-p" not in primary_args:
            # dig -p <port> @<ip> <domain>
            primary_args.insert(1, "-p")
            primary_args.insert(2, str(ctx.dns_port))

    primary_cmd = " ".join(primary_args)
    primary_meta = ctx.cache.get_or_run(primary_args, timeout=DEFAULT_TIMEOUT)
    primary_out = primary_meta['output']

    if output_has_execution_failure(primary_out):
        fallback_cmd = " ".join(fallback_args)
        fallback_meta = ctx.cache.get_or_run(fallback_args, timeout=DEFAULT_TIMEOUT)
        fallback_out = fallback_meta['output']

        raw = (
            f"--- Primary (authoritative: {ctx.dns_ip}) ---\n{format_forensic_output(primary_meta)}\n\n"
            f"--- Fallback (8.8.8.8) ---\n{format_forensic_output(fallback_meta)}"
        )
        cmd_executed = f"Primary: {primary_cmd}\nFallback: {fallback_cmd}"

        result, logic = parser_func(fallback_out)
        if result == "INCONCLUSIVE":
            logic = f"Fallback resolver also failed. {logic}"
        else:
            logic = (
                f"Note: Authoritative server did not respond; "
                f"used public fallback resolver (8.8.8.8). {logic}"
            )
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            # DNS mapping: 101-112 -> 29-40
            try:
                numeric_id = int(check_id) - 101 + 29
            except:
                numeric_id = 0
            cvss_data = get_cvss_for_check(numeric_id, check_name)
            
            # Pass context for Dynamic AI Remediation if available
            finding_context = {
                "check_name": check_name,
                "raw_output": raw,
                "summary": logic
            }
            remediation = get_remediation(numeric_id, finding_details=finding_context)

        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            tool_name=tool_name,
            command_executed=cmd_executed,
            raw_output=raw,
            decision_logic=logic,
            result=result,
            cvss_score=cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id=cvss_data.get('cve_id', ''),
            remediation_text=remediation.get('fix', ''),
            remediation_example=remediation.get('example', ''),
            remediation_reference=remediation.get('reference', ''),
            execution_start=fallback_meta.get('start_time'),
            execution_end=fallback_meta.get('end_time'),
            execution_duration=fallback_meta.get('duration', 0.0)
        )
    else:
        result, logic = parser_func(primary_out)
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            try:
                numeric_id = int(check_id) - 101 + 29
            except:
                numeric_id = 0
            cvss_data = get_cvss_for_check(numeric_id, check_name)
            
            # Pass context for Dynamic AI Remediation if available
            finding_context = {
                "check_name": check_name,
                "raw_output": raw,
                "summary": logic
            }
            remediation = get_remediation(numeric_id, finding_details=finding_context)

        return CheckResult(
            check_id=check_id,
            check_name=check_name,
            tool_name=tool_name,
            command_executed=primary_cmd,
            raw_output=format_forensic_output(primary_meta),
            decision_logic=logic,
            result=result,
            cvss_score=cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id=cvss_data.get('cve_id', ''),
            remediation_text=remediation.get('fix', ''),
            remediation_example=remediation.get('example', ''),
            remediation_reference=remediation.get('reference', ''),
            execution_start=primary_meta.get('start_time'),
            execution_end=primary_meta.get('end_time'),
            execution_duration=primary_meta.get('duration', 0.0)
        )


def format_forensic_output(meta: dict) -> str:
    """Format the metadata into a terminal-style banner at the top."""
    return f"""=== EXECUTION INFO ===
Command: {meta.get('command')}
Start (UTC): {meta.get('start_time')}
End   (UTC): {meta.get('end_time')}
Duration: {meta.get('duration'):.2f} sec
======================

{meta.get('output')}"""


# ── Individual checks ─────────────────────────────────────────────────────────

class Check01OpenPorts(DnsCheck):
    check_id   = "101"
    check_name = "Open ports for DNS server other than required ports"

    def run(self) -> CheckResult:
        # Include custom port in nmap to verify it's open
        args = ["nmap", "-Pn", "-sV", "-O", "-p", str(self.ctx.dns_port), self.ctx.dns_ip]
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_open_ports(meta['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap",
            command_executed = meta['command'],
            raw_output       = format_forensic_output(meta),
            decision_logic   = logic,
            result           = result,
            execution_start  = meta['start_time'],
            execution_end    = meta['end_time'],
            execution_duration = meta['duration'],
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
        )


class Check02DnsVersion(DnsCheck):
    check_id   = "102"
    check_name = "DNS version shall not be visible"

    def run(self) -> CheckResult:
        args_nsid  = ["nmap", "-Pn", "-sU", "-p", str(self.ctx.dns_port),
                      "--script", "dns-nsid", self.ctx.dns_ip]
        args_chaos = ["dig", "-p", str(self.ctx.dns_port), f"@{self.ctx.dns_ip}", "version.bind", "chaos", "txt"]

        cmd  = " ".join(args_nsid) + "\n" + " ".join(args_chaos)
        meta1 = self.ctx.cache.get_or_run(args_nsid,  timeout=NMAP_TIMEOUT)
        meta2 = self.ctx.cache.get_or_run(args_chaos, timeout=DEFAULT_TIMEOUT)

        raw    = f"--- nmap dns-nsid ---\n{format_forensic_output(meta1)}\n\n--- dig CHAOS TXT ---\n{format_forensic_output(meta2)}"
        result, logic = parse_dns_version(meta1['output'], meta2['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap/dig",
            command_executed = cmd,
            raw_output       = raw,
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta1.get('start_time'),
            execution_end=meta2.get('end_time'),
            execution_duration=meta1.get('duration', 0.0) + meta2.get('duration', 0.0)
        )


class Check03Recursion(DnsCheck):
    check_id   = "103"
    check_name = "DNS server shall not support recursion (Open Resolver)"

    def run(self) -> CheckResult:
        args_nmap = ["nmap", "--script=dns-recursion", "-sU", "-Pn", "-p", str(self.ctx.dns_port),
                     self.ctx.dns_ip]
        args_dig  = ["dig", "-p", str(self.ctx.dns_port), "+short", "test.openresolver.com", "txt",
                     f"@{self.ctx.dns_ip}"]

        cmd  = " ".join(args_nmap) + "\n" + " ".join(args_dig)
        meta1 = self.ctx.cache.get_or_run(args_nmap, timeout=NMAP_TIMEOUT)
        meta2 = self.ctx.cache.get_or_run(args_dig,  timeout=DEFAULT_TIMEOUT)

        raw    = f"--- nmap dns-recursion ---\n{format_forensic_output(meta1)}\n\n--- dig openresolver ---\n{format_forensic_output(meta2)}"
        result, logic = parse_recursion(meta1['output'], meta2['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap/dig",
            command_executed = cmd,
            raw_output       = raw,
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta1.get('start_time'),
            execution_end=meta2.get('end_time'),
            execution_duration=meta1.get('duration', 0.0) + meta2.get('duration', 0.0)
        )


class Check04RandomSrcPort(DnsCheck):
    check_id   = "104"
    check_name = "DNS resolving servers should use random source port & transaction ID"

    def run(self) -> CheckResult:
        args = ["nmap", "-Pn", "-sU", "-p", str(self.ctx.dns_port),
                "--script", "dns-random-srcport", self.ctx.dns_ip]
        cmd  = " ".join(args)
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_random_srcport(meta['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap",
            command_executed = cmd,
            raw_output       = format_forensic_output(meta),
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta.get('start_time'),
            execution_end=meta.get('end_time'),
            execution_duration=meta.get('duration', 0.0)
        )


class Check05Dnssec(DnsCheck):
    check_id   = "105"
    check_name = "DNSSEC should be implemented"

    def run(self) -> CheckResult:
        args = ["dig", f"@{self.ctx.dns_ip}", self.ctx.domain, "+dnssec", "+multi"]
        cmd  = " ".join(args)
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_dnssec(meta['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "dig",
            command_executed = cmd,
            raw_output       = format_forensic_output(meta),
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta.get('start_time'),
            execution_end=meta.get('end_time'),
            execution_duration=meta.get('duration', 0.0)
        )


class Check06DnssecAlgorithm(DnsCheck):
    check_id   = "106"
    check_name = "DNSSEC algorithm should be RSA256 (if DNSSEC enabled)"

    def run(self) -> CheckResult:
        args = ["dig", f"@{self.ctx.dns_ip}", self.ctx.domain, "+dnssec", "+multi"]
        cmd  = " ".join(args) + "  [cached from DNS-05]"
        meta = self.ctx.cache.get_or_run(args, timeout=DEFAULT_TIMEOUT)
        result, logic = parse_dnssec_algorithm(meta['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "dig",
            command_executed = cmd,
            raw_output       = format_forensic_output(meta),
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta.get('start_time'),
            execution_end=meta.get('end_time'),
            execution_duration=meta.get('duration', 0.0)
        )


class Check07NsecWalking(DnsCheck):
    check_id   = "107"
    check_name = "NSEC walking shall be disabled"

    def run(self) -> CheckResult:
        args_nmap = ["nmap", "-Pn", "-sU", "-p", str(self.ctx.dns_port),
                     "--script", "dns-nsec-enum",
                     "--script-args", f"dns-nsec-enum.domains={self.ctx.domain}",
                     self.ctx.dns_ip]
        args_rec  = ["dnsrecon", "-d", self.ctx.domain, "-n", "8.8.8.8"]

        cmd  = " ".join(args_nmap) + "\n" + " ".join(args_rec)
        meta1 = self.ctx.cache.get_or_run(args_nmap, timeout=NMAP_TIMEOUT)
        meta2 = self.ctx.cache.get_or_run(args_rec,  timeout=DEFAULT_TIMEOUT)

        raw    = f"--- nmap dns-nsec-enum ---\n{format_forensic_output(meta1)}\n\n--- dnsrecon ---\n{format_forensic_output(meta2)}"
        result, logic = parse_nsec_walking(meta1['output'], meta2['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap/dnsrecon",
            command_executed = cmd,
            raw_output       = raw,
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta1.get('start_time'),
            execution_end=meta2.get('end_time'),
            execution_duration=meta1.get('duration', 0.0) + meta2.get('duration', 0.0)
        )


class Check08Spf(DnsCheck):
    check_id   = "108"
    check_name = 'SPF record shall be published with "-all"'

    def run(self) -> CheckResult:
        return _run_with_fallback(
            ctx=self.ctx,
            primary_args=["dig", f"@{self.ctx.dns_ip}", self.ctx.domain, "TXT"],
            fallback_args=["dig", "@8.8.8.8", self.ctx.domain, "TXT"],
            parser_func=parse_spf,
            tool_name="dig",
            check_id=self.check_id,
            check_name=self.check_name,
        )


class Check09Dmarc(DnsCheck):
    check_id   = "109"
    check_name = "DMARC record shall be published"

    def run(self) -> CheckResult:
        return _run_with_fallback(
            ctx=self.ctx,
            primary_args=["dig", f"@{self.ctx.dns_ip}", f"_dmarc.{self.ctx.domain}", "TXT"],
            fallback_args=["dig", "@8.8.8.8", f"_dmarc.{self.ctx.domain}", "TXT"],
            parser_func=parse_dmarc,
            tool_name="dig",
            check_id=self.check_id,
            check_name=self.check_name,
        )


class Check10Dkim(DnsCheck):
    check_id   = "110"
    check_name = "DKIM record shall be published"

    def run(self) -> CheckResult:
        return _run_with_fallback(
            ctx=self.ctx,
            primary_args=[
                "dig", f"@{self.ctx.dns_ip}",
                f"{self.ctx.selector}._domainkey.{self.ctx.domain}", "TXT"
            ],
            fallback_args=[
                "dig", "@8.8.8.8",
                f"{self.ctx.selector}._domainkey.{self.ctx.domain}", "TXT"
            ],
            parser_func=parse_dkim,
            tool_name="dig",
            check_id=self.check_id,
            check_name=self.check_name,
        )


class Check11Caa(DnsCheck):
    check_id   = "111"
    check_name = "CAA record should be published"

    def run(self) -> CheckResult:
        return _run_with_fallback(
            ctx=self.ctx,
            primary_args=["dig", f"@{self.ctx.dns_ip}", "CAA", self.ctx.domain],
            fallback_args=["dig", "@8.8.8.8", "CAA", self.ctx.domain],
            parser_func=parse_caa,
            tool_name="dig",
            check_id=self.check_id,
            check_name=self.check_name,
        )


class Check12ZoneTransfer(DnsCheck):
    check_id   = "112"
    check_name = "Unprotected DNS zone transfer must be disabled"

    def run(self) -> CheckResult:
        args = [
            "nmap", "-sn", "-Pn", "-p", str(self.ctx.dns_port),
            "--script", "dns-zone-transfer",
            "--script-args", f"dns-zone-transfer.domain={self.ctx.domain}",
            self.ctx.dns_ip,
        ]
        cmd  = " ".join(args)
        meta = self.ctx.cache.get_or_run(args, timeout=NMAP_TIMEOUT)
        result, logic = parse_zone_transfer(meta['output'])
        
        cvss_data = {}
        remediation = {}
        if result in ["FAIL", "INCONCLUSIVE"]:
            numeric_id = int(self.check_id) - 101 + 29
            cvss_data = get_cvss_for_check(numeric_id, self.check_name)
            remediation = get_remediation(numeric_id)

        return CheckResult(
            check_id         = self.check_id,
            check_name       = self.check_name,
            tool_name        = "nmap",
            command_executed = cmd,
            raw_output       = format_forensic_output(meta),
            decision_logic   = logic,
            result           = result,
            cvss_score       = cvss_data.get('cvss_score', 0.0),
            severity=cvss_data.get('severity', ''),
            cve_id           = cvss_data.get('cve_id', ''),
            remediation_text = remediation.get('fix', ''),
            remediation_example = remediation.get('example', ''),
            remediation_reference = remediation.get('reference', ''),
            execution_start=meta.get('start_time'),
            execution_end=meta.get('end_time'),
            execution_duration=meta.get('duration', 0.0)
        )


# ── Registry ──────────────────────────────────────────────────────────────────

ALL_CHECKS: list[type[DnsCheck]] = [
    Check01OpenPorts,
    Check02DnsVersion,
    Check03Recursion,
    Check04RandomSrcPort,
    Check05Dnssec,
    Check06DnssecAlgorithm,
    Check07NsecWalking,
    Check08Spf,
    Check09Dmarc,
    Check10Dkim,
    Check11Caa,
    Check12ZoneTransfer,
]

TOTAL_CHECKS = len(ALL_CHECKS)  # 12
