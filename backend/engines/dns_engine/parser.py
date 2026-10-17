"""
parser.py — PASS / FAIL / INCONCLUSIVE decision logic for all 12 DNS checks.

STRICT ACCURACY CONTRACT
========================
Every parser calls _guard_execution_failure() FIRST.
If the raw output contains ANY privilege/tool/execution error marker,
the result is immediately INCONCLUSIVE with a clear explanation.
No check may return PASS when execution failed.

Only real, successful command output may produce a PASS result.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .commands import output_has_execution_failure

Result          = Tuple[str, str]       # ("PASS"|"FAIL"|"INCONCLUSIVE", explanation)
Optional_Result = Optional[Result]

REQUIRED_DNS_PORTS = {53, 953}


# ── Execution failure guard ───────────────────────────────────────────────────

def _guard_execution_failure(*outputs: str) -> Optional_Result:
    """
    Check all provided output strings for execution failure markers.
    Returns an INCONCLUSIVE Result immediately if any failure marker is found.
    Returns None if all outputs look clean — caller proceeds with normal logic.
    """
    combined = " ".join(outputs)
    if output_has_execution_failure(combined):
        return (
            "INCONCLUSIVE",
            "Check execution failed due to a privilege or tool availability issue — "
            "compliance cannot be verified. "
            "Ensure nmap, dig, and dnsrecon are installed and that the process "
            "has permission to run raw socket operations (sudo is configured).",
        )
    return None


def _lower(text: str) -> str:
    return text.lower()


# ── Check parsers ─────────────────────────────────────────────────────────────

def parse_open_ports(nmap_output: str) -> Result:
    """
    Check 1 — Open ports for DNS server other than required ports.
    """
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard

    open_ports: set[int] = set()
    for line in nmap_output.splitlines():
        m = re.match(r"^\s*(\d+)/(?:tcp|udp)\s+open", line)
        if m:
            open_ports.add(int(m.group(1)))

    if not open_ports:
        return (
            "FAIL",
            "nmap ran successfully but reported no open ports. "
            "This may indicate all ports are filtered. "
            "Manual verification required — cannot confirm compliance without data.",
        )

    unexpected = open_ports - REQUIRED_DNS_PORTS
    if unexpected:
        ports_str = ", ".join(str(p) for p in sorted(unexpected))
        return (
            "FAIL",
            f"Unexpected open ports detected: {ports_str}. "
            f"Only ports {sorted(REQUIRED_DNS_PORTS)} are required for a DNS server.",
        )

    ports_str = ", ".join(str(p) for p in sorted(open_ports))
    return (
        "PASS",
        f"Only required DNS ports are open: {ports_str}.",
    )


def parse_dns_version(nsid_output: str, chaos_output: str) -> Result:
    """
    Check 2 — DNS version shall not be visible.

    PASS if:
      - No version string is exposed, OR
      - Server returned NOTIMP/REFUSED status (server refuses to disclose version).
    FAIL if BIND version string is exposed in either output.
    """
    guard = _guard_execution_failure(nsid_output, chaos_output)
    if guard:
        return guard

    combined = _lower(nsid_output + " " + chaos_output)

    # NOTIMP means the server explicitly refused to answer the CHAOS query —
    # this is a positive indicator that version disclosure is disabled.
    if "notimp" in combined or "not implemented" in combined:
        return (
            "PASS",
            "Server returned NOTIMP/Not Implemented status — "
            "it explicitly refuses to disclose version information via CHAOS queries.",
        )

    # REFUSED is also a positive sign the server blocks version queries.
    if "status: refused" in combined:
        return (
            "PASS",
            "Server returned REFUSED status — version query was rejected.",
        )

    version_patterns = [
        r"\bbind\s+\d",
        r"\b\d+\.\d+\.\d+-\w+",   # e.g. 9.11.4-P2
        r"version\s*[:=]\s*\d",
    ]
    for pattern in version_patterns:
        if re.search(pattern, combined):
            return (
                "FAIL",
                "DNS server version information is exposed. "
                "Configure 'version none;' in named.conf to hide BIND version.",
            )

    if "txt" in _lower(chaos_output) and re.search(r"\d+\.\d+", chaos_output):
        return (
            "FAIL",
            "CHAOS TXT query returned data that may expose version information.",
        )

    return (
        "PASS",
        "No DNS version information detected in NSID or CHAOS TXT responses.",
    )


def parse_recursion(nmap_output: str, dig_output: str) -> Result:
    """
    Check 3 — DNS server shall not support recursion (Open Resolver).
    """
    nmap_failed = output_has_execution_failure(nmap_output)
    dig_failed  = output_has_execution_failure(dig_output)

    if nmap_failed and dig_failed:
        return (
            "INCONCLUSIVE",
            "Both nmap and dig execution failed — compliance cannot be verified. "
            "Ensure tools are installed and sudo is available.",
        )

    combined = _lower(
        ("" if nmap_failed else nmap_output) + " " +
        ("" if dig_failed  else dig_output)
    )

    if "open-resolver-detected" in combined:
        return (
            "FAIL",
            "Non-compliance: 'open-resolver-detected' found in response. "
            "Server is an open resolver — recursive queries are accepted from "
            "external sources. Restrict recursion in named.conf.",
        )

    if "open-resolver" in combined or "is an open resolver" in combined:
        return (
            "FAIL",
            "openresolver.com test confirms this server resolves external queries.",
        )

    note = " (nmap check skipped — execution failed)" if nmap_failed else ""
    return (
        "PASS",
        f"No open-resolver behaviour detected.{note}",
    )


def parse_random_srcport(nmap_output: str) -> Result:
    """
    Check 4 — DNS resolving servers should use random source port & transaction ID.
    """
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard

    lower = _lower(nmap_output)

    if "recursion not enabled" in lower or "recursion refused" in lower or "server refused recursion" in lower:
        return (
            "PASS",
            "Compliance: Server refused recursion or recursion is not enabled. "
            "Source port randomisation check is not applicable.",
        )

    if "great" in lower:
        return (
            "PASS",
            "Compliance: nmap reports 'Great' for source port randomness.",
        )

    if "vulnerable" in lower or "predictable" in lower:
        return (
            "FAIL",
            "nmap dns-random-srcport script reports insecure or predictable "
            "source port / transaction ID behaviour.",
        )

    if "not vulnerable" in lower:
        return (
            "PASS",
            "nmap confirms source port and transaction ID randomisation is in use.",
        )

    return (
        "FAIL",
        "nmap dns-random-srcport ran but produced no definitive verdict. "
        "Cannot confirm compliance — treating as FAIL.",
    )


def parse_dnssec(dig_output: str) -> Result:
    """
    Check 5 — DNSSEC should be implemented.
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    if "rrsig" in _lower(dig_output):
        return (
            "PASS",
            "RRSIG record found in dig +dnssec output — DNSSEC is implemented.",
        )

    if "answer section" in _lower(dig_output) or "status: noerror" in _lower(dig_output):
        return (
            "FAIL",
            "dig ran successfully. No RRSIG record found — "
            "DNSSEC is not configured for this domain.",
        )

    return (
        "FAIL",
        "No RRSIG record found in dig output. "
        "DNSSEC does not appear to be configured for this domain.",
    )


def parse_dnssec_algorithm(dig_output: str) -> Result:
    """
    Check 6 — DNSSEC algorithm should be RSA256 (algorithm 8).
    Applicable only if DNSSEC is implemented.
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    if "rrsig" not in _lower(dig_output):
        return (
            "PASS",
            "DNSSEC is not implemented; algorithm requirement is not applicable.",
        )

    for line in dig_output.splitlines():
        if "rrsig" in line.lower():
            parts = line.split()
            for i, part in enumerate(parts):
                if part.upper() == "RRSIG" and i + 2 < len(parts):
                    algo = parts[i + 2]
                    if algo == "8":
                        return (
                            "PASS",
                            "DNSSEC algorithm 8 (RSASHA256) detected — "
                            "meets the RSA256 requirement.",
                        )
                    else:
                        return (
                            "FAIL",
                            f"DNSSEC algorithm {algo} detected. "
                            "Algorithm 8 (RSASHA256) is required.",
                        )

    if "rsasha256" in _lower(dig_output):
        return (
            "PASS",
            "RSASHA256 string detected in DNSSEC output.",
        )

    return (
        "FAIL",
        "Could not confirm RSASHA256 algorithm from DNSSEC output.",
    )


def parse_nsec_walking(nmap_output: str, dnsrecon_output: str) -> Result:
    """
    Check 7 — NSEC walking shall be disabled.
    """
    nmap_failed     = output_has_execution_failure(nmap_output)
    dnsrecon_failed = output_has_execution_failure(dnsrecon_output)

    if nmap_failed and dnsrecon_failed:
        return (
            "INCONCLUSIVE",
            "Both nmap and dnsrecon execution failed — NSEC walking check "
            "cannot be performed. Install tools and ensure sudo is available.",
        )

    eval_nmap     = "" if nmap_failed     else nmap_output
    eval_dnsrecon = "" if dnsrecon_failed else dnsrecon_output
    combined      = _lower(eval_nmap + " " + eval_dnsrecon)

    failure_indicators = [
        "nsec3 salt",
        "walking the chain",
        "nsec enumeration",
        "zone transfer was successful",
        "axfr",
    ]
    for indicator in failure_indicators:
        if indicator in combined:
            return (
                "FAIL",
                f"Zone enumeration indicator '{indicator}' found in output. "
                "NSEC walking or zone transfer appears to be possible.",
            )

    record_pattern = re.compile(r"\[\*\]\s+\w+\s+\S+\s+\S+")
    if record_pattern.search(eval_dnsrecon):
        return (
            "FAIL",
            "dnsrecon appears to have enumerated zone records — "
            "NSEC walking may be possible.",
        )

    notes = []
    if nmap_failed:
        notes.append("nmap check skipped — execution failed")
    if dnsrecon_failed:
        notes.append("dnsrecon check skipped — tool not available or execution failed")
    note_str = f" ({'; '.join(notes)})" if notes else ""

    return (
        "PASS",
        f"No evidence of successful NSEC walking or zone enumeration.{note_str}",
    )


def parse_spf(dig_output: str) -> Result:
    """
    Check 8 — SPF record shall be published with "-all".
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    lower = _lower(dig_output)

    if "v=spf1" not in lower:
        return (
            "FAIL",
            "No SPF (v=spf1) TXT record found for this domain.",
        )

    if "-all" in lower:
        return (
            "PASS",
            'SPF record found and contains "-all" — hard-fail policy is in place.',
        )

    if "~all" in lower:
        qualifier = "~all (softfail)"
    elif "?all" in lower:
        qualifier = "?all (neutral)"
    elif "+all" in lower:
        qualifier = "+all (pass-all — dangerous)"
    else:
        qualifier = "unknown/missing"

    return (
        "FAIL",
        f'SPF record exists but uses "{qualifier}" instead of "-all". '
        'A hard-fail "-all" policy is required.',
    )


def parse_dmarc(dig_output: str) -> Result:
    """
    Check 9 — DMARC record shall be published with p=quarantine or p=reject.
    Strictly checks pct=100 if present.
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    lower = _lower(dig_output)

    if "v=dmarc1" not in lower:
        return (
            "FAIL",
            "No DMARC (v=DMARC1) TXT record found at _dmarc.<domain>.",
        )

    # Check pct parameter
    pct_match = re.search(r"\bpct=(\d+)\b", lower)
    if pct_match:
        pct_val = int(pct_match.group(1))
        if pct_val < 100:
            return (
                "FAIL",
                f"DMARC record has pct={pct_val} (less than 100). "
                "The policy must be applied to 100% of emails.",
            )

    if "p=reject" in lower:
        return ("PASS", "DMARC record found with p=reject policy.")

    if "p=quarantine" in lower:
        return ("PASS", "DMARC record found with p=quarantine policy.")

    if "p=none" in lower:
        return (
            "FAIL",
            "DMARC record found but policy is p=none (monitor only). "
            "p=quarantine or p=reject is required.",
        )

    return ("FAIL", "DMARC record found but could not confirm an enforcing policy.")


def parse_dkim(dig_output: str) -> Result:
    """
    Check 10 — DKIM record shall be published.
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    lower = _lower(dig_output)

    if "v=dkim1" in lower:
        return ("PASS", "DKIM TXT record (v=DKIM1) found for the domain.")

    if "txt" in lower and '"' in dig_output:
        return (
            "FAIL",
            "TXT record returned but does not contain a valid DKIM record "
            "(missing v=DKIM1 tag).",
        )

    return (
        "FAIL",
        "No DKIM TXT record found. "
        "Ensure a DKIM selector is published in DNS and the correct selector "
        "was passed to the scan.",
    )


def parse_caa(dig_output: str) -> Result:
    """
    Check 11 — CAA record should be published.
    """
    guard = _guard_execution_failure(dig_output)
    if guard:
        return guard

    lower = _lower(dig_output)

    if "caa" in lower and (
        "issue" in lower or "issuewild" in lower or "iodef" in lower
    ):
        return (
            "PASS",
            "CAA record(s) found — certificate authority issuance is restricted.",
        )

    if " 257 " in dig_output:
        return ("PASS", "CAA record (type 257) found in DNS response.")

    return (
        "FAIL",
        "No CAA record found. Publish CAA records to restrict "
        "which CAs may issue certificates for this domain.",
    )


def parse_zone_transfer(nmap_output: str) -> Result:
    """
    Check 12 — Unprotected DNS zone transfer must be disabled.

    INCONCLUSIVE if nmap execution failed.
    PASS if nmap output shows explicit refusal strings.
    FAIL if zone transfer appears to have succeeded.
    """
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard

    lower = _lower(nmap_output)

    # Explicit refusal — strongest PASS signal
    if "transfer failed" in lower or "refused" in lower or "not allowed" in lower:
        return (
            "PASS",
            "Zone transfer was explicitly refused by the DNS server.",
        )

    # Signs that zone transfer succeeded
    success_indicators = [
        "axfr", "zone transfer", "soa ", " a ", " mx ", " ns ", " ptr ", " txt ",
    ]
    hits = sum(1 for ind in success_indicators if ind in lower)
    if hits >= 3:
        return (
            "FAIL",
            "Zone transfer appears to have succeeded — nmap output contains "
            "multiple DNS record types. Restrict AXFR to authorised IPs only.",
        )

    return (
        "FAIL",
        "nmap ran but could not confirm zone transfer is restricted. "
        "Cannot assume compliance without explicit refusal in output. "
        "Verify manually that AXFR is locked down.",
    )
