"""
parser.py — PASS / FAIL / INCONCLUSIVE decision logic for all email checks.
Updated to align with the specific 13 compliance requirements.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .commands import output_has_execution_failure

Result = Tuple[str, str]  # ("PASS"|"FAIL"|"INCONCLUSIVE", explanation)


def _guard_execution_failure(*outputs: str) -> Optional[Result]:
    """Return INCONCLUSIVE immediately if any output contains execution failure."""
    combined = " ".join(outputs)
    if output_has_execution_failure(combined):
        return (
            "INCONCLUSIVE",
            "Command execution failed (timeout, missing tool, etc.). "
            "Compliance cannot be verified.",
        )
    return None


def parse_open_relay(swaks_output: str, smtplib_output: str = "") -> Result:
    """
    Check 1 — Open Relay.
    PASS if relay is explicitly denied.
    """
    guard = _guard_execution_failure(swaks_output)
    if guard:
        return guard

    combined = (swaks_output + " " + smtplib_output).lower()

    # Success indicators for relay
    if "<- 250" in combined and "<- 354" in combined and "-> ." in combined:
         return "FAIL", "Server accepted and attempted to relay mail (external to external)."
    
    if "relay access denied" in combined or "550" in combined or "rejected" in combined:
        return "PASS", "Relay denied — server responded with rejection code (e.g., 550)."

    if "<- 250" in swaks_output and "ok" in combined:
        # If it reached "ok" after DATA, it's likely a relay success
        if "<- 250" in swaks_output.split("<- 354")[-1]:
             return "FAIL", "swaks confirms server accepted external relay."

    return "INCONCLUSIVE", "Could not conclusively confirm relay denial. Verify manually."


def parse_banner_version(nmap_output: str, banner_raw: str = "") -> Result:
    """
    Check 2 — SMTP Banner / Version Disclosure.
    """
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard

    combined = (nmap_output + " " + banner_raw).lower()
    
    # Check for version numbers e.g. "Postfix 3.4.13"
    version_match = re.search(r'\d+\.\d+(\.\d+)?', combined)
    
    # Common MTA names
    mta_names = ["postfix", "exim", "sendmail", "qmail", "microsoft esmtp", "hmailserver"]
    
    discloses = False
    for mta in mta_names:
        if mta in combined and version_match:
            discloses = True
            break
    
    if discloses:
        return (
            "FAIL",
            f"MTA version disclosure detected. Found: {version_match.group(0)}. Hide version in MTA configuration."
        )

    return "PASS", "No sensitive MTA version information detected in SMTP banner."


def parse_old_version(nmap_output: str, banner_raw: str = "") -> Result:
    """
    Check 3 — Old/Discontinued Version.
    (Simple heuristic: if version is disclosed, we flag it as potentially old/unmaintained).
    """
    res, msg = parse_banner_version(nmap_output, banner_raw)
    if res == "FAIL":
        return "FAIL", f"MTA software version is visible, which may indicate an old or unpatched version. {msg}"
    return res, msg


def parse_smtp_tls(openssl_output: str) -> Result:
    """
    Check 4 — TLS Support.
    """
    guard = _guard_execution_failure(openssl_output)
    if guard:
        return guard

    if "CONNECTED" in openssl_output and "SSL handshake" in openssl_output:
        return "PASS", "STARTTLS connection succeeded. MTA supports TLS."
    return "FAIL", "STARTTLS connection failed. MTA may not support TLS on port 25."


def parse_helo_auth(smtp_output: str) -> Result:
    """
    Check 5 — SMTP-AUTH Exposure Check.
    """
    guard = _guard_execution_failure(smtp_output)
    if guard:
        return guard

    lower = smtp_output.lower()
    if "auth" in lower or "smtp-auth" in lower:
        return (
            "FAIL",
            "Non-compliance: 'SMTP-AUTH' or 'AUTH' detected in EHLO response. "
            "Authentication mechanisms should be disabled on the public MX interface."
        )

    if "250" in smtp_output:
        return "PASS", "EHLO successful and no SMTP-AUTH/AUTH keywords detected."

    return "FAIL", "EHLO command did not return a successful 250 response."


def parse_vrfy(vrfy_output: str) -> Result:
    """
    Check 6 — VRFY command check (User Enumeration).
    """
    guard = _guard_execution_failure(vrfy_output)
    if guard:
        return guard

    if "250" in vrfy_output:
        return (
            "FAIL",
            "Non-compliance: VRFY command returned 250. Server allows user enumeration."
        )
    
    if "502" in vrfy_output or "550" in vrfy_output or "command not implemented" in vrfy_output.lower():
        return "PASS", f"VRFY command is disabled or rejected."

    if "252" in vrfy_output:
        return "PASS", "Server returned 252 (cannot VRFY user), which effectively prevents enumeration."

    return "INCONCLUSIVE", f"Unexpected VRFY response: {vrfy_output.strip()}"


def parse_swaks_spoofing(swaks_output: str) -> Result:
    """
    Checks 7-11 — Spoofing tests.
    FAIL if swaks reports the mail was accepted (<- 250 after DATA).
    """
    guard = _guard_execution_failure(swaks_output)
    if guard:
        return guard

    lower = swaks_output.lower()
    
    # If it was accepted for delivery
    if "<- 250" in lower and "ok" in lower and "<- 354" in lower:
        return (
            "FAIL",
            "Server accepted spoofed email."
        )

    if "denied" in lower or "550" in lower or "554" in lower or "rejected" in lower:
        return "PASS", "Spoofed email was correctly rejected by the server."

    return "INCONCLUSIVE", "Could not confirm rejection of spoofed email."


def parse_blacklist(combined_output: str) -> Result:
    """
    Check 12 — Blacklist / RBL Check.
    """
    guard = _guard_execution_failure(combined_output)
    if guard:
        return guard

    if "127.0.0." in combined_output:
        return "FAIL", "IP is listed in one or more DNSBLs (e.g., Spamhaus)."

    lower = combined_output.lower()
    if "nxdomain" in lower or combined_output.strip() == "" or not combined_output.strip():
        return "PASS", "IP not found in queried DNSBLs."

    return "PASS", "IP not found in queried DNSBLs."


def parse_reverse_dns(ptr_output: str, a_output: str) -> Result:
    """
    Check 13 — Forward-Reverse DNS Match.
    """
    guard = _guard_execution_failure(ptr_output, a_output)
    if guard:
        return guard

    ptr = ptr_output.strip().rstrip('.')
    a   = a_output.strip()
    
    if not ptr:
        return "FAIL", "No PTR record found for mail server IP."
    
    if ptr and a and (ptr in a or a in ptr):
        return "PASS", f"Forward and reverse DNS lookups match: {ptr} <=> {a}"
    
    return "FAIL", f"Forward and reverse DNS mismatch. PTR: {ptr}, A: {a}"

# Helper for engine (some might still be used internally but not as top-level 13)
def parse_spf(dig_output: str) -> Result:
    lower = dig_output.lower()
    if "v=spf1" not in lower: return "FAIL", "No SPF found."
    return "PASS", "SPF found."

def parse_dkim(dig_output: str) -> Result:
    lower = dig_output.lower()
    if "v=dkim1" in lower or "p=" in lower: return "PASS", "DKIM found."
    return "FAIL", "No DKIM found."

def parse_dmarc(dig_output: str) -> Result:
    lower = dig_output.lower()
    if "v=dmarc1" in lower: return "PASS", "DMARC found."
    return "FAIL", "No DMARC found."
