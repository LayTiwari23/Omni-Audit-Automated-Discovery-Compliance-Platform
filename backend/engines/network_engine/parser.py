"""
parser.py — PASS/FAIL decision logic for UTM/Switch/Router checks.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .commands import output_has_execution_failure

Result = Tuple[str, str]  # ("PASS"|"FAIL", explanation)

# Ports considered management / login interfaces
MANAGEMENT_PORTS = {22, 80, 443}
LOGIN_PORTS = {80, 443}


def _guard_execution_failure(*outputs: str) -> Optional[Result]:
    combined = " ".join(outputs)
    if output_has_execution_failure(combined):
        return (
            "FAIL",
            "Command execution failed (timeout, missing tool, etc.). "
            "Compliance cannot be verified.",
        )
    return None


def _extract_open_ports(raw: str) -> list[dict]:
    """Return list of {port, service} dicts for all open TCP ports."""
    results = []
    for line in raw.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            results.append({"port": int(m.group(1)), "service": m.group(2)})
    return results


def _versions_visible(raw: str) -> list[str]:
    """Return list of version strings found in nmap output."""
    visible = []
    for line in raw.splitlines():
        # Look for lines like "80/tcp open  http  Apache httpd 2.4.41"
        m = re.search(r"^(\d+)/tcp\s+open\s+\S+\s+(.+)$", line)
        if m:
            version_str = m.group(2).strip()
            if re.search(r"\d+\.\d+", version_str):
                visible.append(version_str)
    return visible


def parse_check_1_open_ports(raw: str) -> Result:
    """Check 1: List open ports – informational, always PASS."""
    guard = _guard_execution_failure(raw)
    if guard:
        return guard
    ports = _extract_open_ports(raw)
    if ports:
        port_list = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
        logic = f"Open ports detected: {port_list}"
    else:
        logic = "No open ports found or scan incomplete."
    return ("PASS", logic)


def parse_check_2_management_ports(raw: str) -> Result:
    """Check 2: Management ports (22,80,443) should not be accessible."""
    guard = _guard_execution_failure(raw)
    if guard:
        return guard
    exposed = [p for p in _extract_open_ports(raw) if p["port"] in MANAGEMENT_PORTS]
    if exposed:
        ports = ", ".join(str(p["port"]) for p in exposed)
        return ("FAIL", f"Management ports accessible: {ports}")
    return ("PASS", "No management ports exposed.")


def parse_check_3_login_interface(raw: str) -> Result:
    """Check 3: Login interface (80/443) should not be visible."""
    guard = _guard_execution_failure(raw)
    if guard:
        return guard
    login_ports = [p for p in _extract_open_ports(raw) if p["port"] in LOGIN_PORTS]
    if login_ports:
        ports = ", ".join(str(p["port"]) for p in login_ports)
        return ("FAIL", f"Login interface ports accessible: {ports}")
    return ("PASS", "No login interfaces exposed.")


def parse_check_4_observed_services(raw: str) -> Result:
    """Check 4: List observed services – informational, always PASS."""
    guard = _guard_execution_failure(raw)
    if guard:
        return guard
    services = _extract_open_ports(raw)
    if services:
        service_list = ", ".join(f"{s['port']}/{s['service']}" for s in services)
        logic = f"Services detected: {service_list}"
    else:
        logic = "No services detected on scanned ports."
    return ("PASS", logic)


def parse_check_5_version_visibility(raw: str) -> Result:
    """Check 5: Service version should not be visible."""
    guard = _guard_execution_failure(raw)
    if guard:
        return guard
    versions = _versions_visible(raw)
    if versions:
        return ("FAIL", f"Version strings visible: {versions}")
    return ("PASS", "No version information visible.")
