"""
parser.py — PASS/FAIL decision logic for SSH checks.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .commands import output_has_execution_failure

Result = Tuple[str, str]  # ("PASS"|"FAIL", explanation)

# ssh-audit output markers
_BANNER_PATTERN = re.compile(r"banner:\s*SSH-[\d\.]+-(\S+)", re.IGNORECASE)
_PROTO_V1_PATTERNS = [
    re.compile(r"SSHv1\s+enabled", re.IGNORECASE),
    re.compile(r"protocol\s+1\s+enabled", re.IGNORECASE),
    re.compile(r"--\s+\[(?:fail|warn)\].*protocol\s+1", re.IGNORECASE),
]

_ENC_LINE = re.compile(r"^\s*\(enc\)\s+(\S+)", re.MULTILINE)
_KEX_LINE = re.compile(r"^\s*\(kex\)\s+(\S+)", re.MULTILINE)
_MAC_LINE = re.compile(r"^\s*\(mac\)\s+(\S+)", re.MULTILINE)

_WEAK_ENC = re.compile(r"^\s*\(enc\)\s+.*--\s+\[(?:fail|warn)\]", re.MULTILINE | re.IGNORECASE)
_WEAK_KEX = re.compile(r"^\s*\(kex\)\s+.*--\s+\[(?:fail|warn)\]", re.MULTILINE | re.IGNORECASE)
_WEAK_MAC = re.compile(r"^\s*\(mac\)\s+.*--\s+\[(?:fail|warn)\]", re.MULTILINE | re.IGNORECASE)

# Strong algorithm whitelists (non‑exhaustive but covers common strong ones)
_STRONG_CIPHERS = {
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
}
_STRONG_KEXS = {
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
}
_STRONG_MACS = {
    "hmac-sha2-256", "hmac-sha2-512",
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
}


def _guard_execution_failure(*outputs: str) -> Optional[Result]:
    combined = " ".join(outputs)
    if output_has_execution_failure(combined):
        return (
            "FAIL",
            "Command execution failed (timeout, missing tool, etc.). "
            "Compliance cannot be verified.",
        )
    return None


def _extract_open_ports(nmap_output: str) -> list[str]:
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            ports.append(f"{m.group(1)}/{m.group(2)}")
    return ports


def parse_check_1_open_ports(nmap_output: str) -> Result:
    """Check 1: List open ports – informational, always PASS."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    ports = _extract_open_ports(nmap_output)
    if ports:
        logic = f"Open ports detected: {', '.join(ports)}"
    else:
        logic = "No open ports found."
    return ("PASS", logic)


def parse_check_2_version_visibility(ssh_audit_output: str) -> Result:
    """Check 2: SSH version not visible."""
    guard = _guard_execution_failure(ssh_audit_output)
    if guard:
        return guard
    m = _BANNER_PATTERN.search(ssh_audit_output)
    if m and re.search(r"\d+\.\d+", m.group(1)):
        return ("FAIL", f"SSH version visible in banner: {m.group(0)}")
    return ("PASS", "No version information visible in SSH banner.")


def parse_check_3_protocol_v1(ssh_audit_output: str) -> Result:
    """Check 3: SSH must NOT support protocol v1."""
    guard = _guard_execution_failure(ssh_audit_output)
    if guard:
        return guard
    for pattern in _PROTO_V1_PATTERNS:
        if pattern.search(ssh_audit_output):
            return ("FAIL", "SSH protocol version 1 is enabled (must be disabled).")
    return ("PASS", "SSH protocol version 1 not supported.")


def _check_strong_algorithm(ssh_audit_output: str, line_pattern, weak_pattern, strong_set, algo_name: str) -> Result:
    offered = set(m.group(1) for m in line_pattern.finditer(ssh_audit_output))
    has_weak = bool(weak_pattern.search(ssh_audit_output))
    has_strong = bool(offered & strong_set)

    if has_weak:
        return ("FAIL", f"Weak/deprecated {algo_name} algorithms offered.")
    if not has_strong:
        return ("FAIL", f"No strong {algo_name} algorithms found.")
    return ("PASS", f"Strong {algo_name} algorithms present.")


def parse_check_4_strong_ciphers(ssh_audit_output: str) -> Result:
    """Check 4: Strong ciphers supported."""
    return _check_strong_algorithm(
        ssh_audit_output,
        _ENC_LINE, _WEAK_ENC, _STRONG_CIPHERS,
        "encryption cipher"
    )


def parse_check_5_strong_kex(ssh_audit_output: str) -> Result:
    """Check 5: Strong key exchange algorithms supported."""
    return _check_strong_algorithm(
        ssh_audit_output,
        _KEX_LINE, _WEAK_KEX, _STRONG_KEXS,
        "key exchange"
    )


def parse_check_6_strong_mac(ssh_audit_output: str) -> Result:
    """Check 6: Strong MAC algorithms supported."""
    return _check_strong_algorithm(
        ssh_audit_output,
        _MAC_LINE, _WEAK_MAC, _STRONG_MACS,
        "MAC"
    )
