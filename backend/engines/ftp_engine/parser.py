"""
parser.py — PASS/FAIL decision logic for FTP checks.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .commands import output_has_execution_failure

Result = Tuple[str, str]  # ("PASS"|"FAIL", explanation)

# Patterns
_PORT_LINE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)
_FTP_OPEN = re.compile(r"^21/tcp\s+open\s+ftp", re.MULTILINE | re.IGNORECASE)
_FTP_VERSION = re.compile(r"^21/tcp\s+open\s+ftp\s+\S+\s+(.+)$", re.MULTILINE | re.IGNORECASE)
_ANON_ALLOWED = re.compile(r"Anonymous FTP login allowed", re.IGNORECASE)
_ANON_WRITE = re.compile(r"(?:READ/WRITE|WRITE)", re.IGNORECASE)
_FTPS_PORT = re.compile(r"^990/tcp\s+open", re.MULTILINE | re.IGNORECASE)
_SFTP_SERVICE = re.compile(r"sftp", re.IGNORECASE)


def _guard_execution_failure(*outputs: str) -> Optional[Result]:
    combined = " ".join(outputs)
    if output_has_execution_failure(combined):
        return (
            "FAIL",
            "Command execution failed (timeout, missing tool, etc.). "
            "Compliance cannot be verified.",
        )
    return None


def _open_ports(raw_nmap: str) -> list[str]:
    ports = []
    for m in _PORT_LINE.finditer(raw_nmap):
        ports.append(f"{m.group(1)}/{m.group(2)}")
    return ports


def _ftp_is_open(raw: str) -> bool:
    return bool(_FTP_OPEN.search(raw))


def _ftp_version_string(raw: str) -> str | None:
    m = _FTP_VERSION.search(raw)
    if m:
        v = m.group(1).strip()
        if re.search(r"\d+[\.\d]*", v):
            return v
    return None


def _anonymous_login_allowed(raw: str) -> bool:
    return bool(_ANON_ALLOWED.search(raw))


def _anonymous_upload_allowed(raw: str) -> bool:
    return _anonymous_login_allowed(raw) and bool(_ANON_WRITE.search(raw))


def _secure_channel_available(raw_full: str) -> bool:
    return bool(_FTPS_PORT.search(raw_full)) or bool(_SFTP_SERVICE.search(raw_full))


def parse_check_1_open_ports(nmap_output: str) -> Result:
    """Check 1: List open ports – informational, always PASS."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    ports = _open_ports(nmap_output)
    if ports:
        logic = f"Open ports detected: {', '.join(ports)}"
    else:
        logic = "No open ports found."
    return ("PASS", logic)


def parse_check_2_ftp_availability(nmap_output: str) -> Result:
    """Check 2: FTP service availability – PASS if port 21 open."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    if _ftp_is_open(nmap_output):
        return ("PASS", "FTP service is available on port 21.")
    return ("FAIL", "FTP port 21 is not open or not reachable.")


def parse_check_3_ftp_version(nmap_output: str) -> Result:
    """Check 3: FTP version not visible – FAIL if version string found."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    version = _ftp_version_string(nmap_output)
    if version:
        return ("FAIL", f"FTP version visible in banner: {version}")
    return ("PASS", "No FTP version information visible.")


def parse_check_4_secure_channel(nmap_output: str) -> Result:
    """Check 4: FTP over secure channel – PASS if FTPS/SFTP detected."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    secure = _secure_channel_available(nmap_output)
    if secure:
        return ("PASS", "Secure FTP channel (FTPS or SFTP) detected.")
    return ("FAIL", "Only plain FTP detected – no secure channel found.")


def parse_check_5_anonymous_upload(nmap_output: str) -> Result:
    """Check 5: Anonymous upload not allowed – FAIL if anonymous write possible."""
    guard = _guard_execution_failure(nmap_output)
    if guard:
        return guard
    if _anonymous_upload_allowed(nmap_output):
        return ("FAIL", "Anonymous FTP upload is allowed – critical risk.")
    if _anonymous_login_allowed(nmap_output):
        return ("FAIL", "Anonymous FTP login is allowed (read access).")
    return ("PASS", "Anonymous FTP login is not allowed.")
