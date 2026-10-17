"""
Check definitions: base class, concrete check implementations, and integration
with the platform's CVSS and remediation services.
"""

import time
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Type, Any

from sqlalchemy.orm import Session

from .commands import CommandCache, check_tool_exists
from .parser import parse_vpn_check_output
from threat.cvss_service import get_cvss_for_check
from remediation.remediation_engine import get_remediation

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CheckContext:
    """Context passed to every check during its execution."""
    db: Session
    scan_id: int
    target: str
    port: int
    command_cache: CommandCache


@dataclass
class CheckResult:
    """Result of a single check execution."""
    check_id: str
    check_name: str
    status: str          # "PASS" or "FAIL"
    logic: str           # Human-readable explanation
    details: str         # Formatted forensic output
    command_executed: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: Optional[Any] = None
    execution_start: Optional[datetime] = None
    execution_end: Optional[datetime] = None
    execution_duration: float = 0.0


def format_forensic_output(command: str, output: str, start: datetime, end: datetime, duration: float) -> str:
    """Format the metadata into a terminal-style banner at the top."""
    return f"""=== EXECUTION INFO ===
Command: {command}
Start (UTC): {start.strftime('%Y-%m-%d %H:%M:%S.%f')}
End   (UTC): {end.strftime('%Y-%m-%d %H:%M:%S.%f')}
Duration: {duration:.2f} sec
======================

{output}"""


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class BaseVPNCheck(ABC):
    """Abstract base class for all VPN checks."""

    # Subclasses must override these
    check_id: str
    check_name: str
    command_template: str
    severity: str  # e.g., "Critical", "High", "Medium"

    def __init__(self) -> None:
        self.required_tool: Optional[str] = None  # tool to check before execution

    def get_command(self, target: str, port: int) -> str:
        """Return the formatted shell command for this check."""
        return self.command_template.format(ip=target, port=port)

    @abstractmethod
    def parse_output(self, output: str) -> Tuple[str, str]:
        """Parse raw command output → (status, logic)."""
        ...

    def run(self, ctx: CheckContext) -> CheckResult:
        """Run the check: tool check → execute command → parse → enrich."""
        # 1. Tool availability check
        if self.required_tool and not check_tool_exists(self.required_tool):
            now = datetime.now(timezone.utc)
            return CheckResult(
                check_id=self.check_id,
                check_name=self.check_name,
                status="FAIL",
                logic=f"Required tool '{self.required_tool}' is not installed.",
                details=f"Required tool '{self.required_tool}' not found.",
                command_executed="N/A",
                execution_start=now,
                execution_end=now,
                execution_duration=0.0
            )

        # 2. Execute command
        cmd = self.get_command(target=ctx.target, port=ctx.port)
        meta = ctx.command_cache.get_or_run(cmd)
        output = meta["output"]

        # 3. Parse
        status, logic = self.parse_output(output)

        # 4. Enrich with CVSS and remediation (platform services)
        try:
            # Note: platform service might expect numeric ID
            cvss_data = get_cvss_for_check(int(self.check_id), self.check_name)
            cvss_score = cvss_data.get("cvss_score")
            cvss_vector = cvss_data.get("severity") # mapping severity to vector for now
        except Exception:
            cvss_score, cvss_vector = None, None
            
        try:
            remediation = get_remediation(int(self.check_id))
        except Exception:
            remediation = None

        # Format details with forensic banner
        forensic_details = format_forensic_output(
            command=cmd,
            output=output,
            start=meta["start_time"],
            end=meta["end_time"],
            duration=meta["duration"]
        )

        return CheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            status=status,
            logic=logic,
            details=forensic_details,
            command_executed=cmd,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            remediation=remediation,
            execution_start=meta["start_time"],
            execution_end=meta["end_time"],
            execution_duration=meta["duration"]
        )


# ---------------------------------------------------------------------------
# Concrete check implementations (one per VPN check ID)
# ---------------------------------------------------------------------------

class Check01LegacyPPTP(BaseVPNCheck):
    check_id = "601"
    check_name = "Legacy PPTP protocol check"
    command_template = "sudo nmap -Pn -sU -sT -p 500,4500,1194,1723,443 {ip}"
    severity = "Medium"
    required_tool = "nmap"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


class Check02IkeAggressive(BaseVPNCheck):
    check_id = "602"
    check_name = "IKE Aggressive Mode check"
    command_template = "sudo ike-scan -A -M {ip}"
    severity = "Critical"
    required_tool = "ike-scan"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


class Check03WeakAlgorithms(BaseVPNCheck):
    check_id = "603"
    check_name = "Weak IKE/IPsec algorithms check"
    command_template = "sudo ike-scan --trans=5,2,1,2 {ip}"
    severity = "High"
    required_tool = "ike-scan"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


class Check04PptpService(BaseVPNCheck):
    check_id = "604"
    check_name = "PPTP service detection"
    command_template = "sudo nmap -Pn -sV -p 1723 --script pptp-version {ip}"
    severity = "Critical"
    required_tool = "nmap"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


class Check05SslVpnTls(BaseVPNCheck):
    check_id = "605"
    check_name = "SSL VPN TLS configuration check"
    command_template = "testssl.sh --quiet --protocols --ciphers {ip}"
    severity = "High"
    required_tool = "testssl.sh"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


class Check06VersionVisibility(BaseVPNCheck):
    check_id = "606"
    check_name = "IKE/OpenVPN version visibility"
    command_template = "sudo nmap -Pn -sU -p 500,4500,1194 --script ike-version,openvpn-info {ip}"
    severity = "Medium"
    required_tool = "nmap"

    def parse_output(self, output: str) -> Tuple[str, str]:
        return parse_vpn_check_output(self.check_id, output)


# Registry used by the engine to instantiate checks dynamically
CHECK_CLASSES: Dict[str, Type[BaseVPNCheck]] = {
    "601": Check01LegacyPPTP,
    "602": Check02IkeAggressive,
    "603": Check03WeakAlgorithms,
    "604": Check04PptpService,
    "605": Check05SslVpnTls,
    "606": Check06VersionVisibility,
}
