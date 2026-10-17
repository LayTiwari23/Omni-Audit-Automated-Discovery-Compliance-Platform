"""
Output parser for VPN security checks.
Each check returns (status: "PASS" | "FAIL", logic: str)
"""

import re
from typing import Literal, Tuple

Status = Literal["PASS", "FAIL"]


def parse_vpn_check_output(check_name: str, output: str) -> Tuple[Status, str]:
    """
    Parse the raw command output and determine pass/fail based on the check name.
    """
    # Check for obvious execution failures
    if "QUITTING!" in output or "Command timed out" in output or "Command not found" in output:
        return ("FAIL", f"Check execution failed: {output.strip().splitlines()[0]}")

    # Normalise newlines for consistent regex matching
    output = output.replace("\r\n", "\n").replace("\r", "\n")

    if check_name == "601":
        # Look for PPTP (port 1723) being open → legacy, high-risk
        if re.search(r"1723/(tcp|udp)\s+open", output):
            return ("FAIL", "PPTP port 1723 is open – deprecated legacy protocol exposed.")
        # If any expected VPN port is open it's okay (Medium severity note)
        if re.search(r"(500|4500|1194|443)/(tcp|udp)\s+open", output):
            return ("PASS", "VPN services detected, no legacy PPTP exposure.")
        return ("PASS", "No VPN-related open ports found.")

    elif check_name == "602":
        # ike-scan with Aggressive Mode: look for "Aggressive Mode" in handshake
        if re.search(r"Aggressive\s+Mode", output, re.IGNORECASE):
            return ("FAIL", "IKE Aggressive Mode is enabled – susceptible to offline dictionary attacks.")
        return ("PASS", "IKE Aggressive Mode is not enabled.")

    elif check_name == "603":
        # Detect weak IKE ciphers/algorithms. The output of ike-scan --trans contains
        # SA=(Enc=... Hash=... Auth=... Group=...) lines.
        weak_enc = re.search(r"Enc=(DES|3DES)", output, re.IGNORECASE)
        weak_hash = re.search(r"Hash=(MD5|SHA1)", output, re.IGNORECASE)
        weak_dh = re.search(r"Group=(1|2)\b", output)
        if weak_enc or weak_hash or weak_dh:
            reasons = []
            if weak_enc:
                reasons.append(f"weak encryption: {weak_enc.group(1)}")
            if weak_hash:
                reasons.append(f"weak hash: {weak_hash.group(1)}")
            if weak_dh:
                reasons.append(f"weak DH group: {weak_dh.group(1)}")
            return ("FAIL", "Weak IKE/IPsec algorithms detected: " + ", ".join(reasons) + ".")
        return ("PASS", "No weak IKE/IPsec algorithms detected.")

    elif check_name == "604":
        # nmap pptp-version script: any output indicates PPTP service
        if re.search(r"PPTP", output, re.IGNORECASE) and "version" in output.lower():
            return ("FAIL", "PPTP service detected – deprecated VPN protocol should be disabled.")
        return ("PASS", "PPTP service not detected.")

    elif check_name == "605":
        # testssl.sh output for SSL/TLS: look for weak protocols
        weak_protocols = re.findall(
            r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s", output
        )
        # Also check for weak ciphers (simple presence of 'EXP' or 'NULL')
        weak_cipher = re.search(r"\b(EXP|NULL|ADH|aNULL)\b", output, re.IGNORECASE)
        if weak_protocols or weak_cipher:
            fail_reason = []
            if weak_protocols:
                fail_reason.append(f"weak protocol(s): {', '.join(set(weak_protocols))}")
            if weak_cipher:
                fail_reason.append("weak cipher(s) detected")
            return ("FAIL", "SSL VPN weak TLS configuration: " + "; ".join(fail_reason) + ".")
        return ("PASS", "SSL VPN TLS configuration appears strong (no known weak protocols/ciphers).")

    elif check_name == "606":
        # ike-version and openvpn-info: version visibility
        has_ike_ver = "IKE version" in output
        has_openvpn = "OpenVPN" in output
        if has_ike_ver or has_openvpn:
            details = []
            if has_ike_ver:
                details.append("IKE version information exposed")
            if has_openvpn:
                details.append("OpenVPN version information exposed")
            return ("FAIL", "Version visibility: " + ", ".join(details) + ".")
        return ("PASS", "No IKE or OpenVPN version information exposed.")

    else:
        # Unknown check – default to PASS with a note
        return ("PASS", f"No parser defined for check {check_name}.")
