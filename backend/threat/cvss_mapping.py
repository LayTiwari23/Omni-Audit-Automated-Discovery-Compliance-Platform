"""
Local mapping for checks that don't have direct CVE IDs.
Keyed by check_id (integer) for stability.
"""

CHECK_SEVERITY_MAP = {
    # Web Engine (1-28)
    1: {"severity": "LOW", "cvss": 2.1, "description": "Open ports beyond 80/443 increase attack surface"},
    2: {"severity": "MEDIUM", "cvss": 5.3, "description": "HTTP without HTTPS allows traffic interception"},
    3: {"severity": "MEDIUM", "cvss": 5.9, "description": "HTTPS not operational or misconfigured"},
    4: {"severity": "LOW", "cvss": 2.1, "description": "Server version disclosure aids attackers"},
    5: {"severity": "LOW", "cvss": 2.1, "description": "Software version disclosure aids attackers"},
    6: {"severity": "LOW", "cvss": 2.1, "description": "ETag may leak inode information"},
    7: {"severity": "MEDIUM", "cvss": 5.3, "description": "Missing X-XSS-Protection header"},
    8: {"severity": "MEDIUM", "cvss": 5.3, "description": "Missing X-Frame-Options allows clickjacking"},
    9: {"severity": "MEDIUM", "cvss": 5.9, "description": "Missing HSTS header"},
    10: {"severity": "MEDIUM", "cvss": 5.3, "description": "Missing Content-Security-Policy header"},
    11: {"severity": "MEDIUM", "cvss": 5.3, "description": "Cookies missing HttpOnly/Secure flags"},
    12: {"severity": "MEDIUM", "cvss": 5.3, "description": "Cookies missing SameSite attribute"},
    13: {"severity": "LOW", "cvss": 2.1, "description": "Missing Cache-Control header"},
    14: {"severity": "HIGH", "cvss": 7.5, "description": "Dangerous HTTP methods enabled"},
    15: {"severity": "HIGH", "cvss": 7.5, "description": "Admin interface exposed"},
    16: {"severity": "HIGH", "cvss": 7.5, "description": "Weak TLS protocols enabled"},
    17: {"severity": "HIGH", "cvss": 7.5, "description": "Weak ciphers enabled"},
    18: {"severity": "MEDIUM", "cvss": 5.9, "description": "POODLE attack possible"},
    19: {"severity": "MEDIUM", "cvss": 5.9, "description": "Logjam attack possible"},
    20: {"severity": "CRITICAL", "cvss": 9.8, "description": "Heartbleed vulnerability", "cve": "CVE-2014-0160"},
    21: {"severity": "MEDIUM", "cvss": 5.9, "description": "CRIME attack possible"},
    22: {"severity": "MEDIUM", "cvss": 5.9, "description": "CCS injection vulnerability"},
    23: {"severity": "MEDIUM", "cvss": 5.3, "description": "Anonymous cipher vulnerability"},
    24: {"severity": "MEDIUM", "cvss": 5.9, "description": "FREAK attack possible"},
    25: {"severity": "HIGH", "cvss": 7.5, "description": "DROWN attack possible"},
    26: {"severity": "LOW", "cvss": 3.7, "description": "Forward secrecy not supported"},
    27: {"severity": "LOW", "cvss": 2.1, "description": "HTTP/1.0 accepted"},
    28: {"severity": "LOW", "cvss": 3.7, "description": "Missing CAA records"},
    
    # DNS Engine (29-40)
    29: {"severity": "MEDIUM", "cvss": 5.3, "description": "Unexpected open ports on DNS server"},
    30: {"severity": "LOW", "cvss": 2.1, "description": "DNS version disclosure"},
    31: {"severity": "HIGH", "cvss": 7.5, "description": "Open resolver (DNS amplification risk)", "cve": "CVE-2006-0987"},
    32: {"severity": "MEDIUM", "cvss": 5.3, "description": "Non‑random source ports"},
    33: {"severity": "MEDIUM", "cvss": 5.3, "description": "DNSSEC not implemented"},
    34: {"severity": "LOW", "cvss": 2.1, "description": "Weak DNSSEC algorithm"},
    35: {"severity": "LOW", "cvss": 3.7, "description": "NSEC walking possible"},
    36: {"severity": "MEDIUM", "cvss": 5.3, "description": "SPF missing -all"},
    37: {"severity": "MEDIUM", "cvss": 5.3, "description": "DMARC missing or misconfigured"},
    38: {"severity": "LOW", "cvss": 3.7, "description": "DKIM missing"},
    39: {"severity": "LOW", "cvss": 2.1, "description": "CAA records missing"},
    40: {"severity": "HIGH", "cvss": 7.5, "description": "Zone transfer allowed"},
    
    # Network Engine (301-305)
    301: {"severity": "", "cvss": 0.0, "description": "Port listing – informational"},
    302: {"severity": "HIGH", "cvss": 7.5, "description": "Management ports exposed"},
    303: {"severity": "HIGH", "cvss": 7.5, "description": "Login interface exposed"},
    304: {"severity": "", "cvss": 0.0, "description": "Service listing – informational"},
    305: {"severity": "LOW", "cvss": 2.1, "description": "Service version disclosure"},
    
    # SSH Engine (501-506)
    501: {"severity": "", "cvss": 0.0, "description": "Port listing – informational"},
    502: {"severity": "LOW", "cvss": 2.1, "description": "SSH version disclosure"},
    503: {"severity": "HIGH", "cvss": 7.5, "description": "SSH protocol 1 enabled"},
    504: {"severity": "MEDIUM", "cvss": 5.3, "description": "Weak SSH ciphers"},
    505: {"severity": "MEDIUM", "cvss": 5.3, "description": "Weak SSH key exchange"},
    506: {"severity": "MEDIUM", "cvss": 5.3, "description": "Weak SSH MAC algorithms"},
    
    # FTP Engine (401-405)
    401: {"severity": "", "cvss": 0.0, "description": "Port listing – informational"},
    402: {"severity": "MEDIUM", "cvss": 5.3, "description": "FTP service exposed"},
    403: {"severity": "LOW", "cvss": 2.1, "description": "FTP version disclosure"},
    404: {"severity": "HIGH", "cvss": 7.5, "description": "Plain FTP without encryption"},
    405: {"severity": "HIGH", "cvss": 7.5, "description": "Anonymous FTP upload allowed"},

    # New Email Compliance (1001-1013)
    1001: {"severity": "CRITICAL", "cvss": 9.8, "description": "The email server shall not function as an open relay for the internet."},
    1002: {"severity": "LOW",      "cvss": 2.1, "description": "The Mail Transfer Agent (MTA) version information shall not be disclosed."},
    1003: {"severity": "MEDIUM",   "cvss": 5.3, "description": "The MTA software shall not be an old or discontinued version."},
    1004: {"severity": "MEDIUM",   "cvss": 5.3, "description": "The MTA shall support TLS (Transport Layer Security) for secure mail transfer."},
    1005: {"severity": "MEDIUM",   "cvss": 5.9, "description": "SMTP authentication (SMTP-AUTH) shall be disabled on the public MX server."},
    1006: {"severity": "MEDIUM",   "cvss": 5.3, "description": "The mail server shall have user enumeration (e.g., VRFY command) disabled."},
    1007: {"severity": "HIGH",     "cvss": 7.5, "description": "The mail server shall block incoming emails that spoof the server's own domain."},
    1008: {"severity": "HIGH",     "cvss": 7.5, "description": "The mail server shall block incoming emails that spoof the server's own domain using Hindi Punycode characters."},
    1009: {"severity": "HIGH",     "cvss": 7.5, "description": "The mail server shall block incoming emails where a subdomain is spoofed as the primary domain."},
    1010: {"severity": "HIGH",     "cvss": 7.5, "description": "The mail server shall block incoming emails that spoof the server's own subdomain using Hindi Punycode characters."},
    1011: {"severity": "HIGH",     "cvss": 7.5, "description": "The mail server shall block incoming emails that spoof the server's own subdomain."},
    1012: {"severity": "MEDIUM",   "cvss": 5.3, "description": "The MTA shall reject mail from dynamic or poor reputation IP addresses (e.g., blacklisted in RBLs like Spamhaus)."},
    1013: {"severity": "LOW",      "cvss": 3.7, "description": "The forward and reverse DNS records for the mail server hostname must match."},

    # VPN Engine (601-606)
    601: {"severity": "MEDIUM", "cvss": 5.3, "description": "Legacy PPTP protocol (port 1723) exposed"},
    602: {"severity": "CRITICAL", "cvss": 9.8, "description": "IKE Aggressive Mode enabled (Offline dictionary attack risk)"},
    603: {"severity": "HIGH", "cvss": 7.5, "description": "Weak IKE/IPsec encryption or algorithms detected"},
    604: {"severity": "CRITICAL", "cvss": 9.1, "description": "PPTP service detected (Deprecated protocol)"},
    605: {"severity": "HIGH", "cvss": 7.5, "description": "Weak SSL/TLS configuration on SSL VPN"},
    606: {"severity": "LOW", "cvss": 2.1, "description": "IKE or OpenVPN version information disclosed"},
}

def get_local_severity(check_id: int) -> dict:
    """Return local CVSS data for a check_id."""
    return CHECK_SEVERITY_MAP.get(check_id, {"severity": "MEDIUM", "cvss": 5.0, "description": "No specific mapping"})
