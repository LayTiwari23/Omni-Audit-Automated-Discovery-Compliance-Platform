"""
Target expansion utility for security scans.
Supports:
- Comma-separated values
- CIDR blocks (IPv4)
- IP ranges (e.g., 192.168.1.1-50)
- Newline-separated entries
- Mixed inputs
"""

import ipaddress
import re
from typing import List

def expand_targets(input_str: str) -> List[str]:
    """
    Expand a string containing multiple targets into a list of individual targets.
    """
    if not input_str:
        return []

    # Pre-processing: Remove spaces around / and - to handle "192.168.1.0 / 24"
    input_str = re.sub(r'\s*/\s*', '/', input_str)
    input_str = re.sub(r'\s*-\s*', '-', input_str)

    # Step 1: Normalize delimiters (newlines and commas to space)
    normalized = input_str.replace('\n', ' ').replace(',', ' ').replace('\r', ' ')
    parts = [p.strip() for p in normalized.split() if p.strip()]

    targets = []
    for part in parts:
        # Expand CIDR block
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                # Safety limit: don't expand more than 1024 IPs per block
                if net.num_addresses <= 1024:
                    # Include ALL IPs in the network (Network, Hosts, and Broadcast)
                    # This ensures coverage and matches user expectations for security tools
                    targets.extend(str(ip) for ip in net)
                    continue
            except ValueError:
                pass

        # Expand IP range (e.g., 192.168.1.1-50 or 192.168.1.1-192.168.1.50)
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start_ip = ipaddress.ip_address(start_str.strip())
                
                # Check if end_str is a full IP or just the last octet
                if '.' in end_str:
                    end_ip = ipaddress.ip_address(end_str.strip())
                else:
                    # It's just an octet
                    base_prefix = '.'.join(str(start_ip).split('.')[:-1])
                    end_ip = ipaddress.ip_address(f"{base_prefix}.{end_str.strip()}")
                
                start_int = int(start_ip)
                end_int = int(end_ip)
                
                if end_int >= start_int:
                    # Limit range size to prevent abuse (e.g. max 256 IPs per range)
                    if end_int - start_int <= 512:
                        for ip_int in range(start_int, end_int + 1):
                            targets.append(str(ipaddress.ip_address(ip_int)))
                        continue
            except ValueError:
                pass

        # Add as individual target (domain or IP)
        targets.append(part)

    # Deduplicate while preserving order
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    return unique_targets

def is_valid_target(target: str) -> bool:
    """Check if a string is a valid domain or IP."""
    # Check if IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check domain (simple regex)
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return True
        
    return False
