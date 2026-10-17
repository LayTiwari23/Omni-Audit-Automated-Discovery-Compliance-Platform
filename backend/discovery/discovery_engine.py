import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Union, Callable, Optional

COMMON_PORTS = "21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,8080,8443"

async def _run_nmap(target: str, log_callback: Optional[Callable[[str, str], None]] = None) -> str:
    """Async nmap scan on target."""
    # Use -sT -Pn as requested. -T4 for speed.
    # Removed -p COMMON_PORTS to scan top 1000 ports. Added --reason for filtered diagnosis.
    cmd = [
        "nmap", "-sT", "-Pn", "-T4", "--reason", target
    ]
    command_str = " ".join(cmd)
    
    start_time = datetime.now()
    if log_callback:
        log_callback("EXEC", f"Executing discovery: {command_str}")
        
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        full_output = []
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            line_str = line.decode('utf-8', errors='ignore')
            full_output.append(line_str)
            
            if log_callback:
                # Log EVERY line for terminal feel
                log_callback("LIVE", f"[{target}] {line_str.strip()}")
        
        # Also wait for the process to fully exit
        await process.wait()
        end_time = datetime.now()
        output = "".join(full_output)
        
        if log_callback:
             # Final terminal block
             meta = {
                 "command": command_str,
                 "start_time": start_time.isoformat(),
                 "end_time": end_time.isoformat(),
                 "duration": (end_time - start_time).total_seconds(),
                 "output": output
             }
             from engines.dns_engine.commands import format_terminal_output
             log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
             log_callback("LIVE", f"[{command_str}] Discovery finished for {target}")
             
        return output
    except asyncio.TimeoutError:
        return f"Timeout scanning {target}"
    except Exception as e:
        return f"Error scanning {target}: {e}"

def _parse_nmap_standard(output: str) -> List[str]:
    """Parse standard nmap output to extract open/filtered services."""
    services = set()
    
    # Improved regex to handle optional leading whitespace and varied spacing
    # (\d+) - Port number
    # /(tcp|udp) - Protocol
    # \s+(open|filtered|open\|filtered) - State
    # \s+(\S+) - Service name
    port_pattern = re.compile(r"^\s*(\d+)/(tcp|udp)\s+(open|filtered|open\|filtered)\s+(\S+)", re.IGNORECASE)
    
    for line in output.splitlines():
        match = port_pattern.search(line)
        if match:
            port = int(match.group(1))
            service = match.group(4).lower()
            
            # Normalize and prioritize
            if any(x in service for x in ("http", "ssl", "web")) or port in (80, 443, 8080, 8443):
                services.add('http')
            elif any(x in service for x in ("domain", "dns")) or port == 53:
                services.add('dns')
            elif any(x in service for x in ("smtp", "smtps", "pop3", "imap")) or port in (25, 465, 587, 110, 143, 993, 995):
                services.add('smtp')
            elif service == 'ssh' or port == 22:
                services.add('ssh')
            elif service == 'ftp' or port == 21:
                services.add('ftp')
            elif any(x in service for x in ('telnet', 'snmp', 'netbios', 'microsoft-ds', 'rdp', 'smb')):
                services.add('network')
            else:
                # If we have a specific engine for it, use it, otherwise generic network
                services.add('network')
    return list(services)

def _expand_target(target: str) -> List[str]:
    """Expand single target, IP range, CIDR to list of IPs."""
    from app.utils.target_expander import expand_targets
    return expand_targets(target)

async def discover_services(target: str, log_callback: Optional[Callable[[str, str], None]] = None) -> List[str]:
    """
    Discover open services on the target (single or range).
    Returns list of service names (e.g., ['http','dns','ssh']).
    """
    all_services = set()
    targets = _expand_target(target)
    # Run nmap concurrently for multiple targets
    tasks = [_run_nmap(t, log_callback) for t in targets]
    outputs = await asyncio.gather(*tasks)
    for output in outputs:
        services = _parse_nmap_standard(output)
        all_services.update(services)
    return list(all_services)
