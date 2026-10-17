import ipaddress
import re
import socket
import subprocess
import logging
import time
from datetime import datetime, timezone
from typing import List, Dict, Set, Tuple
import concurrent.futures

from sqlalchemy.orm import Session
from app.models.discovery import DiscoveryJob, DiscoveryResult, DiscoveryStatus
from app.utils.target_expander import expand_targets
from app.utils.logger import log_event

logger = logging.getLogger(__name__)

# Service to engine mapping
SERVICE_ENGINE = {
    "http": "web",
    "https": "web",
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "email",
    "pop3": "email",
    "imap": "email",
    "dns": "dns",
    "domain": "dns",
    "isakmp": "vpn",
    "ipsec-nat-t": "vpn",
    "openvpn": "vpn",
    "pptp": "vpn",
    "l2tp": "vpn",
    "snmp": "network",
    "ntp": "network",
    "syslog": "network",
    "rdp": "network",
    "default": "network"
}

class DiscoveryService:
    def __init__(self, db: Session):
        self.db = db

    def start_discovery(self, user_id: int, input_type: str, raw_input: str, group_id: int = None) -> int:
        """Create a discovery job and return its ID."""
        job = DiscoveryJob(
            user_id=user_id,
            input_type=input_type,
            raw_input=raw_input,
            group_id=group_id,
            status=DiscoveryStatus.PENDING
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        return job.id

    def run_discovery(self, job_id: int):
        """Perform discovery in background (Celery task) using nmap."""
        job = self.db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
        if not job:
            return

        job.status = DiscoveryStatus.RUNNING
        self.db.commit()

        log_event(self.db, discovery_id=job_id, stage="INIT", message=f"Starting discovery job {job_id}")

        try:
            # Expand targets from raw input
            targets = expand_targets(job.raw_input)
            if not targets:
                raise ValueError("No valid targets found")

            job.total_targets = len(targets)
            self.db.commit()
            
            log_event(self.db, discovery_id=job_id, stage="INFO", message=f"Expanded into {len(targets)} targets")

            # Process targets
            for idx, target in enumerate(targets):
                log_event(self.db, discovery_id=job_id, stage="START", message=f"Scanning target {idx+1}/{len(targets)}: {target}")
                self._process_target_with_nmap(job.id, target)
                job.processed_targets = idx + 1
                self.db.commit()

            job.status = DiscoveryStatus.COMPLETED
            log_event(self.db, discovery_id=job_id, stage="DONE", message="Discovery job completed successfully")
        except Exception as e:
            logger.error(f"Discovery job {job_id} failed: {e}")
            job.status = DiscoveryStatus.FAILED
            log_event(self.db, discovery_id=job_id, stage="ERROR", message=f"Discovery job failed: {str(e)}")
        finally:
            self.db.commit()

    def _process_target_with_nmap(self, job_id: int, target: str):
        """Process a single target using nmap -sT -Pn for discovery."""
        # Check if target resolves if it's a domain
        ip = self._resolve_to_ip(target)
        if not ip:
            result = DiscoveryResult(
                job_id=job_id,
                target_domain=target,
                port=0,
                service="unknown",
                engine="unknown",
                error="Failed to resolve"
            )
            self.db.add(result)
            return

        try:
            # Run nmap: -sT (TCP connect scan), -Pn (no ping), -T4 (speed)
            # Removed -F to scan more ports. Added --reason for filtered port diagnosis.
            cmd = ["nmap", "-sT", "-Pn", "-T4", "--reason", ip]
            cmd_str = " ".join(cmd)
            
            start_time = datetime.now()
            log_event(self.db, discovery_id=job_id, stage="EXEC", message=f"Executing: {cmd_str}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1
            )

            nmap_output_lines = []
            for line in iter(process.stdout.readline, ""):
                nmap_output_lines.append(line)
                # Log EVERY line to the live feed for terminal feel
                log_event(self.db, discovery_id=job_id, stage="LIVE", message=f"[{target}] {line.strip()}")

            process.stdout.close()
            return_code = process.wait(timeout=120)
            end_time = datetime.now()
            
            nmap_output = "".join(nmap_output_lines)

            if return_code != 0:
                raise Exception(f"nmap exited with code {return_code}")

            # Format and send terminal block for the finished target
            try:
                meta = {
                    "command": cmd_str,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration": (end_time - start_time).total_seconds(),
                    "output": nmap_output
                }
                from engines.dns_engine.commands import format_terminal_output
                log_event(self.db, discovery_id=job_id, stage="TERMINAL", message=f"ID:[{cmd_str}]\n" + format_terminal_output(meta))
            except Exception as e:
                logger.warning(f"Failed to broadcast terminal block: {e}")

            detected_services = self._parse_nmap_standard(nmap_output, target, ip)

            if detected_services:
                for svc in detected_services:
                    result = DiscoveryResult(
                        job_id=job_id,
                        target_ip=ip,
                        target_domain=target if target != ip else None,
                        port=svc['port'],
                        state=svc['state'],
                        service=svc['service'],
                        engine=svc['engine'],
                        version_info=svc['version']
                    )
                    self.db.add(result)
            else:
                # Add a result indicating the host responded but no ports were found
                # This supports the 'Scanned IP but no ports found' table
                result = DiscoveryResult(
                    job_id=job_id,
                    target_ip=ip,
                    target_domain=target if target != ip else None,
                    port=0,
                    state="no_ports",
                    service="none",
                    engine="none",
                    version_info="Host responded to ping/discovery but no common services were found."
                )
                self.db.add(result)

        except subprocess.TimeoutExpired:
            logger.error(f"nmap timeout for target {target}")
            self.db.add(DiscoveryResult(job_id=job_id, target_domain=target, target_ip=ip, port=0, service="timeout", engine="unknown", error="nmap scan timed out"))
        except Exception as e:
            logger.error(f"nmap failed for target {target}: {e}")
            self.db.add(DiscoveryResult(job_id=job_id, target_domain=target, target_ip=ip, port=0, service="error", engine="unknown", error=str(e)))

    def _parse_nmap_standard(self, output: str, original_target: str, ip: str) -> List[dict]:
        """Parse standard nmap output to extract service info."""
        results = []
        
        # Standard nmap lines look like:
        # 80/tcp open  http    Apache httpd 2.4.41
        # 443/tcp open|filtered  ssl/http
        # Regex explanation:
        # (\d+) - Port number
        # /(tcp|udp) - Protocol
        # \s+(open|filtered|open\|filtered) - State
        # \s+(\S+) - Service name
        # \s*(.*) - Version info (optional)
        # Improved regex to handle optional leading whitespace and varied spacing
        port_pattern = re.compile(r"^\s*(\d+)/(tcp|udp)\s+(open|filtered|open\|filtered)\s+(\S+)\s*(.*)$", re.IGNORECASE)
        
        for line in output.splitlines():
            # Using search instead of match to allow for varied output
            match = port_pattern.search(line)
            if match:
                port = int(match.group(1))
                state = match.group(3).lower()
                service = match.group(4).lower()
                version = match.group(5).strip()
                
                # Flexible mapping logic
                engine = "unsupported" # Default to unsupported
                
                if "http" in service or port in [80, 8080]:
                    engine = "web"
                elif "ssl" in service or port in [443, 8443]:
                    engine = "web"
                elif "dns" in service or "domain" in service or port == 53:
                    engine = "dns"
                elif "ssh" in service or port == 22:
                    engine = "ssh"
                elif "ftp" in service or port == 21:
                    engine = "ftp"
                elif any(x in service for x in ["smtp", "pop3", "imap"]) or port in [25, 110, 143, 587, 993, 995]:
                    engine = "email"
                elif any(x in service for x in ["isakmp", "ipsec", "openvpn", "pptp", "l2tp"]) or port in [500, 4500, 1194, 1723]:
                    engine = "vpn"
                elif service in ["snmp", "ntp", "syslog", "rdp", "telnet", "netbios", "microsoft-ds", "smb"]:
                    engine = "network"
                else:
                    # Check SERVICE_ENGINE map
                    engine = SERVICE_ENGINE.get(service, "unsupported")

                results.append({
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version,
                    "engine": engine
                })
        return results

    def _resolve_to_ip(self, target: str) -> str:
        """Resolve domain to IP; return IP or None."""
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        try:
            return socket.gethostbyname(target)
        except:
            return None

    def get_discovery_results(self, job_id: int) -> List[dict]:
        """Return formatted results with associated scans."""
        from app.models.scan import Scan
        
        results = self.db.query(DiscoveryResult).filter(DiscoveryResult.job_id == job_id).all()
        
        # Get all unique domains/IPs from these results
        targets = set()
        for r in results:
            if r.target_domain: targets.add(r.target_domain)
            if r.target_ip: targets.add(r.target_ip)
        
        # Batch fetch recent scans for these targets
        scans = self.db.query(Scan).filter(Scan.domain.in_(list(targets))).order_by(Scan.created_at.desc()).all()
        
        # Map scans to their target domain/IP
        scan_map = {}
        for s in scans:
            if s.domain not in scan_map:
                scan_map[s.domain] = []
            scan_map[s.domain].append({
                "id": s.id,
                "status": s.status,
                "scan_type": s.scan_type,
                "compliance_percent": s.compliance_percent,
                "created_at": s.created_at.isoformat()
            })

        formatted_results = []
        for r in results:
            # Find scans that match this result's target AND its detected engine
            target_scans = []
            
            # Check domain first, then IP
            potential_scans = []
            if r.target_domain in scan_map:
                potential_scans.extend(scan_map[r.target_domain])
            if r.target_ip in scan_map:
                # Add scans for IP, but avoid duplicates if domain and IP are the same
                if r.target_ip != r.target_domain:
                    potential_scans.extend(scan_map[r.target_ip])
            
            # Filter by engine type
            for s in potential_scans:
                if s["scan_type"] == r.engine:
                    target_scans.append(s)

            formatted_results.append({
                "id": r.id,
                "target_ip": r.target_ip,
                "target_domain": r.target_domain,
                "port": r.port,
                "state": r.state,
                "service": r.service,
                "engine": r.engine,
                "version_info": r.version_info,
                "error": r.error,
                "scans": target_scans
            })
            
        return formatted_results
