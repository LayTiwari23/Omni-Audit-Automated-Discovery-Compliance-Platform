import asyncio
from datetime import datetime, timezone
from sqlalchemy import text
from discovery import discover_services, map_services_to_engines
from app.utils.logger import log_event

class ScanManager:

    def __init__(self, scan_type, scan_id, domain, db, email_from=None, email_to=None):
        self.scan_type = scan_type
        self.scan_id = scan_id
        self.domain = domain
        self.db = db
        self.email_from = email_from
        self.email_to = email_to

    def run_with_port(self, port=None):
        log_event(self.db, self.scan_id, "INFO", f"Routing scan to engine(s): {self.scan_type} on port {port}")
        
        # 1. Handle "auto" mode
        if self.scan_type == "auto":
            return self.run_auto()

        # 2. Handle comma-separated list of engines
        engine_list = [e.strip().lower() for e in self.scan_type.split(',')]
        
        if len(engine_list) == 1:
            return self._run_single_engine(engine_list[0], port=port)
        
        log_event(self.db, self.scan_id, "INFO", f"Executing multiple engines: {', '.join(engine_list)}")
        for engine_name in engine_list:
            try:
                self._run_single_engine(engine_name, port=port)
            except Exception as e:
                log_event(self.db, self.scan_id, "ERROR", f"Engine {engine_name} failed: {e}")
        
        return True

    def _run_single_engine(self, engine_name, port=None):
        """Helper to run a single specific engine."""
        # Normalize engine name to avoid mismatches
        engine_name = engine_name.strip().lower()
        
        # Comprehensive mapping of service names to engines
        if any(x in engine_name for x in ["web", "http", "https", "ssl/http", "ssl/https"]):
            from engines.web_engine.engine import WebEngine
            return WebEngine().run(self.db, self.scan_id, self.domain, port=port)
        elif any(x in engine_name for x in ["dns", "domain"]):
            from engines.dns_engine.engine import run_dns_engine
            return run_dns_engine(self.db, self.scan_id, self.domain, dns_port=port or 53)
        elif any(x in engine_name for x in ["email", "smtp", "smtps", "pop3", "imap"]):
            from engines.email_engine.engine import run_email_engine
            return run_email_engine(self.db, self.scan_id, self.domain, port=port, email_from=self.email_from, email_to=self.email_to)
        elif "ssh" in engine_name:
            from engines.ssh_engine.engine import run_ssh_engine
            return run_ssh_engine(self.db, self.scan_id, self.domain, ssh_port=port or 22)
        elif "ftp" in engine_name:
            from engines.ftp_engine.engine import run_ftp_engine
            return run_ftp_engine(self.db, self.scan_id, self.domain, ftp_port=port or 21)
        elif "vpn" in engine_name:
            from engines.vpn_engine.engine import run_vpn_engine
            return run_vpn_engine(self.db, self.scan_id, self.domain, port=port)
        elif "network" in engine_name:
            from engines.network_engine.engine import run_network_engine
            return run_network_engine(self.db, self.scan_id, self.domain, port=port)
        else:
            # Fallback to network engine for unknown types
            from engines.network_engine.engine import run_network_engine
            log_event(self.db, self.scan_id, "WARNING", f"Unknown engine type '{engine_name}', falling back to network engine")
            return run_network_engine(self.db, self.scan_id, self.domain, port=port)

    def run_auto(self):
        """
        Auto-Discovery mode: Discover services and run all applicable engines.
        """
        log_event(self.db, self.scan_id, "INIT", "Starting auto-discovery for target...")
        
        # 1. Create a DiscoveryJob record for this auto-scan
        from app.models.discovery import DiscoveryJob, DiscoveryResult, DiscoveryStatus
        from app.models.scan import Scan
        
        # Get group_id if this scan belongs to a group or schedule
        scan_record = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        group_id = scan_record.group_id if scan_record else None
        user_id = scan_record.user_id if scan_record else None

        # Determine if group_id is a ScanGroup or ScanSchedule
        # In scheduler/tasks.py, group_id was set to schedule.id
        # Let's check if it exists in ScanGroup
        from app.models.scan_group import ScanGroup
        from app.models.scan_schedule import ScanSchedule
        
        real_group_id = None
        real_schedule_id = None
        
        if group_id:
            is_group = self.db.query(ScanGroup).filter(ScanGroup.id == group_id).first()
            if is_group:
                real_group_id = group_id
            else:
                # Check if it's a schedule
                is_sched = self.db.query(ScanSchedule).filter(ScanSchedule.id == group_id).first()
                if is_sched:
                    real_schedule_id = group_id

        job = DiscoveryJob(
            user_id=user_id,
            input_type="list",
            raw_input=self.domain,
            group_id=real_group_id,
            schedule_id=real_schedule_id,
            status=DiscoveryStatus.RUNNING,
            total_targets=1,
            processed_targets=0
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        def log_cb(stage, msg):
            log_event(None, self.scan_id, stage, msg)
            
        # Run discovery (async to sync)
        # We need more than just engine names; we need the full service details for the report
        from discovery.discovery_engine import _run_nmap, _parse_nmap_standard
        import asyncio
        
        nmap_output = asyncio.run(_run_nmap(self.domain, log_callback=log_cb))
        
        # Parse into detailed service info
        # Internal parser in discovery_engine only returns engine names currently.
        # Let's use the DiscoveryService logic or similar to get detailed results.
        from app.services.discovery_service import DiscoveryService
        ds = DiscoveryService(self.db)
        ip = ds._resolve_to_ip(self.domain)
        detected_services = ds._parse_nmap_standard(nmap_output, self.domain, ip or self.domain)
        
        # Save results to DB
        if detected_services:
            for svc in detected_services:
                self.db.add(DiscoveryResult(
                    job_id=job.id, target_ip=ip, target_domain=self.domain,
                    port=svc['port'], 
                    state=svc['state'],
                    service=svc['service'], 
                    engine=svc['engine'],
                    version_info=svc['version']
                ))
        
        job.status = DiscoveryStatus.COMPLETED
        job.processed_targets = 1
        self.db.commit()

        # Map to engine names for execution
        engines = list(set(svc['engine'] for svc in detected_services)) if detected_services else []

        if not engines:
            log_event(self.db, self.scan_id, "INFO", "No specific services discovered, falling back to network engine.")
            engines = ["network_engine"]
        else:
            # Normalize engine names to match our internal naming (e.g. 'web' -> 'web_engine')
            normalized_engines = []
            for e in engines:
                if not e.endswith("_engine") and e != "network":
                    normalized_engines.append(f"{e}_engine")
                elif e == "network":
                    normalized_engines.append("network_engine")
                else:
                    normalized_engines.append(e)
            engines = normalized_engines

            log_event(self.db, self.scan_id, "INFO", f"Discovery found {len(engines)} applicable engines: {', '.join(engines)}")
            # If we found specific engines (like ssh, web), and network_engine is also there, 
            # we should remove network_engine to avoid redundant/generic checks
            if len(engines) > 1 and "network_engine" in engines:
                engines.remove("network_engine")

        # Update the main scan record to show discovery is complete
        try:
            # Mark the original 'auto' scan as COMPLETED since it's just the dispatcher now
            self.db.execute(
                text("UPDATE scans SET status = 'COMPLETED', progress_percent = 100 WHERE id = :sid"),
                {"sid": self.scan_id}
            )
            self.db.commit()
        except Exception as e:
            print(f"Failed to complete dispatcher scan: {e}")

        # Run each identified service as a SEPARATE scan record
        from workers.scan_worker import run_scan_task
        import json
        for svc in detected_services:
            engine_name = svc['engine']
            if not engine_name.endswith("_engine") and engine_name != "network":
                engine_name = f"{engine_name}_engine"
            elif engine_name == "network":
                engine_name = "network_engine"

            log_event(self.db, self.scan_id, "START", f"Spawning sub-scan for: {svc['service']} on port {svc['port']} ({engine_name})")
            
            # Create a new scan record for this specific service and port
            meta_json = json.dumps({"port": svc['port'], "service": svc['service'], "version": svc['version']})
            # Canonical engine name for consistent UI display (web, ssh, etc.)
            canonical_engine = engine_name.replace("_engine", "").lower()
            
            result = self.db.execute(
                text("""
                    INSERT INTO scans (user_id, domain, scan_type, group_id, status, progress_percent, created_at, updated_at, scan_metadata)
                    VALUES (:uid, :domain, :scan_type, :gid, 'PENDING', 0, :now, :now, :meta)
                    RETURNING id
                """),
                {
                    "uid": user_id,
                    "domain": self.domain,
                    "scan_type": canonical_engine,
                    "gid": group_id,
                    "now": datetime.now(),
                    "meta": meta_json
                }
            )
            sub_scan_id = result.fetchone()[0]
            self.db.commit()
            
            # Launch the sub-scan
            run_scan_task.delay(sub_scan_id, self.domain, engine_name)
        
        return True
