import os
import traceback
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.orm import Session
from celery.utils.log import get_task_logger

from celery_app import celery
from app.db.session import SessionLocal
from scan_manager import ScanManager
from app.utils.logger import log_event

logger = get_task_logger(__name__)

@celery.task(bind=True, max_retries=3, default_retry_delay=60)
def run_scan_task(self, scan_id: int, domain: str, scan_type: str, email_from: str = None, email_to: str = None):
    """
    Celery task to execute a security scan.
    """
    db: Session = SessionLocal()
    try:
        logger.info(f"Starting scan {scan_id} for {domain} (type={scan_type})")
        log_event(db, scan_id, "WORKER", f"Worker received scan task for {domain} ({scan_type})")

        # Update status to RUNNING (already set when creating scan, but ensure)
        db.execute(
            text("UPDATE scans SET status='RUNNING', updated_at=:ts WHERE id=:id"),
            {"ts": datetime.now(), "id": scan_id}
        )
        db.commit()

        # Route to appropriate engine via ScanManager
        # Fetch scan record to get metadata (port)
        from app.models.scan import Scan
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        port = None
        if scan and scan.scan_metadata:
            # Handle potential string or dict
            import json
            meta = scan.scan_metadata
            if isinstance(meta, str):
                try: meta = json.loads(meta)
                except: meta = {}
            port = meta.get("port")

        manager = ScanManager(scan_type, scan_id, domain, db, email_from=email_from, email_to=email_to)
        # We need to ensure manager.run handles the port
        if hasattr(manager, 'run_with_port'):
            manager.run_with_port(port)
        else:
            # Fallback if I haven't added run_with_port yet
            manager.run()

        logger.info(f"Scan {scan_id} completed successfully")
        log_event(db, scan_id, "WORKER", f"Scan {scan_id} completed successfully")

    except Exception as exc:
        logger.error(f"Scan {scan_id} failed: {exc}\n{traceback.format_exc()}")
        log_event(db, scan_id, "ERROR", f"Scan task failed: {str(exc)}")
        # Mark scan as FAILED
        try:
            db.execute(
                text("UPDATE scans SET status='FAILED', error_message=:err, updated_at=:ts WHERE id=:id"),
                {"err": str(exc)[:500], "ts": datetime.now(), "id": scan_id}
            )
            db.commit()
        except Exception as db_err:
            logger.error(f"Could not update scan status: {db_err}")
        # Optionally retry the task (if error is temporary)
        # self.retry(exc=exc)
        raise

    finally:
        db.close()
