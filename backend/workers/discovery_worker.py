from celery_app import celery
from app.services.discovery_service import DiscoveryService
from app.db.session import SessionLocal

@celery.task(bind=True)
def run_discovery_task(self, job_id: int):
    db = SessionLocal()
    try:
        service = DiscoveryService(db)
        service.run_discovery(job_id)
    finally:
        db.close()
