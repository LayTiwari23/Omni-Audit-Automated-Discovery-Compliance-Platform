from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base

class ScanSchedule(Base):
    __tablename__ = 'scan_schedules'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(255), nullable=False) # This will be the Campaign Name
    description = Column(String(1000), nullable=True)
    target = Column(Text, nullable=False) # Changed to Text for multiple targets/CIDR/CSV
    scan_type = Column(String(100), nullable=False)
    scan_mode = Column(String(50), nullable=False, server_default='command_only')
    cron_expression = Column(String(100), nullable=False)
    discovery_job_id = Column(Integer, ForeignKey('discovery_jobs.id', ondelete='SET NULL'), nullable=True)
    enabled = Column(Boolean, default=True)
    next_run = Column(DateTime(timezone=True), nullable=True)
    selections = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    discovery_jobs = relationship("DiscoveryJob", back_populates="schedule", primaryjoin="ScanSchedule.id == DiscoveryJob.schedule_id", foreign_keys="DiscoveryJob.schedule_id")