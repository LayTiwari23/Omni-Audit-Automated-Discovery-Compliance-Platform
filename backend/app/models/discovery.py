from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Enum, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base
import enum

class DiscoveryStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    input_type = Column(String(20))  # 'list', 'range', 'file'
    raw_input = Column(Text)         # Original user input
    status = Column(Enum(DiscoveryStatus), default=DiscoveryStatus.PENDING)
    group_id = Column(Integer, ForeignKey("scan_groups.id"), nullable=True)
    schedule_id = Column(Integer, ForeignKey("scan_schedules.id", ondelete="CASCADE"), nullable=True)
    total_targets = Column(Integer, default=0)
    processed_targets = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    group = relationship("ScanGroup", back_populates="discovery_jobs")
    schedule = relationship("ScanSchedule", back_populates="discovery_jobs", foreign_keys=[schedule_id])
    results = relationship("DiscoveryResult", back_populates="job")
    # user = relationship("User") # Will use backref if needed, but keeping simple

class DiscoveryResult(Base):
    __tablename__ = "discovery_results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("discovery_jobs.id"), nullable=False)
    target_ip = Column(String(45))           # IP address (v4 or v6)
    target_domain = Column(String(255), nullable=True)  # original domain if any
    port = Column(Integer)
    state = Column(String(20), default="open") # open, filtered, etc.
    service = Column(String(50))              # e.g., 'http', 'https', 'ssh'
    engine = Column(String(20))               # web, dns, email, etc.
    version_info = Column(String(255), nullable=True)
    error = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    job = relationship("DiscoveryJob", back_populates="results")
