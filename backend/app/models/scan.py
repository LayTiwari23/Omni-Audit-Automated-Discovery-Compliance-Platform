"""
Scan database model.
Represents security compliance scans submitted by users.
"""
# FILE: app/models/scan.py

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base


class Scan(Base):
    """
    Scan model for security compliance scans.
    """
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(50), nullable=False, default="PENDING")
    scan_type = Column(String(100), nullable=False, default="web")
    
    group_id = Column(Integer, ForeignKey("scan_groups.id"), nullable=True)
    compliance_percent = Column(Float, nullable=True)
    
    progress_percent = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
   
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    scan_metadata = Column(JSON, nullable=True)

    # Relationships
    user = relationship("User", backref="scans")
    group = relationship("ScanGroup", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    raw_results = relationship("ScanRawResult", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, domain='{self.domain}', status='{self.status}', progress={self.progress_percent}%)>"
