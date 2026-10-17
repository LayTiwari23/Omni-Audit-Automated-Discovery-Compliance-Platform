"""
ScanResult database model.
Represents individual compliance check results for a scan.
"""
# FILE: app/models/scan_result.py

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Float, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.session import Base


class ScanResult(Base):
    """
    ScanResult model for individual compliance check results.
    
    Attributes:
        id: Primary key
        scan_id: Foreign key to scans table
        compliance_id: Compliance check identifier
        status: Compliance status ("Y" for pass, "N" for fail)
        remarks: Additional information or details about the result
        scan: Relationship to Scan model
    """
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    compliance_id = Column(Integer, nullable=True) # Changed to nullable=True as seen in WebEngine._write_summary
    status = Column(String(1), nullable=False)  # "Y" or "N"
    remarks = Column(Text, nullable=True)
    
    # New fields for executive summary in reports
    total_checks = Column(Integer, nullable=True)
    passed_checks = Column(Integer, nullable=True)
    failed_checks = Column(Integer, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="results")
    
    def __repr__(self) -> str:
        return f"<ScanResult(id={self.id}, scan_id={self.scan_id}, status='{self.status}')>"


class ScanRawResult(Base):
    """
    Detailed results for each check performed during a scan.
    Used for technical evidence and detailed PDF reports.
    """
    __tablename__ = "scan_raw_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(100), nullable=False, index=True)
    check_name = Column(String(255), nullable=False)
    tool_name = Column(String(50), nullable=False)
    command_executed = Column(Text, nullable=False)
    raw_output = Column(Text, nullable=True)
    decision_logic = Column(Text, nullable=False)
    result = Column(String(10), nullable=False) # "PASS" or "FAIL"
    
    # Risk and Remediation
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cve_id = Column(String(50), nullable=True)
    remediation_text = Column(Text, nullable=True)
    remediation_example = Column(Text, nullable=True)
    remediation_reference = Column(Text, nullable=True)

    # Timing
    execution_start = Column(DateTime, nullable=True)
    execution_end = Column(DateTime, nullable=True)
    execution_duration = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="raw_results")

    def __repr__(self) -> str:
        return f"<ScanRawResult(id={self.id}, scan_id={self.scan_id}, check_id='{self.check_id}', result='{self.result}')>"


class ScanEditHistory(Base):
    """
    History of manual edits/overrides to scan results.
    """
    __tablename__ = "scan_edit_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(100), nullable=False)
    field_name = Column(String(50), nullable=False) # result, severity, decision_logic
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    edited_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", backref="edit_history")
    user = relationship("User")
