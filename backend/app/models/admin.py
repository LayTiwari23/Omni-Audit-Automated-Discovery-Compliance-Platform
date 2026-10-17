from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, ForeignKey, Float
from sqlalchemy.orm import relationship

from app.db.session import Base

class AuditLog(Base):
    """
    Tracks admin and user activity for auditing.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False) # e.g., "DELETE_REPORT", "CHANGE_SETTING", "LOGIN"
    target_type = Column(String(50), nullable=True) # e.g., "USER", "REPORT", "SYSTEM"
    target_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")

class SystemSetting(Base):
    """
    Global system settings and configurations.
    """
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class GlobalBlacklist(Base):
    """
    Never-scan list for sensitive targets.
    """
    __tablename__ = "global_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), unique=True, index=True, nullable=False) # IP, Domain, or CIDR
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AdminBroadcast(Base):
    """
    System-wide announcements shown to users.
    """
    __tablename__ = "admin_broadcasts"

    id = Column(Integer, primary_key=True, index=True)
    message = Column(Text, nullable=False)
    level = Column(String(20), default="info") # info, warning, danger
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class DynamicCheck(Base):
    """
    UI-managed custom compliance checks.
    """
    __tablename__ = "dynamic_checks"

    id = Column(Integer, primary_key=True, index=True)
    engine = Column(String(50), nullable=False) # 'web', 'dns', etc.
    tool_name = Column(String(50), nullable=False, server_default='nmap')
    check_id_string = Column(String(50), nullable=False) # e.g. "WEB-101", "DNS-101"
    check_name = Column(String(255), nullable=False)
    command_template = Column(Text, nullable=False) # Template using {domain} and {port}
    success_criteria = Column(Text, nullable=False) # Regex to match for PASS
    severity = Column(String(20), default="INFO")
    cvss_score = Column(Float, default=0.0)
    timeout = Column(Integer, default=300) # Execution timeout in seconds
    remediation_text = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
