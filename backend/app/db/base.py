"""
SQLAlchemy declarative base.
All models should inherit from Base.
"""
from app.db.session import Base

# This file is used by Alembic and other tools to discover all models.
# By importing them here, they are registered on the Base.metadata.

from app.models.user import User
from app.models.scan import Scan
from app.models.scan_group import ScanGroup
from app.models.scan_result import ScanResult
from app.models.scan_schedule import ScanSchedule
from app.models.discovery import DiscoveryJob, DiscoveryResult
from app.models.scan_log import ScanLog
from app.models.admin import AuditLog, SystemSetting, GlobalBlacklist, AdminBroadcast, DynamicCheck
