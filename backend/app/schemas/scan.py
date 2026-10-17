"""
Pydantic schemas for scan-related requests and responses.
Handles validation and serialization for scan operations.
"""
# FILE: app/schemas/scan.py

from datetime import datetime
from typing import Literal, List, Optional

from pydantic import BaseModel, Field, ConfigDict, field_validator


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    domain: str = Field(..., min_length=3, max_length=255, description="Domain to scan")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Basic domain validation."""
        # Remove protocol if present
        domain = v.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove trailing slashes
        domain = domain.rstrip('/')
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        
        # Basic validation
        if not domain or len(domain) < 3:
            raise ValueError("Domain must be at least 3 characters")
        
        return domain


class ScanResponse(BaseModel):
    """Schema for scan response."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(..., description="Scan unique identifier")
    user_id: int = Field(..., description="User who created the scan")
    domain: str = Field(..., description="Domain being scanned")
    scan_type: str = Field(..., description="Type of scan (engine)")
    compliance_percent: Optional[float] = Field(None, description="Calculated compliance percentage")
    status: Literal["PENDING", "COMPLETED", "FAILED", "RUNNING", "CANCELLED"] = Field(..., description="Scan status")
    created_at: datetime = Field(..., description="Timestamp of scan creation")
    updated_at: datetime = Field(..., description="Timestamp of last update")
    scan_metadata: Optional[dict] = Field(None, description="Additional scan metadata")


class ScanListResponse(BaseModel):
    """Schema for listing scans."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    domain: str
    status: Literal["PENDING", "COMPLETED", "FAILED", "RUNNING", "CANCELLED"]
    created_at: datetime


class ScanHistoryResponse(BaseModel):
    """Schema for scan history response with essential fields."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(..., description="Scan unique identifier")
    domain: str = Field(..., description="Domain that was scanned")
    status: Literal["PENDING", "COMPLETED", "FAILED", "RUNNING", "CANCELLED"] = Field(..., description="Current scan status")
    created_at: datetime = Field(..., description="When the scan was created")
    updated_at: datetime = Field(..., description="When the scan was last updated")


class ScanHistoryListResponse(BaseModel):
    """Schema for paginated scan history list."""
    total: int = Field(..., description="Total number of scans for the user")
    scans: List[ScanHistoryResponse] = Field(..., description="List of scans")


class ComplianceComparison(BaseModel):
    """Schema for a single compliance check comparison across multiple scans."""
    compliance_id: int = Field(..., description="Compliance check identifier")
    statuses: List[Optional[str]] = Field(..., description="List of statuses (Y/N) for each scan, in order of scan_ids")
    remarks: List[Optional[str]] = Field(..., description="List of remarks for each scan, in order of scan_ids")


class ScanComparisonResponse(BaseModel):
    """Schema for scan comparison response."""
    scan_ids: List[int] = Field(..., description="List of scan IDs being compared, in order")
    comparisons: List[ComplianceComparison] = Field(..., description="Compliance check comparisons grouped by compliance_id")
