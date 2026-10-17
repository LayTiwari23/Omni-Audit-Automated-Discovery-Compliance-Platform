"""
Pydantic schemas for scan result requests and responses.
Handles validation and serialization for scan results.
"""
# FILE: app/schemas/scan_result.py

from typing import Optional, Literal, List
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict


class ScanResultCreate(BaseModel):
    """Schema for creating a scan result."""
    scan_id: int = Field(..., description="Scan identifier")
    compliance_id: int = Field(..., description="Compliance check identifier")
    status: Literal["Y", "N"] = Field(..., description="Compliance status (Y/N)")
    remarks: Optional[str] = Field(None, description="Additional remarks or details")


class ScanResultResponse(BaseModel):
    """Schema for scan result response."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int = Field(..., description="Result unique identifier")
    scan_id: int = Field(..., description="Scan identifier")
    compliance_id: int = Field(..., description="Compliance check identifier")
    status: Literal["Y", "N"] = Field(..., description="Compliance status (Y/N)")
    remarks: Optional[str] = Field(None, description="Additional remarks or details")


class ScanRawResultUpdate(BaseModel):
    """Schema for updating a raw scan result."""
    result: Optional[str] = None
    severity: Optional[str] = None
    decision_logic: Optional[str] = None


class ScanEditHistoryResponse(BaseModel):
    """Schema for scan edit history."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    check_id: str
    field_name: str
    old_value: Optional[str]
    new_value: Optional[str]
    edited_by: Optional[int]
    created_at: datetime
