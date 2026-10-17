"""
Pydantic schemas for user-related requests and responses.
Handles validation and serialization.
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ── Registration ─────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    """Schema for user registration request."""
    email: EmailStr = Field(..., description="User's email address")
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username")
    full_name: Optional[str] = Field(None, max_length=100, description="Full name")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    is_admin: Optional[bool] = False
    admin_secret: Optional[str] = None


# ── Login ────────────────────────────────────────────────────────────────────
class UserLogin(BaseModel):
    """Schema for user login request — accepts username OR email."""
    username_or_email: str = Field(..., min_length=1, description="Username or email")
    password: str = Field(..., description="Password")
    is_admin: bool = Field(default=False, description="Whether the login is for an admin")


# ── Token response ───────────────────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


# ── User response (excluding password) ───────────────────────────────────────
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    created_at: datetime
    is_admin: bool
    all_access: bool
    allowed_targets: Optional[str] = None


# ── Profile update request ───────────────────────────────────────────────────
class UserUpdate(BaseModel):
    """Schema for updating user profile."""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)


# ── Admin User update request ────────────────────────────────────────────────
class UserAdminUpdate(UserUpdate):
    """Schema for admin updating user permissions."""
    is_admin: Optional[bool] = None
    all_access: Optional[bool] = None
    allowed_targets: Optional[str] = None


# ── Password change request ──────────────────────────────────────────────────
class PasswordChange(BaseModel):
    """Schema for changing password."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")
