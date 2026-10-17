"""
User database model.
Represents users in the system with authentication credentials.
"""
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


class User(Base):
    """
    User model for authentication.
    
    Attributes:
        id: Primary key
        email: Unique email address for login
        username: Unique username (optional but recommended)
        full_name: User's full display name
        password_hash: Bcrypt hashed password
        created_at: Timestamp of user creation
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(255), unique=True, index=True, nullable=True)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Admin and Permission fields
    is_admin = Column(Boolean, default=False, nullable=False)
    all_access = Column(Boolean, default=False, nullable=False)
    allowed_targets = Column(Text, nullable=True) # Comma-separated list of IPs/Domains
    last_login = Column(DateTime, nullable=True)
    
    scan_groups = relationship("ScanGroup", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', username='{self.username}')>"
