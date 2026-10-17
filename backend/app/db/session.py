"""
Database session management.
Provides database engine and session factory with scoped session support.
"""
import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from app.core.config import settings

# Use environment variable or default to postgres
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://compliance_user:compliance_sec@localhost/compliance_db")

# Create database engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,
    pool_pre_ping=True
)

Base = declarative_base()

# 1. Create standard session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 2. NEW: Create scoped session factory for background tasks
# This allows background threads to have their own database connection
ScopedSession = scoped_session(SessionLocal)

def get_db() -> Generator[Session, None, None]:
    """
    Dependency that provides a database session for standard API routes.
    Ensures the session is properly closed after the request is finished.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_background_db() -> Session:
    """
    NEW: Provides a new session specifically for long-running background tasks.
    Usage: db = get_background_db()
    """
    return ScopedSession()
