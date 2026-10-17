from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.session import SessionLocal
from app.core.security import get_current_user_id
from app.models.user import User
from app.models.admin import GlobalBlacklist

def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id)
) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Support Impersonation for Admins
    impersonate_id = request.headers.get("X-Impersonate-User")
    
    if impersonate_id and impersonate_id not in ("null", "undefined", "") and user.is_admin:
        try:
            target_user = db.query(User).filter(User.id == int(impersonate_id)).first()
            if target_user:
                # Mark that this user is being impersonated by an admin
                # This allows bypassing permission checks while still acting as the user
                target_user.is_admin_impersonating = True
                return target_user
        except (ValueError, TypeError):
            pass

    return user

def get_current_admin_user(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id)
) -> User:
    """
    Specifically returns the REAL admin user, ignoring impersonation.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have enough privileges"
        )
    return user

def check_target_permission(db: Session, user: User, target: str):
    """
    Checks if a user is allowed to scan a specific target.
    Includes Global Blacklist check.
    Raises HTTPException if not allowed.
    """
    target_lower = target.strip().lower()

    # 1. Admin Bypass (Moved to top)
    # If the user is an admin, they can scan EVERYTHING, including blacklisted targets.
    if user.is_admin or user.all_access or getattr(user, 'is_admin_impersonating', False):
        return True

    # 2. Global Blacklist Check (for non-admins)
    blacklisted = db.query(GlobalBlacklist).filter(
        (GlobalBlacklist.target == target_lower)
    ).first()
    
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scan blocked: '{target}' is on the Global Blacklist. Reason: {blacklisted.reason or 'Not specified'}"
        )

    # 3. User Permission Check
    if not user.allowed_targets:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You are not authorized to scan '{target}'. No allowed targets assigned."
        )
    
    # Use the expander to handle CIDRs, ranges, and lists
    from app.utils.target_expander import expand_targets
    allowed_list = expand_targets(user.allowed_targets)
    allowed_set = {t.lower() for t in allowed_list}
    
    # Direct match or expanded match
    if target_lower in allowed_set:
        return True
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"You are not allowed to scan '{target}'."
    )
