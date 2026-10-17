"""
Authentication API endpoints.
Handles user registration, login, profile updates, and password changes.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import text, or_
from datetime import datetime

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_id,
)
from app.db.session import get_db
from app.models.user import User
from app.models.admin import AuditLog
from app.schemas.user import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    UserUpdate,
    PasswordChange,
)


router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    # Check if email already exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    # Check if username already exists (if provided)
    if user_data.username:
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )

    hashed_password = hash_password(user_data.password)
    
    # Logic for Admin registration
    is_admin = False
    all_access = False
    if user_data.is_admin:
        if user_data.admin_secret == "admin123": # Secret key for safety
            is_admin = True
            all_access = True
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Admin Secret Key"
            )

    new_user = User(
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        password_hash=hashed_password,
        is_admin=is_admin,
        all_access=all_access
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    Accepts username or email.
    """
    identifier = credentials.username_or_email.strip()
    user = db.query(User).filter(
        or_(User.email == identifier, User.username == identifier)
    ).first()

    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Role check: Admin cannot login as user, and vice versa
    if user.is_admin != credentials.is_admin:
        role_type = "Admin" if credentials.is_admin else "User"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Access denied: This account is not authorized to login as {role_type}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Log the activity
    user.last_login = datetime.utcnow()
    audit = AuditLog(
        user_id=user.id,
        action="LOGIN",
        target_type="USER",
        target_id=str(user.id),
        details=f"Successful {'Admin' if user.is_admin else 'User'} login",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()

    access_token = create_access_token(data={"sub": str(user.id)})
    return TokenResponse(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserResponse)
def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Get current authenticated user's information."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/me", response_model=UserResponse)
def update_profile(
    update_data: UserUpdate,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Update user profile (username, full_name)."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check username uniqueness if changing
    if update_data.username and update_data.username != user.username:
        existing = db.query(User).filter(User.username == update_data.username).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )
        user.username = update_data.username

    if update_data.full_name is not None:
        user.full_name = update_data.full_name

    db.commit()
    db.refresh(user)
    return user


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    password_data: PasswordChange,
    user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """Change user password."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password_data.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    user.password_hash = hash_password(password_data.new_password)
    db.commit()
    return {"message": "Password updated successfully"}
