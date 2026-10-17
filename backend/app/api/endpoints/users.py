from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api import deps
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserAdminUpdate

router = APIRouter()

@router.get("/", response_model=List[UserResponse])
def read_users(
    db: Session = Depends(get_db),
    current_admin: User = Depends(deps.get_current_admin_user),
):
    """
    Retrieve all users. Admin only.
    """
    users = db.query(User).all()
    return users

@router.get("/{user_id}", response_model=UserResponse)
def read_user_by_id(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(deps.get_current_admin_user),
):
    """
    Get a specific user by id. Admin only.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/{user_id}", response_model=UserResponse)
def update_user_permissions(
    user_id: int,
    user_in: UserAdminUpdate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(deps.get_current_admin_user),
):
    """
    Update user permissions and profile. Admin only.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields
    if user_in.username is not None:
        user.username = user_in.username
    if user_in.full_name is not None:
        user.full_name = user_in.full_name
    if user_in.is_admin is not None:
        user.is_admin = user_in.is_admin
    if user_in.all_access is not None:
        user.all_access = user_in.all_access
    if user_in.allowed_targets is not None:
        user.allowed_targets = user_in.allowed_targets
        
    db.commit()
    db.refresh(user)
    return user

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(deps.get_current_admin_user),
):
    """
    Delete a user. Admin only.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Admins cannot delete themselves")
        
    db.delete(user)
    db.commit()
    return None
