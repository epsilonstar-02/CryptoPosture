"""
api/auth_router.py
Authentication and user lifecycle REST endpoints:
- User registration (auto-promotes first user to admin)
- User login (JSON & OAuth2 form)
- Current user profile (/me)
- User management (Admin only)
- Audit log explorer (Admin & Lead Analyst)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from core.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    log_audit_event,
    require_role,
    verify_password,
)
from core.db import get_db
from core.db_models import AuditLog, User

logger = logging.getLogger("cryptoposture.api.auth")

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication & Access Control"])


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=6, max_length=128)
    full_name: Optional[str] = Field(None, max_length=100)


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserUpdateRequest(BaseModel):
    role: Optional[str] = Field(None, pattern=r"^(admin|lead_analyst|analyst|auditor)$")
    is_active: Optional[bool] = None


class AuditLogResponse(BaseModel):
    id: int
    timestamp: str
    username: Optional[str]
    action: str
    resource_id: Optional[str]
    details: Optional[str]
    ip_address: Optional[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@auth_router.post("/register", response_model=TokenResponse, summary="Register a new analyst account")
def register_user(
    req: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Register a new user account.
    If this is the very first user created in the database, they are automatically
    granted the 'admin' role. Subsequent users default to 'analyst'.
    """
    clean_username = req.username.strip().lower()
    clean_email = req.email.strip().lower()

    if db.query(User).filter(User.username == clean_username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "USERNAME_EXISTS", "message": f"Username '{clean_username}' is already registered."},
        )

    if db.query(User).filter(User.email == clean_email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "EMAIL_EXISTS", "message": f"Email '{clean_email}' is already registered."},
        )

    user_count = db.query(User).count()
    assigned_role = "admin" if user_count == 0 else "analyst"

    new_user = User(
        username=clean_username,
        email=clean_email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name.strip() if req.full_name else None,
        role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        action="USER_REGISTER",
        user=new_user,
        resource_id=str(new_user.id),
        details=f"Registered user '{new_user.username}' with role '{assigned_role}'",
        request=request,
    )

    access_token = create_access_token(
        data={"sub": new_user.username, "role": new_user.role, "uid": new_user.id}
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(**new_user.to_dict()),
    )


@auth_router.post("/login", response_model=TokenResponse, summary="Login and obtain JWT token (JSON body)")
def login_json(
    req: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate user with username and password, returning JWT access token and profile."""
    clean_username = req.username.strip().lower()
    user = db.query(User).filter(User.username == clean_username).first()

    if not user or not verify_password(req.password, user.hashed_password):
        log_audit_event(
            db=db,
            action="LOGIN_FAILED",
            user=None,
            resource_id=clean_username,
            details="Invalid username or password attempt",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "INVALID_CREDENTIALS", "message": "Incorrect username or password."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "ACCOUNT_DEACTIVATED", "message": "Account has been deactivated."},
        )

    log_audit_event(
        db=db,
        action="USER_LOGIN",
        user=user,
        resource_id=str(user.id),
        details=f"Successful login for user '{user.username}'",
        request=request,
    )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "uid": user.id}
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(**user.to_dict()),
    )


@auth_router.post("/token", summary="OAuth2 standard token endpoint for Swagger docs authentication")
def login_oauth2(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Standard OAuth2 form login for OpenAPI interactive docs."""
    clean_username = form_data.username.strip().lower()
    user = db.query(User).filter(User.username == clean_username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role, "uid": user.id}
    )

    return {"access_token": access_token, "token_type": "bearer"}


@auth_router.get("/me", response_model=UserResponse, summary="Get current logged-in user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve profile and permissions for currently authenticated user."""
    return UserResponse(**current_user.to_dict())


@auth_router.get("/users", response_model=List[UserResponse], summary="List all users (Admin only)")
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """List all registered analyst users. Restricted to Admin."""
    users = db.query(User).order_by(User.id.asc()).all()
    return [UserResponse(**u.to_dict()) for u in users]


@auth_router.patch("/users/{user_id}", response_model=UserResponse, summary="Update user role or status (Admin only)")
def update_user(
    user_id: int,
    req: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    """Modify user role or activation status. Restricted to Admin."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Guard: prevent admin from deactivating or demoting their own account
    if target_user.id == admin.id and req.role and req.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot revoke your own admin privileges.")

    changes = []
    if req.role is not None and req.role != target_user.role:
        changes.append(f"role: {target_user.role} -> {req.role}")
        target_user.role = req.role

    if req.is_active is not None and req.is_active != target_user.is_active:
        changes.append(f"is_active: {target_user.is_active} -> {req.is_active}")
        target_user.is_active = req.is_active

    if changes:
        db.commit()
        db.refresh(target_user)
        log_audit_event(
            db=db,
            action="USER_MODIFIED",
            user=admin,
            resource_id=str(target_user.id),
            details=f"Admin '{admin.username}' updated user '{target_user.username}': {', '.join(changes)}",
            request=request,
        )

    return UserResponse(**target_user.to_dict())


@auth_router.get("/audit-logs", summary="List forensic audit logs (Admin & Lead Analyst)")
def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _authorized_user: User = Depends(require_role("admin", "lead_analyst")),
):
    """View forensic audit trail of all platform activities."""
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(min(limit, 500))
        .all()
    )
    total = db.query(AuditLog).count()
    return {
        "total": total,
        "logs": [log.to_dict() for log in logs],
    }
