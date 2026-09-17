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

import csv
import io
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
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


class UserCreateByAdminRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=6, max_length=128)
    full_name: Optional[str] = Field(None, max_length=100)
    role: str = Field("analyst", pattern=r"^(admin|analyst)$")
    is_active: bool = True


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
    role: Optional[str] = Field(None, pattern=r"^(admin|analyst)$")
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


@auth_router.post("/users", response_model=UserResponse, summary="Provision new user account (Admin only)")
def create_user_by_admin(
    req: UserCreateByAdminRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    """Admin-only user provisioning."""
    clean_username = req.username.strip().lower()
    clean_email = req.email.strip().lower()

    if db.query(User).filter(User.username == clean_username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "USERNAME_EXISTS", "message": f"Username '{clean_username}' already exists."},
        )

    if db.query(User).filter(User.email == clean_email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "EMAIL_EXISTS", "message": f"Email '{clean_email}' already exists."},
        )

    new_user = User(
        username=clean_username,
        email=clean_email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name.strip() if req.full_name else None,
        role=req.role,
        is_active=req.is_active,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        action="USER_CREATED",
        user=admin,
        resource_id=str(new_user.id),
        details=f"Admin '{admin.username}' provisioned user '{new_user.username}' with role '{new_user.role}'",
        request=request,
    )

    return UserResponse(**new_user.to_dict())


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


@auth_router.delete("/users/{user_id}", summary="Delete a user account (Admin only)")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    """Delete user. Restricted to Admin. Admin cannot delete self."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if target_user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account.")

    username = target_user.username
    db.delete(target_user)
    db.commit()

    log_audit_event(
        db=db,
        action="USER_DELETED",
        user=admin,
        resource_id=str(user_id),
        details=f"Admin '{admin.username}' deleted user '{username}' (ID: {user_id})",
        request=request,
    )

    return {"status": "ok", "deleted_user": username}


@auth_router.get("/audit-logs", summary="List forensic audit logs (Admin only)")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, description="Filter by audit action"),
    username: Optional[str] = Query(None, description="Filter by actor username"),
    search: Optional[str] = Query(None, description="Search details or resource"),
    db: Session = Depends(get_db),
    _authorized_user: User = Depends(require_role("admin")),
):
    """View forensic audit trail of all platform activities with filtering."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action.upper())
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username.strip()}%"))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter((AuditLog.details.ilike(pattern)) | (AuditLog.resource_id.ilike(pattern)))

    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "logs": [log.to_dict() for log in logs],
    }


@auth_router.get("/audit-logs/export", summary="Export audit logs as CSV or JSON (Admin only)")
def export_audit_logs(
    format: str = Query("csv", pattern=r"^(csv|json)$"),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
):
    """Export forensic audit logs for regulatory compliance."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(1000).all()
    if format == "json":
        return [log.to_dict() for log in logs]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp UTC", "User", "Action", "Resource ID", "IP Address", "Details"])
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.isoformat() if log.timestamp else "",
            log.username or "anonymous",
            log.action,
            log.resource_id or "",
            log.ip_address or "",
            log.details or "",
        ])
    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs_export.csv"},
    )
