"""
api/admin_router.py
Administrative governance and platform telemetry endpoints.
Restricted exclusively to users with the 'admin' role.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from core.auth import get_current_user, log_audit_event, require_role
from core.db import DEFAULT_DB_PATH, get_db
from core.db_models import AnalysisRecord, AuditLog, User
from core.models import FORENSIC_ENGINE_VERSION, SCHEMA_VERSION

logger = logging.getLogger("cryptoposture.api.admin")

admin_router = APIRouter(prefix="/api/admin", tags=["Platform Administration & Governance"])

START_TIME = time.time()

# In-memory governance policy store (seeded with defaults)
_SYSTEM_GOVERNANCE_CONFIG: Dict[str, Any] = {
    "policy_id": "crypto-posture-v1",
    "policy_name": "NIST SP 800-52r2 & RFC 8314 Baseline",
    "min_acceptable_epi": 70.0,
    "strict_rfc_enforcement": True,
    "pqc_hybrid_warning": True,
    "quarantine_critical_flows": False,
    "max_upload_size_mb": 50,
}


class PolicyUpdateRequest(BaseModel):
    min_acceptable_epi: Optional[float] = Field(None, ge=0.0, le=100.0)
    strict_rfc_enforcement: Optional[bool] = None
    pqc_hybrid_warning: Optional[bool] = None
    quarantine_critical_flows: Optional[bool] = None


@admin_router.get("/status", summary="Get system status & forensic telemetry (Admin only)")
def get_system_status(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """Provide comprehensive health, database, and telemetry metrics to Platform Admins."""
    uptime_seconds = round(time.time() - START_TIME)

    # User metrics
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()  # noqa: E712
    users_by_role = {}
    role_counts = db.query(User.role, func.count(User.id)).group_by(User.role).all()
    for r, count in role_counts:
        users_by_role[r] = count

    # Investigation metrics
    total_analyses = db.query(AnalysisRecord).count()
    analyses_by_tier = {
        "CRITICAL": db.query(AnalysisRecord).filter(AnalysisRecord.overall_risk_tier == "CRITICAL").count(),
        "HIGH": db.query(AnalysisRecord).filter(AnalysisRecord.overall_risk_tier == "HIGH").count(),
        "MEDIUM": db.query(AnalysisRecord).filter(AnalysisRecord.overall_risk_tier == "MEDIUM").count(),
        "LOW": db.query(AnalysisRecord).filter(AnalysisRecord.overall_risk_tier == "LOW").count(),
    }
    total_violations = db.query(func.sum(AnalysisRecord.total_violations)).scalar() or 0

    # Audit logs count
    total_audit_logs = db.query(AuditLog).count()

    # DB storage estimate
    db_size_bytes = 0
    if DEFAULT_DB_PATH.exists():
        try:
            db_size_bytes = DEFAULT_DB_PATH.stat().st_size
        except Exception:
            pass

    return {
        "status": "OPERATIONAL",
        "engine_version": FORENSIC_ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "uptime_seconds": uptime_seconds,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "users": {
            "total": total_users,
            "active": active_users,
            "by_role": users_by_role,
        },
        "investigations": {
            "total_analyses": total_analyses,
            "by_tier": analyses_by_tier,
            "total_violations_recorded": int(total_violations),
        },
        "audit_trail": {
            "total_events": total_audit_logs,
        },
        "storage": {
            "database_size_bytes": db_size_bytes,
            "database_file": str(DEFAULT_DB_PATH),
        },
    }


@admin_router.get("/policy", summary="View platform governance & scoring policy (Admin only)")
def get_governance_policy(
    _admin: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """Retrieve the current active scoring policy and enforcement parameters."""
    return dict(_SYSTEM_GOVERNANCE_CONFIG)


@admin_router.post("/policy", summary="Update platform governance parameters (Admin only)")
def update_governance_policy(
    req: PolicyUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """Admin-only modification of platform governance and compliance thresholds."""
    changes = []
    if req.min_acceptable_epi is not None and req.min_acceptable_epi != _SYSTEM_GOVERNANCE_CONFIG["min_acceptable_epi"]:
        changes.append(f"min_acceptable_epi: {_SYSTEM_GOVERNANCE_CONFIG['min_acceptable_epi']} -> {req.min_acceptable_epi}")
        _SYSTEM_GOVERNANCE_CONFIG["min_acceptable_epi"] = req.min_acceptable_epi

    if req.strict_rfc_enforcement is not None and req.strict_rfc_enforcement != _SYSTEM_GOVERNANCE_CONFIG["strict_rfc_enforcement"]:
        changes.append(f"strict_rfc_enforcement: {_SYSTEM_GOVERNANCE_CONFIG['strict_rfc_enforcement']} -> {req.strict_rfc_enforcement}")
        _SYSTEM_GOVERNANCE_CONFIG["strict_rfc_enforcement"] = req.strict_rfc_enforcement

    if req.pqc_hybrid_warning is not None and req.pqc_hybrid_warning != _SYSTEM_GOVERNANCE_CONFIG["pqc_hybrid_warning"]:
        changes.append(f"pqc_hybrid_warning: {_SYSTEM_GOVERNANCE_CONFIG['pqc_hybrid_warning']} -> {req.pqc_hybrid_warning}")
        _SYSTEM_GOVERNANCE_CONFIG["pqc_hybrid_warning"] = req.pqc_hybrid_warning

    if req.quarantine_critical_flows is not None and req.quarantine_critical_flows != _SYSTEM_GOVERNANCE_CONFIG["quarantine_critical_flows"]:
        changes.append(f"quarantine_critical_flows: {_SYSTEM_GOVERNANCE_CONFIG['quarantine_critical_flows']} -> {req.quarantine_critical_flows}")
        _SYSTEM_GOVERNANCE_CONFIG["quarantine_critical_flows"] = req.quarantine_critical_flows

    if changes:
        log_audit_event(
            db=db,
            action="POLICY_UPDATED",
            user=admin,
            resource_id=_SYSTEM_GOVERNANCE_CONFIG["policy_id"],
            details=f"Admin '{admin.username}' updated governance policy: {', '.join(changes)}",
            request=request,
        )

    return {
        "status": "updated",
        "applied_changes": changes,
        "current_policy": dict(_SYSTEM_GOVERNANCE_CONFIG),
    }


@admin_router.delete("/history/purge", summary="Bulk purge investigation captures (Admin only)")
def purge_investigation_history(
    request: Request,
    only_samples: bool = Query(False, description="Purge only sample scenario runs"),
    older_than_days: Optional[int] = Query(None, ge=1, description="Purge records older than N days"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """Bulk cleanup of investigation records. Restricted to Admin."""
    query = db.query(AnalysisRecord)

    if only_samples:
        query = query.filter(AnalysisRecord.filename.ilike("%.pcap"))

    if older_than_days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        query = query.filter(AnalysisRecord.created_at < cutoff)

    deleted_count = query.delete(synchronize_session=False)
    db.commit()

    log_audit_event(
        db=db,
        action="BULK_PURGE_HISTORY",
        user=admin,
        resource_id="analysis_records",
        details=f"Admin '{admin.username}' purged {deleted_count} analysis records (only_samples={only_samples}, older_than_days={older_than_days})",
        request=request,
    )

    return {
        "status": "ok",
        "purged_count": deleted_count,
    }
