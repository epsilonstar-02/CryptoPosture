"""
core/db_models.py
SQLAlchemy ORM models for Users, Forensic Analysis Records, and Audit Logs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from core.db import Base


class User(Base):
    """Forensic Analyst / Operator User entity."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    # Roles: "admin", "analyst"
    role = Column(String(30), default="analyst", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    analyses = relationship("AnalysisRecord", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalysisRecord(Base):
    """Persisted forensic analysis run for an evidence PCAP."""
    __tablename__ = "analysis_records"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    file_size_bytes = Column(BigInteger, default=0, nullable=False)
    capture_format = Column(String(32), default="PCAP", nullable=False)
    capture_duration = Column(Float, default=0.0, nullable=False)
    total_packets = Column(Integer, default=0, nullable=False)
    session_count = Column(Integer, default=0, nullable=False)
    enterprise_posture_index = Column(Float, default=0.0, nullable=False)
    overall_risk_tier = Column(String(20), default="UNKNOWN", nullable=False)
    total_violations = Column(Integer, default=0, nullable=False)
    critical_violations = Column(Integer, default=0, nullable=False)
    high_violations = Column(Integer, default=0, nullable=False)
    processing_time_ms = Column(Float, default=0.0, nullable=False)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    summary_json = Column(Text, nullable=False)
    # Triage and Analyst Case Management
    triage_status = Column(String(30), default="UNASSIGNED", nullable=False, index=True)
    analyst_notes = Column(Text, nullable=True)
    tags = Column(String(255), nullable=True)
    assigned_analyst = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="analyses")

    def to_dict(self, include_full: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "filename": self.filename,
            "sha256": self.sha256,
            "file_size_bytes": self.file_size_bytes,
            "capture_format": self.capture_format,
            "capture_duration": self.capture_duration,
            "total_packets": self.total_packets,
            "session_count": self.session_count,
            "enterprise_posture_index": self.enterprise_posture_index,
            "overall_risk_tier": self.overall_risk_tier,
            "total_violations": self.total_violations,
            "critical_violations": self.critical_violations,
            "high_violations": self.high_violations,
            "processing_time_ms": self.processing_time_ms,
            "user_id": self.user_id,
            "username": self.user.username if self.user else None,
            "triage_status": self.triage_status or "UNASSIGNED",
            "analyst_notes": self.analyst_notes or "",
            "tags": [t.strip() for t in self.tags.split(",") if t.strip()] if self.tags else [],
            "assigned_analyst": self.assigned_analyst or (self.user.username if self.user else None),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_full and self.summary_json:
            try:
                data["summary"] = json.loads(self.summary_json)
            except Exception:
                data["summary"] = None
        return data


class AuditLog(Base):
    """Forensic activity log tracking system events and analyst operations."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username = Column(String(50), nullable=True)
    action = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)

    user = relationship("User", back_populates="audit_logs")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "resource_id": self.resource_id,
            "details": self.details,
            "ip_address": self.ip_address,
        }
