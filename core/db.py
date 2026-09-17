"""
core/db.py
Database connection and session lifecycle management for the Forensic Framework.
Supports SQLite (zero-config default) and production PostgreSQL via DATABASE_URL.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "forensics.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"

DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# Ensure data directory exists if using local file sqlite
if DATABASE_URL.startswith("sqlite:///") and not DATABASE_URL.startswith("sqlite:///:memory:"):
    db_file_path = DATABASE_URL.replace("sqlite:///", "")
    Path(db_file_path).parent.mkdir(parents=True, exist_ok=True)

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=os.getenv("SQL_ECHO", "false").lower() in ("true", "1", "yes"),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a thread-safe database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(target_engine=None) -> None:
    """Initialize all registered database tables and apply lightweight migrations."""
    # Import models here to register them with Base.metadata before creating tables
    import core.db_models  # noqa: F401
    from sqlalchemy import inspect, text

    bind_engine = target_engine or engine
    Base.metadata.create_all(bind=bind_engine)

    # Safe migration: ensure analysis_records has triage columns if table already existed
    try:
        inspector = inspect(bind_engine)
        if "analysis_records" in inspector.get_table_names():
            columns = {col["name"] for col in inspector.get_columns("analysis_records")}
            with bind_engine.connect() as conn:
                if "triage_status" not in columns:
                    conn.execute(text("ALTER TABLE analysis_records ADD COLUMN triage_status VARCHAR(30) DEFAULT 'UNASSIGNED'"))
                if "analyst_notes" not in columns:
                    conn.execute(text("ALTER TABLE analysis_records ADD COLUMN analyst_notes TEXT"))
                if "tags" not in columns:
                    conn.execute(text("ALTER TABLE analysis_records ADD COLUMN tags VARCHAR(255)"))
                if "assigned_analyst" not in columns:
                    conn.execute(text("ALTER TABLE analysis_records ADD COLUMN assigned_analyst VARCHAR(50)"))
                conn.commit()
    except Exception:
        pass
