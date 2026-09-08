"""
api/app.py
FastAPI REST API for the Email Cryptographic Forensics Framework.
Provides endpoints for PCAP upload, forensic analysis, and report export.

Run with: uvicorn api.app:app --reload --port 8000
Docs at:  http://localhost:8000/docs
"""

from __future__ import annotations

import io
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Tuple

from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from core.ingestion import (
    CorruptCaptureError,
    EmptyCaptureError,
    EvidenceIntegrityError,
    IngestionError,
    UnsupportedFormatError,
    detect_capture_format,
)
from core.models import FORENSIC_ENGINE_VERSION, SCHEMA_VERSION
from core.pipeline import analyze_pcap
from core.report_exporter import export_json, export_html
from generator.pcap_generator import (
    generate_all,
    generate_enterprise_simulations,
    DEFAULT_OUTPUT_DIR,
    SCENARIO_GENERATORS,
    ENTERPRISE_GENERATORS,
    ALL_SCENARIO_GENERATORS,
)

# ---------------------------------------------------------------------------
# Logging & Configuration
# ---------------------------------------------------------------------------

logger = logging.getLogger("cryptoposture.api")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

# Max upload limit: default 50 MB
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 50 * 1024 * 1024))
UPLOAD_CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks

# Configurable CORS origins
CORS_ORIGINS_RAW = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000",
)
if CORS_ORIGINS_RAW.strip() == "*":
    ALLOWED_ORIGINS = ["*"]
else:
    ALLOWED_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]

# Demo / synthetic test endpoints toggle
ENABLE_DEMO_ENDPOINTS = os.getenv("ENABLE_DEMO_ENDPOINTS", "true").lower() in ("true", "1", "yes")

SAMPLE_DIR = Path(DEFAULT_OUTPUT_DIR)


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Email Cryptographic Forensics Framework",
    description=(
        "AI-assisted passive network forensic engine for email cryptographic posture assessment. "
        "Compliant with RFC 8314, RFC 9325, NIST SP 800-52 Rev. 2, and Poddebniak et al. (USENIX '21)."
    ),
    version=FORENSIC_ENGINE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_samples():
    """Generate sample PCAPs if they don't already exist."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    if not (SAMPLE_DIR / "clean_implicit_tls.pcap").exists():
        generate_all(SAMPLE_DIR)
    if not (SAMPLE_DIR / "enterprise_network_simulation.pcap").exists():
        generate_enterprise_simulations(SAMPLE_DIR)


def _require_demo_enabled():
    """Guard dependency for demo/synthetic sample endpoints."""
    if not ENABLE_DEMO_ENDPOINTS:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "DEMO_ENDPOINTS_DISABLED",
                "message": "Demo and synthetic generation endpoints are disabled in this configuration.",
            },
        )


async def _stream_upload_to_temp(file: UploadFile, ext: str) -> Tuple[str, int]:
    """
    Stream uploaded file to disk in chunks to prevent memory exhaustion,
    strictly enforcing the maximum byte size limit.
    """
    total_bytes = 0
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp_path = tmp.name
        try:
            while chunk := await file.read(UPLOAD_CHUNK_SIZE):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                    max_mb = MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "error_code": "PAYLOAD_TOO_LARGE",
                            "message": f"Upload exceeds maximum allowable size of {max_mb} MB.",
                            "uploaded_bytes": total_bytes,
                            "max_allowed_bytes": MAX_UPLOAD_SIZE_BYTES,
                        },
                    )
                tmp.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    return tmp_path, total_bytes


def _validate_pcap_structure(filepath: Path) -> Tuple[str, bytes]:
    """
    Perform early binary validation of PCAP/PCAPNG header bytes
    before starting the compute-intensive analysis pipeline.
    """
    try:
        return detect_capture_format(filepath)
    except (UnsupportedFormatError, CorruptCaptureError, EmptyCaptureError) as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "FORENSIC_INVALID_CAPTURE",
                "message": str(exc),
                "filename": filepath.name,
            },
        )
    except IngestionError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "FORENSIC_INGESTION_ERROR",
                "message": str(exc),
                "filename": filepath.name,
            },
        )


# ---------------------------------------------------------------------------
# Core Analysis Endpoints
# ---------------------------------------------------------------------------

@app.get("/", summary="Service Health & Diagnostic Status")
def root():
    return {
        "status": "ok",
        "service": "Email Cryptographic Forensics Framework",
        "forensic_engine_version": FORENSIC_ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "max_upload_size_mb": MAX_UPLOAD_SIZE_BYTES // (1024 * 1024),
        "demo_endpoints_enabled": ENABLE_DEMO_ENDPOINTS,
    }


@app.post("/api/analyze", summary="Analyze an uploaded PCAP file")
async def analyze_uploaded_pcap(
    file: UploadFile = File(..., description="PCAP or PCAPNG evidence file"),
    run_ml: bool = True,
) -> JSONResponse:
    """
    Upload a PCAP/PCAPNG file for forensic analysis.

    Enforces:
    - File extension and binary magic-byte structural verification
    - Streaming disk persistence with configurable size ceiling
    - Isolated forensic engine execution
    - Comprehensive metadata envelope with unique analysis ID
    """
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail={"error_code": "MISSING_FILENAME", "message": "No file or filename provided."},
        )

    ext = Path(file.filename).suffix.lower()
    if ext not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "UNSUPPORTED_EXTENSION",
                "message": f"Unsupported file extension '{ext}'. Provide .pcap or .pcapng evidence files.",
            },
        )

    analysis_id = f"an_{uuid.uuid4().hex[:12]}"
    start_time = time.perf_counter()

    # Stream to temporary disk storage with byte ceiling
    tmp_path, total_bytes = await _stream_upload_to_temp(file, ext)

    try:
        # Validate binary magic bytes before starting pipeline
        _validate_pcap_structure(Path(tmp_path))

        # Run pipeline
        summary = analyze_pcap(tmp_path, run_ml=run_ml)
        result = summary.to_dict()

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Restore original uploaded filename in evidence metadata
        result["evidence"]["filename"] = file.filename

        # Forensic audit metadata envelope
        result["meta"] = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processing_time_ms": duration_ms,
            "uploaded_bytes": total_bytes,
            "forensic_engine_version": FORENSIC_ENGINE_VERSION,
            "schema_version": SCHEMA_VERSION,
            "scoring_policy": result.get("scoring_policy"),
        }

        logger.info(
            "Analysis %s completed for '%s' in %.2fms: %d sessions, EPI=%.2f",
            analysis_id,
            file.filename,
            duration_ms,
            result.get("session_count", 0),
            result.get("enterprise_posture_index", 0.0),
        )

        return JSONResponse(
            content=result,
            headers={
                "X-Analysis-ID": analysis_id,
                "X-Forensic-Engine-Version": FORENSIC_ENGINE_VERSION,
            },
        )
    except HTTPException:
        raise
    except IngestionError as exc:
        logger.warning("Ingestion error during %s: %s", analysis_id, exc)
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "FORENSIC_CAPTURE_ERROR",
                "message": str(exc),
                "analysis_id": analysis_id,
            },
        )
    except Exception as exc:
        logger.exception("Unexpected error during analysis %s for file %s", analysis_id, file.filename)
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": "INTERNAL_ANALYSIS_ERROR",
                "message": "A server error occurred during capture analysis. Internal error logged.",
                "analysis_id": analysis_id,
            },
        )
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.post("/api/analyze/report", summary="Analyze PCAP and return self-contained HTML report")
async def analyze_and_get_report(
    file: UploadFile = File(..., description="PCAP or PCAPNG evidence file"),
    run_ml: bool = True,
) -> HTMLResponse:
    """Analyze a PCAP file and return an interactive, standalone HTML forensic report."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    ext = Path(file.filename).suffix.lower()
    if ext not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Provide .pcap or .pcapng.",
        )

    analysis_id = f"an_{uuid.uuid4().hex[:12]}"
    tmp_path, _ = await _stream_upload_to_temp(file, ext)

    try:
        _validate_pcap_structure(Path(tmp_path))
        summary = analyze_pcap(tmp_path, run_ml=run_ml)
        summary.evidence.filename = file.filename
        html = export_html(summary)
        return HTMLResponse(
            content=html,
            status_code=200,
            headers={
                "X-Analysis-ID": analysis_id,
                "X-Forensic-Engine-Version": FORENSIC_ENGINE_VERSION,
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Report export failed for %s", analysis_id)
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": "INTERNAL_REPORT_ERROR",
                "message": "Failed to generate HTML forensic report.",
                "analysis_id": analysis_id,
            },
        )
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Demo & Synthetic Evidence Namespace
# ---------------------------------------------------------------------------

demo_router = APIRouter(
    prefix="/api/demo",
    tags=["Demo & Synthetic Samples"],
    dependencies=[Depends(_require_demo_enabled)],
)


@demo_router.get("/samples", summary="List available synthetic and simulation sample PCAPs")
def list_samples() -> dict:
    """List the pre-generated synthetic and multi-session forensic test PCAPs."""
    _ensure_samples()
    samples = []
    all_names = list(ENTERPRISE_GENERATORS.keys()) + list(ALL_SCENARIO_GENERATORS.keys())
    for name in all_names:
        path = SAMPLE_DIR / f"{name}.pcap"
        samples.append({
            "name": name,
            "filename": f"{name}.pcap",
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "description": _SAMPLE_DESCRIPTIONS.get(name, ""),
            "is_simulation": name in ENTERPRISE_GENERATORS,
        })
    return {"samples": samples, "directory": str(SAMPLE_DIR)}


@demo_router.post("/samples/generate", summary="Regenerate all synthetic and simulation sample PCAPs")
def generate_samples() -> dict:
    """(Re)generate all synthetic and multi-session forensic test PCAP files."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    paths = generate_all(SAMPLE_DIR)
    ent_paths = generate_enterprise_simulations(SAMPLE_DIR)
    paths.update(ent_paths)
    return {
        "generated": {k: str(v) for k, v in paths.items() if v},
        "errors": [k for k, v in paths.items() if not v],
    }


@demo_router.get("/samples/{name}/analyze", summary="Analyze a named sample PCAP")
def analyze_sample(name: str, run_ml: bool = True) -> JSONResponse:
    """Run forensic analysis on one of the pre-generated sample PCAPs."""
    _ensure_samples()
    path = SAMPLE_DIR / f"{name}.pcap"
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Sample '{name}' not found. POST /api/demo/samples/generate first.",
        )
    try:
        summary = analyze_pcap(str(path), run_ml=run_ml)
        return JSONResponse(content=summary.to_dict())
    except Exception as exc:
        logger.exception("Error analyzing sample %s", name)
        raise HTTPException(status_code=500, detail=str(exc))


@demo_router.get("/samples/{name}/report", summary="Get HTML forensic report for a sample PCAP")
def sample_report(name: str, run_ml: bool = True) -> HTMLResponse:
    """Return an HTML forensic report for a named sample PCAP."""
    _ensure_samples()
    path = SAMPLE_DIR / f"{name}.pcap"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found.")
    try:
        summary = analyze_pcap(str(path), run_ml=run_ml)
        return HTMLResponse(content=export_html(summary))
    except Exception as exc:
        logger.exception("Error generating report for sample %s", name)
        raise HTTPException(status_code=500, detail=str(exc))


@demo_router.get("/samples/{name}/download", summary="Download a sample PCAP file")
def download_sample(name: str) -> FileResponse:
    """Download a sample PCAP file."""
    _ensure_samples()
    path = SAMPLE_DIR / f"{name}.pcap"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found.")
    return FileResponse(
        path=str(path),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{name}.pcap",
    )


app.include_router(demo_router)


# ---------------------------------------------------------------------------
# Backward-compatible Aliases (/api/samples/* -> /api/demo/samples/*)
# ---------------------------------------------------------------------------

@app.get("/api/samples", include_in_schema=False)
def legacy_list_samples():
    return list_samples()


@app.post("/api/samples/generate", include_in_schema=False)
def legacy_generate_samples():
    return generate_samples()


@app.get("/api/samples/{name}/analyze", include_in_schema=False)
def legacy_analyze_sample(name: str, run_ml: bool = True):
    return analyze_sample(name, run_ml=run_ml)


@app.get("/api/samples/{name}/report", include_in_schema=False)
def legacy_sample_report(name: str, run_ml: bool = True):
    return sample_report(name, run_ml=run_ml)


@app.get("/api/samples/{name}/download", include_in_schema=False)
def legacy_download_sample(name: str):
    return download_sample(name)


# ---------------------------------------------------------------------------
# Sample Descriptions
# ---------------------------------------------------------------------------

_SAMPLE_DESCRIPTIONS = {
    "clean_implicit_tls":          "IMAPS port 993 — TLS 1.3, ECDHE, AES-256-GCM, valid cert (EXPECTED: LOW risk, score ~90+)",
    "weak_cipher_starttls":        "SMTP STARTTLS — TLS 1.0, 3DES cipher, SHA-1 cert (EXPECTED: HIGH risk, score 30–55)",
    "stripped_starttls_plaintext": "SMTP STARTTLS stripped by MITM — full plaintext fallback (EXPECTED: CRITICAL, score 0)",
    "expired_cert_implicit_tls":   "IMAPS port 993 — TLS 1.2, ECDHE, expired X.509 cert (EXPECTED: MEDIUM–HIGH, score 40–65)",
    "buffer_injection_attack":     "SMTP STARTTLS — Poddebniak et al. buffer injection of cleartext commands (EXPECTED: CRITICAL, score <= 15)",
    "enterprise_network_simulation": "Corporate Perimeter Simulation (16 Flows, 119 Pkts) — Mixed Departments, PQC, Deprecated Ciphers, Attack Vectors (EXPECTED: CRITICAL)",
    "mitm_attack_campaign":        "Adversarial MitM Attack Campaign (6 Flows, 46 Pkts) — Credential Theft, Buffer Injection, Phishing SNI Mismatch (EXPECTED: CRITICAL)",
    "cloud_migration_audit":       "Hybrid Cloud Migration Audit (8 Flows, 63 Pkts) — Modern M365/PQC vs Legacy On-Prem Exchange & Cleartext ERP (EXPECTED: CRITICAL)",
}
