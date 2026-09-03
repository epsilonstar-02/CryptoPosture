"""
api/app.py
FastAPI REST API for the Email Cryptographic Forensics Framework.
Provides endpoints for PCAP upload, forensic analysis, and report export.

Run with: uvicorn api.app:app --reload --port 8000
Docs at:  http://localhost:8000/docs
"""

from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from core.pipeline import analyze_pcap
from core.report_exporter import export_json, export_html
from generator.pcap_generator import generate_all, DEFAULT_OUTPUT_DIR, SCENARIO_GENERATORS

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Email Cryptographic Forensics Framework",
    description=(
        "AI-Assisted Passive Network Forensic Framework for Enterprise Email "
        "Cryptographic Posture Assessment. Analyzes PCAP/PCAPNG files and "
        "produces per-session TLS/X.509 posture scores with violation reports."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SAMPLE_DIR = Path(DEFAULT_OUTPUT_DIR)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_samples():
    """Generate sample PCAPs if they don't already exist."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    if not list(SAMPLE_DIR.glob("*.pcap")):
        generate_all(SAMPLE_DIR)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", summary="Health check")
def root():
    return {"status": "ok", "service": "Email Cryptographic Forensics Framework v0.1.0"}


@app.post("/api/analyze", summary="Analyze an uploaded PCAP file")
async def analyze_uploaded_pcap(
    file: UploadFile = File(..., description="PCAP or PCAPNG evidence file"),
    run_ml: bool = True,
) -> JSONResponse:
    """
    Upload a PCAP/PCAPNG file for forensic analysis.

    Returns a full JSON forensic report including:
    - Evidence integrity (SHA-256 hash)
    - Per-session TLS/STARTTLS/X.509 analysis
    - Posture scores and risk tiers
    - Violation list with NIST/RFC references
    - ML anomaly scores
    - Enterprise Posture Index
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    ext = Path(file.filename).suffix.lower()
    if ext not in {".pcap", ".pcapng"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Provide .pcap or .pcapng."
        )

    # Save uploaded file to a temp location
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        summary = analyze_pcap(tmp_path, run_ml=run_ml)
        result  = summary.to_dict()
        # Override filename with original upload name
        result["evidence"]["filename"] = file.filename
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        os.unlink(tmp_path)


@app.post("/api/analyze/report", summary="Analyze PCAP and return HTML report")
async def analyze_and_get_report(
    file: UploadFile = File(...),
    run_ml: bool = True,
) -> HTMLResponse:
    """Analyze a PCAP file and return a self-contained HTML forensic report."""
    ext = Path(file.filename or "file.pcap").suffix.lower()
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        summary = analyze_pcap(tmp_path, run_ml=run_ml)
        html    = export_html(summary)
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        os.unlink(tmp_path)


@app.get("/api/samples", summary="List available sample PCAPs")
def list_samples() -> dict:
    """List the pre-generated synthetic forensic test PCAPs."""
    _ensure_samples()
    samples = []
    for name in SCENARIO_GENERATORS.keys():
        path = SAMPLE_DIR / f"{name}.pcap"
        samples.append({
            "name": name,
            "filename": f"{name}.pcap",
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "description": _SAMPLE_DESCRIPTIONS.get(name, ""),
        })
    return {"samples": samples, "directory": str(SAMPLE_DIR)}


@app.post("/api/samples/generate", summary="Generate all sample PCAPs")
def generate_samples() -> dict:
    """(Re)generate all 5 synthetic forensic test PCAP files."""
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    paths = generate_all(SAMPLE_DIR)
    return {
        "generated": {k: str(v) for k, v in paths.items() if v},
        "errors":    [k for k, v in paths.items() if not v],
    }


@app.get("/api/samples/{name}/analyze", summary="Analyze a named sample PCAP")
def analyze_sample(name: str, run_ml: bool = True) -> JSONResponse:
    """Run forensic analysis on one of the pre-generated sample PCAPs."""
    _ensure_samples()
    path = SAMPLE_DIR / f"{name}.pcap"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found. Try POST /api/samples/generate first.")
    try:
        summary = analyze_pcap(str(path), run_ml=run_ml)
        return JSONResponse(content=summary.to_dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/samples/{name}/report", summary="Get HTML forensic report for a sample PCAP")
def sample_report(name: str, run_ml: bool = True) -> HTMLResponse:
    """Return an HTML forensic report for a named sample PCAP."""
    _ensure_samples()
    path = SAMPLE_DIR / f"{name}.pcap"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{name}' not found.")
    try:
        summary = analyze_pcap(str(path), run_ml=run_ml)
        return HTMLResponse(content=export_html(summary))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/samples/{name}/download", summary="Download a sample PCAP file")
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


# ---------------------------------------------------------------------------
# Sample descriptions
# ---------------------------------------------------------------------------

_SAMPLE_DESCRIPTIONS = {
    "clean_implicit_tls":          "IMAPS port 993 — TLS 1.3, ECDHE, AES-256-GCM, valid cert (EXPECTED: LOW risk, score ~90+)",
    "weak_cipher_starttls":        "SMTP STARTTLS — TLS 1.0, 3DES cipher, SHA-1 cert (EXPECTED: HIGH risk, score 30–55)",
    "stripped_starttls_plaintext": "SMTP STARTTLS stripped by MITM — full plaintext fallback (EXPECTED: CRITICAL, score <20)",
    "expired_cert_implicit_tls":   "IMAPS port 993 — TLS 1.2, ECDHE, expired X.509 cert (EXPECTED: MEDIUM–HIGH, score 40–65)",
    "buffer_injection_attack":     "SMTP STARTTLS — Poddebniak et al. buffer injection of cleartext commands (EXPECTED: CRITICAL, score <15)",
}
