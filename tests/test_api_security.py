"""
tests/test_api_security.py
Comprehensive test suite for the hardened API layer:
- Health and diagnostic check
- Early binary magic-byte structural verification
- Upload size limit enforcement (HTTP 413)
- Unsupported file extensions (HTTP 400)
- Metadata envelope and unique analysis ID verification
- Gated demo and synthetic evidence namespace
"""

from __future__ import annotations

import io
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import app, MAX_UPLOAD_SIZE_BYTES
from generator.pcap_generator import generate_all, DEFAULT_OUTPUT_DIR


SAMPLE_DIR = Path(DEFAULT_OUTPUT_DIR)


class TestAPISecurity(unittest.TestCase):
    """Test suite for the hardened REST API boundary."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)
        cls.client = TestClient(app)

    # ---- 1. Service Health & Diagnostic Check ----
    def test_health_check_status_and_metadata(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("forensic_engine_version", data)
        self.assertIn("schema_version", data)
        self.assertIn("max_upload_size_mb", data)
        self.assertIn("demo_endpoints_enabled", data)

    # ---- 2. Extension and Input Validation ----
    def test_upload_unsupported_extension_rejected(self):
        fake_file = io.BytesIO(b"dummy payload")
        resp = self.client.post(
            "/api/analyze",
            files={"file": ("malicious.exe", fake_file, "application/octet-stream")},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["detail"]["error_code"], "UNSUPPORTED_EXTENSION")

    def test_upload_missing_filename_rejected(self):
        fake_file = io.BytesIO(b"dummy payload")
        resp = self.client.post(
            "/api/analyze",
            files={"file": ("", fake_file, "application/octet-stream")},
        )
        self.assertIn(resp.status_code, (400, 422))

    # ---- 3. Binary Magic Byte Validation ----
    def test_upload_corrupt_non_pcap_content_rejected(self):
        # A file with .pcap extension but plain text ASCII content (no PCAP magic bytes)
        fake_file = io.BytesIO(b"THIS_IS_NOT_A_VALID_PCAP_MAGIC_HEADER_1234567890")
        resp = self.client.post(
            "/api/analyze",
            files={"file": ("corrupt.pcap", fake_file, "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertEqual(data["detail"]["error_code"], "FORENSIC_INVALID_CAPTURE")

    def test_upload_empty_pcap_rejected(self):
        empty_file = io.BytesIO(b"")
        resp = self.client.post(
            "/api/analyze",
            files={"file": ("empty.pcap", empty_file, "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertEqual(data["detail"]["error_code"], "FORENSIC_INVALID_CAPTURE")

    # ---- 4. Valid PCAP Analysis & Metadata Envelope ----
    def test_upload_valid_pcap_analysis_success(self):
        clean_path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(clean_path)

        with open(clean_path, "rb") as f:
            resp = self.client.post(
                "/api/analyze",
                files={"file": ("clean_implicit_tls.pcap", f, "application/vnd.tcpdump.pcap")},
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Check response headers
        self.assertIn("x-analysis-id", resp.headers)
        self.assertIn("x-forensic-engine-version", resp.headers)

        # Check forensic metadata envelope
        self.assertIn("meta", data)
        meta = data["meta"]
        self.assertTrue(meta["analysis_id"].startswith("an_"))
        self.assertIn("processing_time_ms", meta)
        self.assertIn("uploaded_bytes", meta)
        self.assertGreater(meta["uploaded_bytes"], 0)

        # Check evidence and dual breakdowns
        self.assertEqual(data["evidence"]["filename"], "clean_implicit_tls.pcap")
        self.assertIn("session_tier_breakdown", data)
        self.assertIn("violation_severity_breakdown", data)
        self.assertIn("scoring_explanation", data["sessions"][0])

    # ---- 5. Upload Size Ceiling Enforcement (HTTP 413) ----
    def test_upload_size_limit_enforced(self):
        with patch("api.app.MAX_UPLOAD_SIZE_BYTES", 500):
            # Create a 1000-byte dummy payload (exceeds 500 bytes)
            large_content = io.BytesIO(b"A" * 1000)
            resp = self.client.post(
                "/api/analyze",
                files={"file": ("large.pcap", large_content, "application/vnd.tcpdump.pcap")},
            )
            self.assertEqual(resp.status_code, 413)
            data = resp.json()
            self.assertEqual(data["detail"]["error_code"], "PAYLOAD_TOO_LARGE")

    # ---- 6. HTML Report Endpoint ----
    def test_analyze_and_get_html_report(self):
        clean_path = self.paths.get("clean_implicit_tls")
        with open(clean_path, "rb") as f:
            resp = self.client.post(
                "/api/analyze/report",
                files={"file": ("clean_implicit_tls.pcap", f, "application/vnd.tcpdump.pcap")},
            )

        self.assertEqual(resp.status_code, 200)
        self.assertIn("x-analysis-id", resp.headers)
        self.assertIn("text/html", resp.headers.get("content-type", ""))
        self.assertIn("<!DOCTYPE html>", resp.text)

    # ---- 7. Demo Namespace & Backward Compatibility ----
    def test_demo_samples_list(self):
        resp = self.client.get("/api/demo/samples")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("samples", data)
        self.assertGreaterEqual(len(data["samples"]), 5)

    def test_demo_sample_analyze(self):
        resp = self.client.get("/api/demo/samples/clean_implicit_tls/analyze")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("enterprise_posture_index", data)

    def test_backward_compatible_sample_alias(self):
        resp = self.client.get("/api/samples")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("samples", data)

    def test_demo_endpoints_disabled_guard(self):
        with patch("api.app.ENABLE_DEMO_ENDPOINTS", False):
            resp = self.client.get("/api/demo/samples")
            self.assertEqual(resp.status_code, 403)
            data = resp.json()
            self.assertEqual(data["detail"]["error_code"], "DEMO_ENDPOINTS_DISABLED")


if __name__ == "__main__":
    unittest.main()
