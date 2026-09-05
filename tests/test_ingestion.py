"""
tests/test_ingestion.py
Forensic Evidence Ingestion Unit & Integration Test Suite.
Validates Stage 1 requirements: binary magic bytes detection, chain-of-custody
metadata, memory-efficient streaming, tamper detection, and error isolation.
"""

import os
import struct
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

# Ensure project root on sys.path
_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root))

from core.ingestion import (
    compute_sha256,
    detect_capture_format,
    ingest_pcap,
    stream_pcap,
    IngestionError,
    EvidenceNotFoundError,
    EvidencePermissionError,
    UnsupportedFormatError,
    CorruptCaptureError,
    EmptyCaptureError,
    EvidenceIntegrityError,
    PCAP_MAGIC_MICROSECONDS,
    PCAP_MAGIC_MICROSECONDS_SWAPPED,
    PCAP_MAGIC_NANOSECONDS,
    PCAPNG_MAGIC_SHB,
)
from core.pipeline import analyze_pcap, stage1_ingest
from core.models import ConfidenceLevel, StageStatus
from generator.pcap_generator import generate_all

SAMPLE_DIR = _root / "sample_pcaps"


class TestEvidenceFormatDetection(unittest.TestCase):
    """Unit tests for binary magic number detection and capture validation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_detect_pcap_microsecond(self):
        """Microsecond PCAP header magic bytes (0xa1b2c3d4)."""
        f = self.tmp_path / "valid_usec.pcap"
        f.write_bytes(PCAP_MAGIC_MICROSECONDS + b"\x00" * 20)
        fmt, magic = detect_capture_format(f)
        self.assertEqual(fmt, "PCAP")
        self.assertEqual(magic, PCAP_MAGIC_MICROSECONDS)

    def test_detect_pcap_nanosecond(self):
        """Nanosecond PCAP header magic bytes (0xa1b23c4d)."""
        f = self.tmp_path / "valid_nsec.pcap"
        f.write_bytes(PCAP_MAGIC_NANOSECONDS + b"\x00" * 20)
        fmt, magic = detect_capture_format(f)
        self.assertEqual(fmt, "PCAP")
        self.assertEqual(magic, PCAP_MAGIC_NANOSECONDS)

    def test_detect_pcapng_shb(self):
        """PCAPNG Section Header Block magic bytes (0x0a0d0d0a)."""
        f = self.tmp_path / "valid.pcapng"
        f.write_bytes(PCAPNG_MAGIC_SHB + b"\x00" * 20)
        fmt, magic = detect_capture_format(f)
        self.assertEqual(fmt, "PCAPNG")
        self.assertEqual(magic, PCAPNG_MAGIC_SHB)

    def test_detect_truncated_capture_header(self):
        """Files smaller than 4 bytes must raise CorruptCaptureError."""
        f = self.tmp_path / "tiny.pcap"
        f.write_bytes(b"\xa1\xb2")
        with self.assertRaises(CorruptCaptureError) as ctx:
            detect_capture_format(f)
        self.assertIn("truncated", str(ctx.exception).lower())

    def test_detect_unsupported_magic_bytes(self):
        """Arbitrary non-PCAP binary files must raise UnsupportedFormatError."""
        f = self.tmp_path / "fake.pcap"
        f.write_bytes(b"MZ\x90\x00" + b"\x00" * 20)  # Windows PE executable header
        with self.assertRaises(UnsupportedFormatError) as ctx:
            detect_capture_format(f)
        self.assertIn("Unsupported or invalid capture magic bytes", str(ctx.exception))


class TestEvidenceIngestionExceptions(unittest.TestCase):
    """Unit tests for diagnostic exception hierarchy and fail-safe defenses."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_nonexistent_file_raises_evidence_not_found(self):
        """Nonexistent capture file raises EvidenceNotFoundError (inheriting FileNotFoundError)."""
        missing_file = self.tmp_path / "non_existent_evidence.pcap"
        with self.assertRaises(EvidenceNotFoundError) as ctx:
            ingest_pcap(missing_file)
        self.assertIsInstance(ctx.exception, FileNotFoundError)
        self.assertIsInstance(ctx.exception, IngestionError)

    def test_unsupported_extension_raises_unsupported_format(self):
        """Unsupported file extensions (.txt, .bin, .log) raise UnsupportedFormatError."""
        txt_file = self.tmp_path / "evidence.txt"
        txt_file.write_text("not a pcap")
        with self.assertRaises(UnsupportedFormatError) as ctx:
            ingest_pcap(txt_file)
        self.assertIsInstance(ctx.exception, ValueError)
        self.assertIsInstance(ctx.exception, IngestionError)
        self.assertIn("Unsupported file extension", str(ctx.exception))

    def test_extension_spoofing_detected_via_magic_bytes(self):
        """File named .pcap containing text or garbage raises UnsupportedFormatError."""
        spoofed_file = self.tmp_path / "malicious_spoof.pcap"
        spoofed_file.write_text("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        with self.assertRaises(UnsupportedFormatError) as ctx:
            ingest_pcap(spoofed_file)
        self.assertIn("magic bytes", str(ctx.exception).lower())

    def test_empty_capture_zero_bytes_raises_empty_capture_error(self):
        """Zero-byte file raises EmptyCaptureError."""
        empty_file = self.tmp_path / "empty.pcap"
        empty_file.touch()
        with self.assertRaises(EmptyCaptureError) as ctx:
            ingest_pcap(empty_file)
        self.assertIsInstance(ctx.exception, IngestionError)
        self.assertIn("0 bytes", str(ctx.exception))

    def test_pcap_header_with_zero_packets_raises_empty_capture_error(self):
        """Valid 24-byte PCAP header with 0 packet records raises EmptyCaptureError."""
        header_only = self.tmp_path / "header_only.pcap"
        # Standard libpcap global header: magic(4), v_maj(2), v_min(2), thiszone(4), sigfigs(4), snaplen(4), linktype(4)
        raw_header = struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        header_only.write_bytes(raw_header)
        with self.assertRaises(EmptyCaptureError) as ctx:
            ingest_pcap(header_only)
        self.assertIn("0 packets were decoded", str(ctx.exception))


class TestValidPcapIngestion(unittest.TestCase):
    """Integration tests on realistic PCAP evidence files."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)

    def test_clean_implicit_tls_metadata(self):
        """Test full chain-of-custody metadata extraction on clean implicit TLS capture."""
        path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(path)

        packets, ev = ingest_pcap(path)

        # 1. Packet extraction
        self.assertGreater(len(packets), 0)
        self.assertEqual(ev.total_packets, len(packets))

        # 2. Forensic hash and identifiers
        self.assertEqual(len(ev.sha256_hash), 64)
        self.assertEqual(ev.hash_algorithm, "SHA-256")
        self.assertTrue(ev.evidence_id.startswith("ev_"))
        self.assertEqual(ev.evidence_id, f"ev_{ev.sha256_hash[:16]}")

        # 3. Chain of custody file attributes
        self.assertEqual(ev.filename, Path(path).name)
        self.assertEqual(ev.absolute_path, str(Path(path).resolve()))
        self.assertGreater(ev.file_size_bytes, 0)
        self.assertEqual(ev.capture_format, "PCAP")
        self.assertIn(ev.magic_bytes_hex, ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1"))

        # 4. Tamper verification
        self.assertTrue(ev.is_tamper_free)

        # 5. Timestamp analysis
        self.assertIsNotNone(ev.first_packet_timestamp)
        self.assertIsNotNone(ev.last_packet_timestamp)
        self.assertLessEqual(ev.first_packet_timestamp, ev.last_packet_timestamp)
        self.assertGreaterEqual(ev.capture_duration, 0.0)

        # 6. Ingestion UTC timestamp
        parsed_utc = datetime.fromisoformat(ev.ingestion_timestamp)
        self.assertIsNotNone(parsed_utc)

        # 7. No decode errors on clean capture
        self.assertEqual(ev.parse_error_count, 0)

    def test_max_packets_cap(self):
        """max_packets limits packet ingestion and logs diagnostic note."""
        path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(path)

        packets, ev = ingest_pcap(path, max_packets=2)
        self.assertLessEqual(len(packets), 2)
        self.assertTrue(any("max_packets" in d for d in ev.diagnostics))

    def test_stream_pcap_generator(self):
        """stream_pcap yields packets sequentially matching ingest_pcap."""
        path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(path)

        streamed = list(stream_pcap(path))
        direct, _ = ingest_pcap(path)
        self.assertEqual(len(streamed), len(direct))

    def test_stream_pcap_missing_file_raises(self):
        """stream_pcap on missing file raises EvidenceNotFoundError."""
        with self.assertRaises(EvidenceNotFoundError):
            list(stream_pcap("nonexistent_path_404.pcap"))


class TestEvidenceTamperDetection(unittest.TestCase):
    """Tests double-hash tamper verification during ingestion."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)

    def test_tamper_detection_triggers_integrity_error(self):
        """If file hash changes between pre-read and post-read, raise EvidenceIntegrityError."""
        path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(path)

        original_compute = compute_sha256
        call_count = [0]

        def tamper_compute(f):
            call_count[0] += 1
            if call_count[0] == 2:
                # Return spoofed/different hash on second (post-read) call
                return "0" * 64
            return original_compute(f)

        with patch("core.ingestion.compute_sha256", side_effect=tamper_compute):
            with self.assertRaises(EvidenceIntegrityError) as ctx:
                ingest_pcap(path, verify_tamper=True)
            self.assertIn("modified during ingestion", str(ctx.exception))


class TestPipelineStage1Integration(unittest.TestCase):
    """Integration tests for Stage 1 inside the forensic orchestrator."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)

    def test_stage1_ingest_success(self):
        """stage1_ingest returns StageStatus.SUCCESS and populated StageResult metadata."""
        path = self.paths.get("clean_implicit_tls")
        packets, ev, s1_res = stage1_ingest(path)

        self.assertEqual(s1_res.status, StageStatus.SUCCESS)
        self.assertEqual(s1_res.confidence, ConfidenceLevel.CONFIRMED)
        self.assertEqual(s1_res.stage_id, "stage1_ingestion")
        self.assertIn("evidence_id", s1_res.metadata)
        self.assertIn("sha256", s1_res.metadata)
        self.assertIn("capture_format", s1_res.metadata)
        self.assertTrue(s1_res.metadata["is_tamper_free"])

    def test_stage1_ingest_error_isolation_missing_file(self):
        """stage1_ingest isolates missing file error as StageStatus.ERROR without raising."""
        packets, ev, s1_res = stage1_ingest("definitely_missing_forensic_evidence.pcap")

        self.assertEqual(len(packets), 0)
        self.assertEqual(s1_res.status, StageStatus.ERROR)
        self.assertEqual(s1_res.confidence, ConfidenceLevel.LOW)
        self.assertEqual(s1_res.metadata.get("error_type"), "EvidenceNotFoundError")
        self.assertTrue(any("not found" in d.lower() for d in s1_res.diagnostics))

    def test_stage1_ingest_error_isolation_unsupported_format(self):
        """stage1_ingest isolates unsupported format as StageStatus.ERROR without raising."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"not a pcap")
            temp_path = f.name
        try:
            packets, ev, s1_res = stage1_ingest(temp_path)
            self.assertEqual(len(packets), 0)
            self.assertEqual(s1_res.status, StageStatus.ERROR)
            self.assertEqual(s1_res.metadata.get("error_type"), "UnsupportedFormatError")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_evidence_lineage_propagated_to_sessions_and_facts(self):
        """Orchestrator propagates evidence_id and sha256 to SessionAnalysis and ForensicFacts."""
        path = self.paths.get("clean_implicit_tls")
        summary = analyze_pcap(str(path), run_ml=False)

        self.assertIsNotNone(summary.evidence)
        ev_id = summary.evidence.evidence_id
        ev_hash = summary.evidence.sha256_hash

        self.assertTrue(ev_id.startswith("ev_"))
        self.assertEqual(len(ev_hash), 64)

        for sess in summary.sessions:
            # Session-level evidence lineage
            self.assertEqual(sess.evidence_id, ev_id)
            self.assertEqual(sess.evidence_hash, ev_hash)

            # Stage results include Stage 1
            self.assertIn("stage1_ingestion", sess.stage_results)
            self.assertEqual(sess.stage_results["stage1_ingestion"].status, StageStatus.SUCCESS)

            # Forensic Fact lineage includes evidence
            self.assertIn("evidence", sess.facts)
            fact_ev = sess.facts["evidence"]
            self.assertEqual(fact_ev.value, ev_id)
            self.assertIn(ev_hash, fact_ev.diagnostic)
            self.assertIn(summary.evidence.capture_format, fact_ev.diagnostic)


if __name__ == "__main__":
    unittest.main(verbosity=2)
