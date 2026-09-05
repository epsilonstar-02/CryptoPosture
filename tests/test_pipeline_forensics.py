"""
tests/test_pipeline_forensics.py
Comprehensive end-to-end regression and stress tests for the forensic pipeline orchestrator.

Asserts:
  1. Full forensic evidence chain: PCAP -> stream -> STARTTLS -> TLS/cert -> findings -> score -> EPI
  2. Stage-level error isolation: malformed TCP, broken TLS, and corrupted certificates
  3. Multi-session captures: one corrupted stream does not abort or contaminate other sessions
  4. PQC Offered vs Negotiated semantic distinction (pqc_state 0, 1, 2)
  5. Deterministic session IDs and cross-run reproducibility
  6. Pipeline-level cross-stage semantic validation (STARTTLS vs TLS mismatch, empty streams)
  7. ML isolation: machine learning is optional and never alters deterministic results
  8. AnalysisConfig policy propagation and attribution
"""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root on path
_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root))

from scapy.all import IP, TCP, Raw, wrpcap

from core.models import (
    AnalysisConfig,
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    KeyExchange,
    MLSettings,
    ParserOptions,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StageResult,
    StageStatus,
    StarttlsStatus,
    TLSVersion,
)
from core.starttls_tracker import StarttlsAnalysis
from core.pipeline import (
    analyze_pcap,
    _analyze_stream,
    stage1_ingest,
    stage2_reassemble,
    stage3_track_starttls,
    stage4_parse_handshake,
    stage5_validate_certs,
    stage6_fingerprint,
    stage7_cross_validate,
    stage8_build_lineage,
    stage9_evaluate_rules,
    stage10_score_session,
    stage11_ml_anomaly,
    stage12_aggregate_enterprise,
)
from core.reassembly import TCPStream, TCPSegment
from core.crypto_parser import HandshakeResult
from generator.pcap_generator import generate_all, _tcp_pkt, _tls_record, _client_hello, _server_hello


SAMPLE_DIR = _root / "sample_pcaps"


class TestPipelineForensicOrchestrator(unittest.TestCase):
    """End-to-end regression tests verifying the forensic orchestrator contracts."""

    @classmethod
    def setUpClass(cls):
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)

    # -----------------------------------------------------------------------
    # Requirement 1 & 3: Full Forensic Chain & Provenance Lineage
    # -----------------------------------------------------------------------
    def test_full_chain_clean_implicit_tls(self):
        """PCAP -> stream -> STARTTLS -> TLS/cert -> findings -> score -> EPI."""
        path = self.paths.get("clean_implicit_tls")
        self.assertIsNotNone(path)

        summary = analyze_pcap(str(path), run_ml=False)

        # 1. Evidence Ingestion & Hash
        self.assertIsNotNone(summary.evidence.sha256_hash)
        self.assertEqual(len(summary.evidence.sha256_hash), 64)
        self.assertGreater(summary.evidence.total_packets, 0)

        # 2. Reassembly & Sessions
        self.assertEqual(len(summary.sessions), 1)
        sess = summary.sessions[0]

        # Deterministic IDs
        self.assertTrue(sess.session_id.startswith("sess_"))
        self.assertIn("->", sess.flow_id)

        # 3. STARTTLS tracking & channel type
        self.assertEqual(sess.channel_type, ChannelType.IMPLICIT_TLS)
        self.assertEqual(sess.starttls_status, StarttlsStatus.NONE)

        # 4. TLS & Certificate parsing
        self.assertEqual(sess.tls_version, TLSVersion.TLS13)
        self.assertIsNotNone(sess.cipher_suite)
        self.assertTrue(sess.sni_present)
        self.assertIsNotNone(sess.cert)

        # 5. Intermediate Stage Results preserved
        self.assertIn("stage3_starttls", sess.stage_results)
        self.assertIn("stage4_tls_handshake", sess.stage_results)
        self.assertIn("stage5_cert_validation", sess.stage_results)
        self.assertIn("stage6_fingerprinting", sess.stage_results)
        self.assertIn("stage7_cross_validation", sess.stage_results)
        self.assertIn("stage8_provenance", sess.stage_results)
        self.assertIn("stage9_rules", sess.stage_results)
        self.assertIn("stage10_scoring", sess.stage_results)

        for st_name, st_res in sess.stage_results.items():
            self.assertEqual(st_res.status, StageStatus.SUCCESS, f"Stage {st_name} did not succeed")

        # 6. Forensic Facts & Lineage
        self.assertIn("flow", sess.facts)
        self.assertIn("tls_version", sess.facts)
        self.assertIn("cipher_suite", sess.facts)
        self.assertIn("cert", sess.facts)
        self.assertIn("pqc_posture", sess.facts)

        # Lineage links
        fact_tls = sess.facts["tls_version"]
        self.assertIsNotNone(fact_tls.provenance)
        self.assertEqual(fact_tls.provenance.stream_id, sess.flow_id)

        # 7. Posture scoring & explanation
        self.assertGreater(sess.posture_score, 70.0)
        self.assertEqual(sess.risk_tier, RiskTier.LOW)
        self.assertIsNotNone(sess.scoring_explanation)
        self.assertIn("evidence_lineage", sess.scoring_explanation)
        self.assertEqual(sess.scoring_explanation["flow_id"], sess.flow_id)

        # 8. Enterprise aggregation
        self.assertGreater(summary.enterprise_posture_index, 70.0)
        self.assertEqual(summary.overall_risk_tier, RiskTier.LOW)

    # -----------------------------------------------------------------------
    # Requirement 8: Deterministic Session ID Reproducibility
    # -----------------------------------------------------------------------
    def test_reproducible_session_identifiers(self):
        """Repeated analysis of the same capture MUST produce identical session IDs."""
        path = self.paths.get("clean_implicit_tls")
        s1 = analyze_pcap(str(path), run_ml=False)
        s2 = analyze_pcap(str(path), run_ml=False)

        self.assertEqual(len(s1.sessions), len(s2.sessions))
        for sess1, sess2 in zip(s1.sessions, s2.sessions):
            self.assertEqual(sess1.session_id, sess2.session_id)
            self.assertEqual(sess1.flow_id, sess2.flow_id)
            self.assertEqual(sess1.posture_score, sess2.posture_score)

    # -----------------------------------------------------------------------
    # Requirement 4: PQC Offered vs Actually Negotiated Distinction
    # -----------------------------------------------------------------------
    def test_pqc_state_distinction_offered_vs_negotiated(self):
        """Verify pqc_state: 0=Classical, 1=PQC Offered, 2=Hybrid PQC Negotiated."""
        config = AnalysisConfig.from_args(run_ml=False)

        # Case 1: Classical only
        hs_classical = HandshakeResult(
            tls_version=TLSVersion.TLS13,
            cipher_suite_name="TLS_AES_128_GCM_SHA256",
            key_exchange=KeyExchange.ECDHE,
            pqc_offered=False,
            pqc_negotiated=False,
            handshake_status="COMPLETED",
        )
        stream = TCPStream(
            stream_id="10.0.0.1:50000->10.0.0.2:993",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=50000,
            dst_port=993,
            protocol=Protocol.IMAP,
            is_implicit_tls=True,
        )

        with patch("core.pipeline.stage4_parse_handshake", return_value=(hs_classical, StageResult("s4", "Handshake"))):
            sess1 = _analyze_stream(stream, config)
            self.assertEqual(sess1.pqc_state, 0, "Classical session should have pqc_state == 0")
            self.assertFalse(sess1.pqc_offered)
            self.assertFalse(sess1.pqc_negotiated)
            self.assertEqual(sess1.facts["pqc_posture"].value, "Classical Only")

        # Case 2: PQC Offered in ClientHello, but Server negotiated Classical group
        hs_offered = HandshakeResult(
            tls_version=TLSVersion.TLS13,
            cipher_suite_name="TLS_AES_128_GCM_SHA256",
            key_exchange=KeyExchange.ECDHE,
            selected_group=0x0017,  # secp256r1 (Classical)
            selected_group_name="secp256r1",
            pqc_offered=True,       # Client offered Kyber/ML-KEM
            pqc_negotiated=False,   # Server chose classical
            handshake_status="COMPLETED",
        )
        with patch("core.pipeline.stage4_parse_handshake", return_value=(hs_offered, StageResult("s4", "Handshake"))):
            sess2 = _analyze_stream(stream, config)
            self.assertEqual(sess2.pqc_state, 1, "PQC offered but classical chosen must have pqc_state == 1")
            self.assertTrue(sess2.pqc_offered)
            self.assertFalse(sess2.pqc_negotiated)
            self.assertIn("Offered", sess2.facts["pqc_posture"].value)

        # Case 3: Hybrid PQC Negotiated in ServerHello
        hs_negotiated = HandshakeResult(
            tls_version=TLSVersion.TLS13,
            cipher_suite_name="TLS_AES_256_GCM_SHA384",
            key_exchange=KeyExchange.ECDHE,
            selected_group=0x6399,  # X25519Kyber768Draft00
            selected_group_name="x25519_kyber768",
            pqc_offered=True,
            pqc_negotiated=True,
            handshake_status="COMPLETED",
        )
        with patch("core.pipeline.stage4_parse_handshake", return_value=(hs_negotiated, StageResult("s4", "Handshake"))):
            sess3 = _analyze_stream(stream, config)
            self.assertEqual(sess3.pqc_state, 2, "Negotiated PQC must have pqc_state == 2")
            self.assertTrue(sess3.pqc_offered)
            self.assertTrue(sess3.pqc_negotiated)
            self.assertEqual(sess3.facts["pqc_posture"].value, "Hybrid PQC Negotiated")

    # -----------------------------------------------------------------------
    # Requirement 2: Stage-Level Error Isolation (Single Malformed Stream)
    # -----------------------------------------------------------------------
    def test_stage_level_error_isolation_broken_tls(self):
        """Corrupted TLS handshake must be caught in Stage 4 and mark session INCONCLUSIVE."""
        config = AnalysisConfig.from_args(run_ml=False)

        stream = TCPStream(
            stream_id="10.0.0.1:45000->10.0.0.2:993",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45000,
            dst_port=993,
            protocol=Protocol.IMAP,
            is_implicit_tls=True,
            client_data=bytearray(b"\x16\x03\x03\xff\xff\x01\x00"),  # Corrupt truncated record length
            server_data=bytearray(b"GARBAGE_PAYLOAD"),
        )

        session = _analyze_stream(stream, config)

        self.assertIsNotNone(session)
        self.assertEqual(session.flow_id, stream.stream_id)
        # Session does NOT abort; it marks status as inconclusive
        self.assertIn("stage4_tls_handshake", session.stage_results)
        self.assertIn(
            session.stage_results["stage4_tls_handshake"].status,
            (StageStatus.INCONCLUSIVE, StageStatus.PARTIAL, StageStatus.ERROR),
        )

    def test_stage_level_error_isolation_simulated_exception(self):
        """Unhandled exception in a stage must be safely isolated without aborting analysis."""
        config = AnalysisConfig.from_args(run_ml=False)
        stream = TCPStream(
            stream_id="10.0.0.1:45001->10.0.0.2:25",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=45001,
            dst_port=25,
            protocol=Protocol.SMTP,
        )

        with patch("core.pipeline.stage3_track_starttls", side_effect=RuntimeError("Simulated stage 3 crash")):
            session = _analyze_stream(stream, config)
            self.assertEqual(session.stage_results["stage3_starttls"].status, StageStatus.ERROR)
            self.assertIn("Simulated stage 3 crash", session.stage_results["stage3_starttls"].diagnostics[0])
            # Session completes and receives risk assessment
            self.assertIsNotNone(session.posture_score)

    # -----------------------------------------------------------------------
    # Requirement 2 & 10: Multi-Session PCAP with Mixed Good and Malformed Flows
    # -----------------------------------------------------------------------
    def test_multi_session_pcap_isolation(self):
        """A PCAP containing one valid session and one malformed session isolates the fault."""
        test_pcap = SAMPLE_DIR / "test_multi_session_isolation.pcap"

        # Session 1: Clean Implicit TLS (port 993)
        client_hi = _client_hello()
        server_hi = _server_hello(version=0x0304, cipher_suite=0x1302)  # TLS 1.3
        p1 = _tcp_pkt("192.168.1.10", "192.168.1.1", 51000, 993, client_hi, seq=1000)
        p2 = _tcp_pkt("192.168.1.1", "192.168.1.10", 993, 51000, server_hi, seq=2000)

        # Session 2: Malformed garbage stream on port 25
        p3 = _tcp_pkt("192.168.1.20", "192.168.1.1", 52000, 25, b"\x00\xff\xee\xdd", seq=3000)

        wrpcap(str(test_pcap), [p1, p2, p3])

        try:
            summary = analyze_pcap(str(test_pcap), run_ml=False)

            self.assertEqual(len(summary.sessions), 2)
            # Find the clean IMAPS session and the malformed SMTP session
            clean_sess = next((s for s in summary.sessions if s.dst_port == 993), None)
            malformed_sess = next((s for s in summary.sessions if s.dst_port == 25), None)

            self.assertIsNotNone(clean_sess)
            self.assertIsNotNone(malformed_sess)

            # Clean session has valid high posture
            self.assertEqual(clean_sess.tls_version, TLSVersion.TLS13)
            self.assertGreater(clean_sess.posture_score, 60.0)

            # Malformed session handled without crash
            self.assertIsNotNone(malformed_sess.posture_score)
            self.assertLessEqual(malformed_sess.posture_score, 50.0)
        finally:
            if test_pcap.exists():
                test_pcap.unlink()

    # -----------------------------------------------------------------------
    # Requirement 9: Cross-Stage Validation Checks
    # -----------------------------------------------------------------------
    def test_cross_stage_starttls_tls_conflict_detected(self):
        """If STARTTLS indicates plaintext/stripped, but TLS handshake is parsed, flag conflict."""
        stream = TCPStream(
            stream_id="10.0.0.1:40000->10.0.0.2:25",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=25,
            protocol=Protocol.SMTP,
        )
        st_res = StarttlsAnalysis(
            starttls_status=StarttlsStatus.STRIPPED,
            channel_type=ChannelType.PLAINTEXT,
        )
        hs = HandshakeResult(
            tls_version=TLSVersion.TLS12,
            cipher_suite_name="TLS_RSA_WITH_AES_128_CBC_SHA",
            handshake_status="COMPLETED",
        )

        status_code, warnings, stage_res = stage7_cross_validate(stream, st_res, hs)

        self.assertEqual(status_code, "AMBIGUOUS_CONFLICT")
        self.assertTrue(any("STARTTLS tracker classified session as cleartext" in w for w in warnings))

    def test_cross_stage_empty_flow_safeguard(self):
        """Zero payload bytes flow must be marked INCONCLUSIVE_EMPTY."""
        stream = TCPStream(
            stream_id="10.0.0.1:40001->10.0.0.2:25",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40001,
            dst_port=25,
            protocol=Protocol.SMTP,
            packet_count=3,
            byte_count=0,
        )
        st_res = StarttlsAnalysis()
        hs = HandshakeResult()

        status_code, warnings, stage_res = stage7_cross_validate(stream, st_res, hs)
        self.assertEqual(status_code, "INCONCLUSIVE_EMPTY")

    # -----------------------------------------------------------------------
    # Requirement 6: Isolated and Optional Machine Learning
    # -----------------------------------------------------------------------
    def test_ml_optional_and_isolated(self):
        """ML anomaly detection must be skippable and must not alter deterministic scores."""
        path = self.paths.get("clean_implicit_tls")

        # 1. Run without ML
        cfg_no_ml = AnalysisConfig(ml_settings=MLSettings(enabled=False))
        s_no_ml = analyze_pcap(str(path), config=cfg_no_ml)
        self.assertFalse(s_no_ml.sessions[0].is_anomalous)

        # 2. Run with ML enabled
        cfg_with_ml = AnalysisConfig(ml_settings=MLSettings(enabled=True))
        s_with_ml = analyze_pcap(str(path), config=cfg_with_ml)

        # Scores must be identical regardless of ML execution
        self.assertEqual(s_no_ml.sessions[0].posture_score, s_with_ml.sessions[0].posture_score)
        self.assertEqual(s_no_ml.sessions[0].risk_tier, s_with_ml.sessions[0].risk_tier)
        self.assertEqual(len(s_no_ml.sessions[0].violations), len(s_with_ml.sessions[0].violations))

    # -----------------------------------------------------------------------
    # Requirement 7: AnalysisConfig Propagation & Attribution
    # -----------------------------------------------------------------------
    def test_analysis_config_propagation(self):
        """Reports must accurately reflect the AnalysisConfig that generated them."""
        path = self.paths.get("clean_implicit_tls")
        cfg = AnalysisConfig(
            config_id="enterprise-audit-policy-2026",
            scoring_policy_id="strict-crypto-v2",
            scoring_policy_version="2.0",
            rule_policy_id="nist-bcp-strict-v2",
            rule_policy_version="2.5",
            ml_settings=MLSettings(enabled=False),
        )

        summary = analyze_pcap(str(path), config=cfg)

        self.assertIsNotNone(summary.analysis_config)
        self.assertEqual(summary.analysis_config["config_id"], "enterprise-audit-policy-2026")
        self.assertEqual(summary.analysis_config["scoring_policy_id"], "strict-crypto-v2")
        self.assertEqual(summary.analysis_config["rule_policy_version"], "2.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
