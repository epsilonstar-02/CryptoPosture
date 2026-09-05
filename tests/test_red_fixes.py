"""
tests/test_red_fixes.py
Comprehensive regression tests for the 5 critical (red) forensic issues:
1. Issue 1: TCP Gap Handling (SequenceGap, stream.has_gaps, StageStatus.PARTIAL)
2. Issue 2: TLS 1.3 Passive Certificate Limitation (cert_visibility, ENCRYPTED_TLS13)
3. Issue 3: Handshake Status Semantics (HANDSHAKE_MESSAGES_COMPLETE)
4. Issue 4: Scoring Missing-Evidence Mathematics (Weight renormalization)
5. Issue 5: Pipeline Policy Wiring (PolicyCatalog & ScoringPolicy end-to-end)
"""

import unittest
from scapy.layers.inet import IP, TCP

from core.models import (
    AnalysisConfig,
    AssessmentStatus,
    CertHealth,
    ChannelType,
    FindingStatus,
    KeyExchange,
    ParserOptions,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StageStatus,
    StarttlsStatus,
    TLSVersion,
)
from core.reassembly import (
    _TCPDirectionReassembler,
    SequenceGap,
    StreamReassembler,
    TCPStream,
)
from core.crypto_parser import HandshakeResult, parse_combined
from core.scorer import (
    DEFAULT_POLICY,
    ScoringPolicy,
    score_session,
    compute_enterprise_index,
)
from core.models import EnterpriseSummary, EvidenceMetadata
from core.rule_engine import PolicyCatalog, RuleDefinition, run_rules
from core.pipeline import (
    stage2_reassemble,
    stage4_parse_handshake,
    stage5_validate_certs,
    stage7_cross_validate,
    stage9_evaluate_rules,
    stage10_score_session,
    stage12_aggregate_enterprise,
)
from core.starttls_tracker import StarttlsAnalysis
from tests.test_crypto_parser import _build_client_hello, _build_server_hello, _build_record


class TestRedIssue1TCPGapHandling(unittest.TestCase):
    """🔴 Issue 1: TCP Gap Handling verification."""

    def test_direction_reassembler_gap_detection(self):
        """When segments have a sequence gap, SequenceGap must be recorded."""
        r = _TCPDirectionReassembler(from_client=True)
        r.ref_seq = 1000
        # Segment 1: seq 1000..1010 (10 bytes)
        r.add_segment(1000, b"0123456789", timestamp=1.0)
        # Gap: seq 1010..1020 is missing (10 bytes)
        # Segment 2: seq 1020..1030 (10 bytes)
        r.add_segment(1020, b"ABCDEFGHIJ", timestamp=2.0)

        data, segs, gaps = r.reassemble()
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].start_offset, 10)
        self.assertEqual(gaps[0].end_offset, 20)
        self.assertEqual(gaps[0].missing_bytes, 10)
        self.assertEqual(gaps[0].direction, "client")
        self.assertEqual(len(segs), 2)
        self.assertEqual(data, b"0123456789ABCDEFGHIJ")

    def test_tcp_stream_gap_properties(self):
        """TCPStream exposes has_gaps, sequence_gaps, and gap_summary."""
        stream = TCPStream(
            stream_id="10.0.0.1:1000->10.0.0.2:25",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1000,
            dst_port=25,
            protocol=Protocol.SMTP,
            client_gaps=[SequenceGap(start_offset=5, end_offset=15, missing_bytes=10, direction="client")],
        )
        self.assertTrue(stream.has_gaps)
        self.assertEqual(len(stream.sequence_gaps), 1)
        summary = stream.gap_summary
        self.assertTrue(summary["has_gaps"])
        self.assertEqual(summary["gap_count"], 1)
        self.assertEqual(summary["total_missing_bytes"], 10)

    def test_stage2_marks_gapped_stream_partial(self):
        """Stage 2 must mark StageStatus.PARTIAL when any stream has gaps."""
        pkt1 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10000, dport=25, seq=100, flags="PA") / b"EHLO test\r\n"
        # Gap: seq 111 to 149 missing
        pkt2 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10000, dport=25, seq=150, flags="PA") / b"STARTTLS\r\n"

        streams, stage_res = stage2_reassemble([pkt1, pkt2], ParserOptions())
        self.assertEqual(len(streams), 1)
        self.assertTrue(streams[0].has_gaps)
        self.assertEqual(stage_res.status, StageStatus.PARTIAL)
        self.assertGreater(stage_res.metadata["total_gap_count"], 0)

    def test_stage7_flags_gaps(self):
        """Stage 7 sets validation_status to PARTIAL_STREAM_GAPS when gaps exist."""
        stream = TCPStream(
            stream_id="1.1.1.1:10->2.2.2.2:25",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=10,
            dst_port=25,
            protocol=Protocol.SMTP,
            client_gaps=[SequenceGap(0, 10, 10, "client")],
        )
        st_res = StarttlsAnalysis(starttls_status=StarttlsStatus.NONE, channel_type=ChannelType.PLAINTEXT)
        hs = HandshakeResult()
        status_code, warnings, stage_res = stage7_cross_validate(stream, st_res, hs)
        self.assertEqual(status_code, "PARTIAL_STREAM_GAPS")
        self.assertEqual(stage_res.status, StageStatus.PARTIAL)


class TestRedIssue2TLS13PassiveCertLimitation(unittest.TestCase):
    """🔴 Issue 2: TLS 1.3 Passive Certificate Limitation."""

    def test_tls13_encrypted_cert_visibility(self):
        """When TLS 1.3 is negotiated without cert, cert_visibility is ENCRYPTED_TLS13."""
        ch_bytes = bytes.fromhex(
            "16030100400100003c0303" + "00"*32 + "00" + "00021301" + "0100"
            + "0013002b0003020304" # supported_versions TLS 1.3
        )
        sv_bytes = bytes.fromhex(
            "16030300300200002c0303" + "00"*32 + "130100"
            + "0006002b00020304" # supported_versions TLS 1.3
        )
        res = parse_combined(ch_bytes, sv_bytes)
        self.assertEqual(res.tls_version, TLSVersion.TLS13)
        self.assertIsNone(res.cert)
        self.assertEqual(res.cert_visibility, "ENCRYPTED_TLS13")
        self.assertTrue(any("TLS 1.3 certificate unavailable" in d for d in res.diagnostics))

    def test_stage5_handles_encrypted_tls13(self):
        """Stage 5 returns StageStatus.PARTIAL with explicit note for ENCRYPTED_TLS13."""
        hs = HandshakeResult(
            tls_version=TLSVersion.TLS13,
            cert_visibility="ENCRYPTED_TLS13",
            handshake_status="HANDSHAKE_MESSAGES_COMPLETE",
        )
        leaf, chain, stage_res = stage5_validate_certs(hs)
        self.assertIsNone(leaf)
        self.assertEqual(stage_res.status, StageStatus.PARTIAL)
        self.assertTrue(any("TLS 1.3 LIMITATION" in d for d in stage_res.diagnostics))


class TestRedIssue3HandshakeStatusSemantics(unittest.TestCase):
    """🔴 Issue 3: Handshake Status Semantics."""

    def test_handshake_messages_complete_status(self):
        """CH + SH parsed sets HANDSHAKE_MESSAGES_COMPLETE rather than bare COMPLETED."""
        ch_body = _build_client_hello(cipher_suites=[0xC02F], legacy_version=0x0303)
        ch_rec = _build_record(0x16, 0x0301, ch_body)
        sh_body = _build_server_hello(cipher_suite=0xC02F, legacy_version=0x0303)
        sh_rec = _build_record(0x16, 0x0303, sh_body)
        res = parse_combined(ch_rec, sh_rec)
        self.assertEqual(res.handshake_status, "HANDSHAKE_MESSAGES_COMPLETE")

    def test_rule_engine_accepts_handshake_messages_complete(self):
        """Rule engine does not mark FS inconclusive when HANDSHAKE_MESSAGES_COMPLETE is present."""
        session = SessionAnalysis(
            channel_type=ChannelType.IMPLICIT_TLS,
            tls_version=TLSVersion.TLS12,
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange=KeyExchange.ECDHE,
            handshake_status="HANDSHAKE_MESSAGES_COMPLETE",
        )
        violations = run_rules(session)
        fs_violations = [v for v in violations if v.code in ("FS-001", "FS-002")]
        self.assertEqual(len(fs_violations), 0)


class TestRedIssue4ScoringRenormalization(unittest.TestCase):
    """🔴 Issue 4: Scoring Missing-Evidence Mathematics."""

    def test_inconclusive_components_do_not_drag_score_down(self):
        """
        When cert_health and forward_secrecy are INCONCLUSIVE, the score
        is renormalized over the assessed dimensions (e.g. 100/100 instead of 70/100).
        """
        session = SessionAnalysis(
            session_id="sess_test_renorm",
            protocol=Protocol.SMTP,
            channel_type=ChannelType.IMPLICIT_TLS,
            tls_version=TLSVersion.TLS13,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange=KeyExchange.UNKNOWN,  # INCONCLUSIVE forward secrecy
            cert=CertHealth(),                 # INCONCLUSIVE cert health
            starttls_status=StarttlsStatus.NONE,
            dst_port=465,
        )
        scored = score_session(session)
        exp = scored.scoring_explanation

        self.assertGreater(scored.posture_score, 90.0)
        self.assertEqual(exp["assessed_component_count"], 4)
        self.assertAlmostEqual(exp["evidence_completeness_ratio"], 0.70, places=2)
        self.assertGreater(exp["renormalized_quality_score"], exp["quality_score"])
        self.assertIn("70%", exp["evidence_note"])

    def test_all_inconclusive_scores_zero(self):
        """When 0 components are assessable, score is 0.0 with low completeness note."""
        session = SessionAnalysis(
            session_id="sess_empty",
            channel_type=ChannelType.UNKNOWN,
            tls_version=None,
            cipher_suite=None,
            key_exchange=None,
            cert=CertHealth(),
            starttls_status=StarttlsStatus.UNKNOWN,
        )
        scored = score_session(session)
        self.assertEqual(scored.posture_score, 0.0)


class TestRedIssue5PolicyWiring(unittest.TestCase):
    """🔴 Issue 5: Pipeline Policy Wiring."""

    def test_custom_rule_policy_is_passed_to_engine(self):
        """Custom PolicyCatalog passed in config is actually used in stage 9."""
        custom_catalog = PolicyCatalog(
            policy_id="custom-audit-policy-v1",
            name="Custom Audit Policy",
            version="2.0.0",
            rules={
                "TEST-RULE-001": RuleDefinition(
                    rule_id="TEST-RULE-001",
                    title="Test Mandatory TLS 1.3 Rule",
                    description="Flags any non-TLS 1.3 as violation",
                    severity="CRITICAL",
                    reference="NIST SP 800-52r2 §3.1",
                    category="TLS_VERSION",
                    mandate_level="MUST",
                )
            }
        )
        config = AnalysisConfig(
            rule_policy_id="custom-audit-policy-v1",
            rule_policy_version="2.0.0",
            policy_catalog=custom_catalog,
        )
        session = SessionAnalysis(
            tls_version=TLSVersion.TLS12,
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        )
        violations, stage_res = stage9_evaluate_rules(session, config)
        self.assertEqual(stage_res.metadata["policy_id"], "custom-audit-policy-v1")
        self.assertEqual(stage_res.metadata["policy_version"], "2.0.0")

    def test_custom_scoring_policy_is_passed_to_scorer(self):
        """Custom ScoringPolicy passed in config is actually used in stage 10."""
        custom_scoring = ScoringPolicy(
            policy_id="custom-cipher-heavy-v1",
            policy_version="3.0",
            weights={
                "tls_version": 0.0,
                "cipher_suite": 1.0,
                "cert_health": 0.0,
                "starttls_transition": 0.0,
                "forward_secrecy": 0.0,
                "protocol_context": 0.0,
            }
        )
        config = AnalysisConfig(
            scoring_policy_id="custom-cipher-heavy-v1",
            scoring_policy_version="3.0",
            scoring_policy=custom_scoring,
        )
        session = SessionAnalysis(
            session_id="sess_custom_score",
            tls_version=TLSVersion.TLS10,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            channel_type=ChannelType.IMPLICIT_TLS,
            dst_port=465,
        )
        session, stage_res = stage10_score_session(session, config)
        self.assertEqual(session.scoring_policy_id, "custom-cipher-heavy-v1")
        self.assertEqual(session.scoring_policy_version, "3.0")
        self.assertEqual(stage_res.metadata["scoring_policy_id"], "custom-cipher-heavy-v1")

    def test_enterprise_aggregation_uses_scoring_policy(self):
        """stage12 passes configured scoring policy to compute_enterprise_index."""
        custom_scoring = ScoringPolicy(
            policy_id="enterprise-custom-v1",
            policy_version="1.5",
        )
        config = AnalysisConfig(
            scoring_policy_id="enterprise-custom-v1",
            scoring_policy_version="1.5",
            scoring_policy=custom_scoring,
        )
        session = SessionAnalysis(
            session_id="sess_1",
            posture_score=85.0,
            byte_count=1000,
            risk_tier=RiskTier.LOW,
        )
        ev = EvidenceMetadata(filename="test.pcap", sha256_hash="abc"*21+"a")
        summary, stage_res = stage12_aggregate_enterprise(ev, [session], config)
        self.assertEqual(summary.scoring_policy_id, "enterprise-custom-v1")
        self.assertEqual(summary.scoring_policy_version, "1.5")
        self.assertEqual(stage_res.metadata["scoring_policy_id"], "enterprise-custom-v1")


if __name__ == "__main__":
    unittest.main()
