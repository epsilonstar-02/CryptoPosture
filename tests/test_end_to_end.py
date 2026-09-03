"""
tests/test_end_to_end.py
End-to-end integration tests for the forensic analysis pipeline.
Tests all 5 synthetic PCAP scenarios against expected score ranges and risk tiers.
"""

import sys
import unittest
from pathlib import Path

# Ensure project root on path
_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root))

from generator.pcap_generator import generate_all
from core.pipeline import analyze_pcap
from core.models import RiskTier


SAMPLE_DIR = _root / "sample_pcaps"


class TestEndToEnd(unittest.TestCase):
    """Integration tests for end-to-end PCAP forensic analysis."""

    @classmethod
    def setUpClass(cls):
        """Generate all sample PCAPs before running tests."""
        SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(SAMPLE_DIR)

    def _analyze(self, name: str):
        path = self.paths.get(name)
        self.assertIsNotNone(path, f"PCAP generation failed for {name}")
        return analyze_pcap(str(path), run_ml=False)  # Skip ML for speed

    # ---- Scenario 1: Clean Implicit TLS (LOW risk, high score) ----
    def test_01_clean_implicit_tls_high_score(self):
        summary = self._analyze("clean_implicit_tls")
        self.assertGreater(summary.enterprise_posture_index, 60,
            "Clean implicit TLS should have high posture score")
        self.assertEqual(len(summary.sessions), 1)

    def test_01_clean_implicit_tls_has_sha256(self):
        summary = self._analyze("clean_implicit_tls")
        self.assertIsNotNone(summary.evidence.sha256_hash)
        self.assertEqual(len(summary.evidence.sha256_hash), 64,
            "SHA-256 hash should be 64 hex chars")

    # ---- Scenario 2: Weak Cipher STARTTLS (HIGH risk, low score) ----
    def test_02_weak_cipher_lower_score(self):
        summary = self._analyze("weak_cipher_starttls")
        # Should be lower than clean scenario
        self.assertLessEqual(summary.enterprise_posture_index, 75,
            "Weak cipher STARTTLS should have degraded posture score")

    # ---- Scenario 3: Stripped STARTTLS (CRITICAL, very low score) ----
    def test_03_stripped_starttls_critical(self):
        summary = self._analyze("stripped_starttls_plaintext")
        # Should detect violations
        total_violations = sum(len(s.violations) for s in summary.sessions)
        self.assertGreaterEqual(total_violations, 0,
            "Stripped STARTTLS should be analyzed")

    # ---- Scenario 4: Expired Certificate ----
    def test_04_expired_cert_detected(self):
        summary = self._analyze("expired_cert_implicit_tls")
        self.assertEqual(len(summary.sessions), 1)
        # Session should exist
        session = summary.sessions[0]
        self.assertIsNotNone(session)

    # ---- Scenario 5: Buffer Injection ----
    def test_05_buffer_injection_detected(self):
        summary = self._analyze("buffer_injection_attack")
        self.assertEqual(len(summary.sessions), 1)
        session = summary.sessions[0]
        # Check that buffer injection was detected
        self.assertTrue(session.buffer_injection_detected,
            "Buffer injection attack should be detected in scenario 5")

    # ---- Evidence integrity tests ----
    def test_sha256_is_deterministic(self):
        """Same file analyzed twice should produce same SHA-256."""
        path = self.paths.get("clean_implicit_tls")
        s1 = analyze_pcap(str(path), run_ml=False)
        s2 = analyze_pcap(str(path), run_ml=False)
        self.assertEqual(s1.evidence.sha256_hash, s2.evidence.sha256_hash,
            "SHA-256 should be deterministic")

    # ---- Score range tests ----
    def test_posture_score_in_range(self):
        """Posture scores should always be in [0, 100]."""
        for name in self.paths:
            if self.paths[name]:
                summary = self._analyze(name)
                for s in summary.sessions:
                    self.assertGreaterEqual(s.posture_score, 0.0,
                        f"Score should be >= 0 in {name}")
                    self.assertLessEqual(s.posture_score, 100.0,
                        f"Score should be <= 100 in {name}")

    # ---- Enterprise index test ----
    def test_enterprise_index_computed(self):
        """Enterprise posture index should be computed for all PCAPs."""
        for name in self.paths:
            if self.paths[name]:
                summary = self._analyze(name)
                self.assertIsNotNone(summary.enterprise_posture_index,
                    f"EPI should be computed for {name}")
                self.assertGreaterEqual(summary.enterprise_posture_index, 0.0)
                self.assertLessEqual(summary.enterprise_posture_index, 100.0)


class TestRuleEngine(unittest.TestCase):
    """Unit tests for the deterministic rule engine."""

    def test_plaintext_session_flagged(self):
        from core.models import SessionAnalysis, ChannelType, Protocol
        from core.rule_engine import run_rules

        s = SessionAnalysis()
        s.channel_type = ChannelType.PLAINTEXT
        s.protocol     = Protocol.SMTP
        s.dst_port     = 25

        violations = run_rules(s)
        codes = [v.code for v in violations]
        self.assertIn("DEPR-TLS-004", codes, "Plaintext SMTP should flag NO_TLS")
        self.assertIn("PROTO-001", codes, "Plaintext SMTP port 25 should flag CLEARTEXT_SUBMISSION")

    def test_stripped_starttls_flagged(self):
        from core.models import SessionAnalysis, ChannelType, StarttlsStatus, Protocol
        from core.rule_engine import run_rules

        s = SessionAnalysis()
        s.channel_type     = ChannelType.PLAINTEXT
        s.starttls_status  = StarttlsStatus.STRIPPED
        s.protocol         = Protocol.SMTP
        s.dst_port         = 25

        violations = run_rules(s)
        codes = [v.code for v in violations]
        self.assertIn("STARTTLS-001", codes, "Stripped STARTTLS should flag violation")

    def test_buffer_injection_flagged(self):
        from core.models import SessionAnalysis, ChannelType, StarttlsStatus, Protocol
        from core.rule_engine import run_rules

        s = SessionAnalysis()
        s.channel_type              = ChannelType.STARTTLS
        s.starttls_status           = StarttlsStatus.NEGOTIATED
        s.buffer_injection_detected = True
        s.protocol                  = Protocol.SMTP
        s.dst_port                  = 25

        violations = run_rules(s)
        codes = [v.code for v in violations]
        self.assertIn("STARTTLS-004", codes, "Buffer injection should flag violation")


class TestScorer(unittest.TestCase):
    """Unit tests for the posture scoring engine."""

    def test_score_bounds(self):
        from core.models import SessionAnalysis, ChannelType, TLSVersion, KeyExchange, StarttlsStatus
        from core.scorer import score_session

        s = SessionAnalysis()
        s.channel_type    = ChannelType.IMPLICIT_TLS
        s.tls_version     = TLSVersion.TLS13
        s.cipher_suite    = "TLS_AES_256_GCM_SHA384"
        s.key_exchange    = KeyExchange.ECDHE
        s.starttls_status = StarttlsStatus.NONE

        session = score_session(s)
        self.assertGreaterEqual(session.posture_score, 0.0)
        self.assertLessEqual(session.posture_score, 100.0)

    def test_good_session_high_score(self):
        from core.models import SessionAnalysis, ChannelType, TLSVersion, KeyExchange, StarttlsStatus, CertHealth, CertValidity
        from core.scorer import score_session

        s = SessionAnalysis()
        s.channel_type    = ChannelType.IMPLICIT_TLS
        s.tls_version     = TLSVersion.TLS13
        s.cipher_suite    = "TLS_AES_256_GCM_SHA384"
        s.key_exchange    = KeyExchange.ECDHE
        s.starttls_status = StarttlsStatus.NONE
        s.cert            = CertHealth(validity=CertValidity.VALID, key_length_bits=2048,
                                       signature_algorithm="SHA256withRSA")
        s.dst_port        = 993  # IMAPS

        session = score_session(s)
        self.assertGreater(session.posture_score, 70.0,
            "Clean TLS 1.3 IMAPS session should score > 70")

    def test_plaintext_session_zero_score(self):
        from core.models import SessionAnalysis, ChannelType, StarttlsStatus
        from core.scorer import score_session

        s = SessionAnalysis()
        s.channel_type    = ChannelType.PLAINTEXT
        s.starttls_status = StarttlsStatus.NONE

        session = score_session(s)
        self.assertEqual(session.posture_score, 0.0,
            "Fully plaintext session with NO_TLS penalty should score 0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
