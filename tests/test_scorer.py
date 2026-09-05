"""
tests/test_scorer.py
Comprehensive test suite for the redesigned Cryptographic Posture Scoring Engine.
Implements the testing requirements from §14 of Docs/scorer_module_redesign.md.
"""

from __future__ import annotations

import unittest
from core.models import (
    AssessmentStatus,
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    EnterpriseSummary,
    EvidenceMetadata,
    KeyExchange,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)
from core.scorer import (
    ScoringPolicy,
    DEFAULT_POLICY,
    assess_tls_version,
    assess_cipher,
    assess_cert_health,
    assess_starttls_transition,
    assess_forward_secrecy,
    assess_protocol_context,
    evaluate_critical_caps,
    score_session,
    compute_enterprise_index,
)


class TestTLSVersionAssessment(unittest.TestCase):
    """Test matrix for TLS Version dimension."""

    def test_tls13_preferred(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.TLS13)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH)
        self.assertTrue(any("8446" in r for r in res.references))

    def test_tls12_secure_baseline(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.TLS12)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 92.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)
        self.assertEqual(res.confidence, ConfidenceLevel.HIGH)

    def test_tls11_deprecated(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.TLS11)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 15.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)
        self.assertTrue(any("8996" in r for r in res.references))

    def test_tls10_deprecated(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.TLS10)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 10.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_sslv3_broken(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.SSLv3)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_sslv2_broken(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.SSLv2)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_unknown_is_inconclusive_zero_not_fifty(self):
        """Doc §5.1 / §2.3: Unknown should be INCONCLUSIVE and 0, NOT an arbitrary 50."""
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, tls_version=TLSVersion.UNKNOWN)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.INCONCLUSIVE)
        self.assertEqual(res.confidence, ConfidenceLevel.LOW)

    def test_plaintext_tls_version(self):
        s = SessionAnalysis(channel_type=ChannelType.PLAINTEXT)
        res = assess_tls_version(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)


class TestCipherSuiteAssessment(unittest.TestCase):
    """Test matrix for Cipher Suite dimension."""

    def test_modern_aead_gcm(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="TLS_AES_256_GCM_SHA384")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_modern_aead_chacha(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="TLS_CHACHA20_POLY1305_SHA256")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_legacy_cbc_sha256(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 75.0)
        self.assertEqual(res.assessment, AssessmentStatus.DEGRADED)

    def test_legacy_cbc_sha1(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 45.0)
        self.assertEqual(res.assessment, AssessmentStatus.DEGRADED)

    def test_3des_sweet32(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 15.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_broken_rc4_null_export(self):
        for c in ("TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"):
            s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite=c)
            res = assess_cipher(s)
            self.assertEqual(res.component_score, 0.0)
            self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_unknown_cipher_inconclusive(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cipher_suite="")
        res = assess_cipher(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.INCONCLUSIVE)
        self.assertEqual(res.confidence, ConfidenceLevel.LOW)


class TestCertHealthAssessment(unittest.TestCase):
    """Test matrix for Certificate Health dimension."""

    def test_valid_strong_cert(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=2048,
            signature_algorithm="SHA256withRSA",
            key_type="RSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_expired_cert(self):
        cert = CertHealth(
            validity=CertValidity.EXPIRED,
            key_length_bits=2048,
            signature_algorithm="SHA256withRSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 40.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_self_signed_cert_degraded(self):
        """Doc §5.3: Self-signed is context-dependent, labeled degraded rather than universally broken."""
        cert = CertHealth(
            validity=CertValidity.SELF_SIGNED,
            is_self_signed=True,
            key_length_bits=2048,
            signature_algorithm="SHA256withRSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 80.0)
        self.assertEqual(res.assessment, AssessmentStatus.DEGRADED)

    def test_sha1_signature(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=2048,
            signature_algorithm="SHA1withRSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 75.0)
        self.assertEqual(res.assessment, AssessmentStatus.DEGRADED)

    def test_weak_rsa_key(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=1024,
            signature_algorithm="SHA256withRSA",
            key_type="RSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 70.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_strong_ec_key(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=256,
            signature_algorithm="ECDSA-with-SHA256",
            key_type="EC",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_missing_cert_inconclusive(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=None)
        res = assess_cert_health(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.INCONCLUSIVE)
        self.assertEqual(res.confidence, ConfidenceLevel.LOW)


class TestStarttlsAssessment(unittest.TestCase):
    """Test matrix for STARTTLS Transition dimension."""

    def test_implicit_tls(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS)
        res = assess_starttls_transition(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_starttls_negotiated(self):
        s = SessionAnalysis(channel_type=ChannelType.STARTTLS, starttls_status=StarttlsStatus.NEGOTIATED)
        res = assess_starttls_transition(s)
        self.assertEqual(res.component_score, 95.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_starttls_stripped(self):
        s = SessionAnalysis(channel_type=ChannelType.STARTTLS, starttls_status=StarttlsStatus.STRIPPED)
        res = assess_starttls_transition(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_buffer_injection(self):
        s = SessionAnalysis(channel_type=ChannelType.STARTTLS, starttls_status=StarttlsStatus.NEGOTIATED, buffer_injection_detected=True)
        res = assess_starttls_transition(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_starttls_advertised_but_unused(self):
        s = SessionAnalysis(channel_type=ChannelType.PLAINTEXT, starttls_status=StarttlsStatus.ADVERTISED)
        res = assess_starttls_transition(s)
        self.assertEqual(res.component_score, 20.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)


class TestForwardSecrecyAssessment(unittest.TestCase):
    """Test matrix for Forward Secrecy dimension."""

    def test_ecdhe(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, key_exchange=KeyExchange.ECDHE)
        res = assess_forward_secrecy(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_dhe(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, key_exchange=KeyExchange.DHE)
        res = assess_forward_secrecy(s)
        self.assertEqual(res.component_score, 85.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_static_rsa(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, key_exchange=KeyExchange.RSA)
        res = assess_forward_secrecy(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)

    def test_unknown(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, key_exchange=KeyExchange.UNKNOWN)
        res = assess_forward_secrecy(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.INCONCLUSIVE)


class TestProtocolContextAssessment(unittest.TestCase):
    """Test matrix for Protocol Context dimension."""

    def test_implicit_tls_port_993(self):
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, dst_port=993, protocol=Protocol.IMAP)
        res = assess_protocol_context(s)
        self.assertEqual(res.component_score, 100.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_starttls_relay_port_587(self):
        s = SessionAnalysis(channel_type=ChannelType.STARTTLS, dst_port=587, protocol=Protocol.SMTP)
        res = assess_protocol_context(s)
        self.assertEqual(res.component_score, 85.0)
        self.assertEqual(res.assessment, AssessmentStatus.PASS)

    def test_starttls_access_port_143(self):
        s = SessionAnalysis(channel_type=ChannelType.STARTTLS, dst_port=143, protocol=Protocol.IMAP)
        res = assess_protocol_context(s)
        self.assertEqual(res.component_score, 50.0)
        self.assertEqual(res.assessment, AssessmentStatus.DEGRADED)

    def test_plaintext_port_25(self):
        s = SessionAnalysis(channel_type=ChannelType.PLAINTEXT, dst_port=25, protocol=Protocol.SMTP)
        res = assess_protocol_context(s)
        self.assertEqual(res.component_score, 0.0)
        self.assertEqual(res.assessment, AssessmentStatus.VIOLATION)


class TestCriticalCapsAndNoDoubleCounting(unittest.TestCase):
    """Verify that score caps prevent double-counting and catastrophic flaws cannot be averaged away."""

    def test_buffer_injection_caps_at_15_and_forces_critical(self):
        """Even with perfect TLS 1.3, AES-GCM, and ECDHE, buffer injection caps score at 15."""
        s = SessionAnalysis(
            channel_type=ChannelType.STARTTLS,
            starttls_status=StarttlsStatus.NEGOTIATED,
            tls_version=TLSVersion.TLS13,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange=KeyExchange.ECDHE,
            cert=CertHealth(validity=CertValidity.VALID, key_length_bits=2048, signature_algorithm="SHA256withRSA"),
            dst_port=587,
            buffer_injection_detected=True,
        )
        scored = score_session(s)
        self.assertLessEqual(scored.posture_score, 15.0)
        self.assertEqual(scored.risk_tier, RiskTier.CRITICAL)
        self.assertTrue(len(scored.scoring_explanation["critical_caps_applied"]) > 0)

    def test_starttls_stripping_caps_at_15_and_forces_critical(self):
        s = SessionAnalysis(
            channel_type=ChannelType.STARTTLS,
            starttls_status=StarttlsStatus.STRIPPED,
            dst_port=25,
            protocol=Protocol.SMTP,
        )
        scored = score_session(s)
        self.assertLessEqual(scored.posture_score, 15.0)
        self.assertEqual(scored.risk_tier, RiskTier.CRITICAL)

    def test_plaintext_caps_at_zero(self):
        s = SessionAnalysis(
            channel_type=ChannelType.PLAINTEXT,
            dst_port=25,
            protocol=Protocol.SMTP,
        )
        scored = score_session(s)
        self.assertEqual(scored.posture_score, 0.0)
        self.assertEqual(scored.risk_tier, RiskTier.CRITICAL)

    def test_sslv3_caps_at_15(self):
        s = SessionAnalysis(
            channel_type=ChannelType.IMPLICIT_TLS,
            tls_version=TLSVersion.SSLv3,
            cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            dst_port=993,
        )
        scored = score_session(s)
        self.assertLessEqual(scored.posture_score, 15.0)
        self.assertEqual(scored.risk_tier, RiskTier.CRITICAL)


class TestExplanationModel(unittest.TestCase):
    """Verify structured explanation fields."""

    def test_explanation_structure_and_references(self):
        s = SessionAnalysis(
            channel_type=ChannelType.IMPLICIT_TLS,
            tls_version=TLSVersion.TLS12,
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange=KeyExchange.ECDHE,
            cert=CertHealth(validity=CertValidity.VALID, key_length_bits=2048, signature_algorithm="SHA256withRSA"),
            dst_port=993,
            protocol=Protocol.IMAP,
        )
        scored = score_session(s)
        expl = scored.scoring_explanation
        self.assertIsNotNone(expl)
        self.assertEqual(expl["policy_id"], "crypto-posture-v1")
        self.assertEqual(expl["policy_version"], "1.0")
        self.assertEqual(len(expl["components"]), 6)
        self.assertEqual(expl["overall_confidence"], "HIGH")

        # Verify every component has observed, assessment, contribution, and references
        for c in expl["components"]:
            self.assertIn("component", c)
            self.assertIn("observed", c)
            self.assertIn("assessment", c)
            self.assertIn("contribution", c)
            self.assertIn("references", c)
            self.assertIn("reason", c)


class TestSensitivityAnalysis(unittest.TestCase):
    """
    Sensitivity analysis (§11 Step 5):
    Perturb weights within reasonable ranges (+/- 5%) and verify that
    the relative ordering of standard scenarios remains stable.
    """

    def test_relative_ranking_stability(self):
        # Scenario A: Clean TLS 1.3
        clean = SessionAnalysis(
            channel_type=ChannelType.IMPLICIT_TLS,
            tls_version=TLSVersion.TLS13,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange=KeyExchange.ECDHE,
            cert=CertHealth(validity=CertValidity.VALID, key_length_bits=2048, signature_algorithm="SHA256withRSA"),
            dst_port=993,
        )
        # Scenario B: Deprecated TLS 1.0 + 3DES
        degraded = SessionAnalysis(
            channel_type=ChannelType.STARTTLS,
            starttls_status=StarttlsStatus.NEGOTIATED,
            tls_version=TLSVersion.TLS10,
            cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_exchange=KeyExchange.RSA,
            cert=CertHealth(validity=CertValidity.VALID, key_length_bits=1024, signature_algorithm="SHA1withRSA"),
            dst_port=25,
        )
        # Scenario C: Plaintext attack
        attack = SessionAnalysis(
            channel_type=ChannelType.PLAINTEXT,
            starttls_status=StarttlsStatus.STRIPPED,
            dst_port=25,
        )

        policies = [
            DEFAULT_POLICY,
            # Perturbation 1: Higher version weight, lower cipher weight
            ScoringPolicy(weights={"tls_version": 0.30, "cipher_suite": 0.15, "cert_health": 0.20, "starttls_transition": 0.15, "forward_secrecy": 0.10, "protocol_context": 0.10}),
            # Perturbation 2: Higher cert weight, lower transition weight
            ScoringPolicy(weights={"tls_version": 0.25, "cipher_suite": 0.20, "cert_health": 0.25, "starttls_transition": 0.10, "forward_secrecy": 0.10, "protocol_context": 0.10}),
            # Perturbation 3: Higher forward secrecy
            ScoringPolicy(weights={"tls_version": 0.20, "cipher_suite": 0.20, "cert_health": 0.20, "starttls_transition": 0.15, "forward_secrecy": 0.15, "protocol_context": 0.10}),
        ]

        for p in policies:
            sc_clean = score_session(clean, policy=p).posture_score
            sc_degraded = score_session(degraded, policy=p).posture_score
            sc_attack = score_session(attack, policy=p).posture_score

            self.assertGreater(sc_clean, 80.0, f"Clean should remain LOW risk under {p.weights}")
            self.assertGreater(sc_clean, sc_degraded, f"Clean must outrank degraded under {p.weights}")
            self.assertGreater(sc_degraded, sc_attack, f"Degraded must outrank attack under {p.weights}")
            self.assertLessEqual(sc_attack, 15.0, f"Attack must remain capped under {p.weights}")


class TestEnterprisePostureIndex(unittest.TestCase):
    """Test matrix for Enterprise Posture Index (§13)."""

    def test_empty_sessions(self):
        summary = EnterpriseSummary(sessions=[])
        res = compute_enterprise_index(summary)
        self.assertEqual(res.enterprise_posture_index, 0.0)
        self.assertEqual(res.overall_risk_tier, RiskTier.CRITICAL)
        self.assertIn("enterprise_explanation", res.to_dict())

    def test_zero_score_handling_no_divide_by_zero(self):
        s1 = SessionAnalysis(posture_score=95.0, byte_count=100000, risk_tier=RiskTier.LOW)
        s2 = SessionAnalysis(posture_score=0.0, byte_count=50000, risk_tier=RiskTier.CRITICAL)
        summary = EnterpriseSummary(sessions=[s1, s2])
        res = compute_enterprise_index(summary)
        self.assertGreaterEqual(res.enterprise_posture_index, 0.0)
        self.assertLessEqual(res.enterprise_posture_index, 100.0)
        # Because of zero-score session with large volume, EPI should reflect severe risk
        self.assertEqual(res.overall_risk_tier, RiskTier.CRITICAL)

    def test_enterprise_explanation_breakdown(self):
        s1 = SessionAnalysis(session_id="s1", posture_score=95.0, byte_count=50000, risk_tier=RiskTier.LOW)
        s2 = SessionAnalysis(session_id="s2", posture_score=15.0, byte_count=20000, risk_tier=RiskTier.CRITICAL)
        summary = EnterpriseSummary(sessions=[s1, s2])
        res = compute_enterprise_index(summary)
        expl = res.enterprise_explanation
        self.assertEqual(expl["total_volume_bytes"], 70000)
        self.assertEqual(len(expl["session_contributions"]), 2)
        self.assertEqual(len(expl["top_risk_contributors"]), 1)
        self.assertEqual(expl["top_risk_contributors"][0]["session_id"], "s2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
