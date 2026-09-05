"""
tests/test_forensic_models.py
Unit tests for explicit forensic provenance, NIST SP 800-57 public key security profiles,
and schema/engine versioning.
"""

import unittest
from core.models import (
    SCHEMA_VERSION,
    FORENSIC_ENGINE_VERSION,
    AssessmentStatus,
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    EnterpriseSummary,
    EvidenceMetadata,
    FactOrigin,
    ForensicFact,
    KeyAlgorithm,
    PacketProvenance,
    PublicKeyProfile,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)
from core.scorer import assess_cert_health


class TestPublicKeyProfile(unittest.TestCase):
    """Test NIST SP 800-57 Part 1 Rev. 5 key security strength mapping."""

    def test_rsa_key_strengths(self):
        # RSA 1024 -> 80 bits (disallowed by NIST SP 800-57)
        prof_1024 = PublicKeyProfile.compute(key_type="RSA", key_length=1024)
        self.assertEqual(prof_1024.algorithm, KeyAlgorithm.RSA)
        self.assertEqual(prof_1024.effective_security_bits, 80)
        self.assertFalse(prof_1024.nist_compliant)
        self.assertEqual(prof_1024.assessment, AssessmentStatus.VIOLATION)

        # RSA 2048 -> 112 bits (legacy compliant through 2030)
        prof_2048 = PublicKeyProfile.compute(key_type="RSA", key_length=2048)
        self.assertEqual(prof_2048.algorithm, KeyAlgorithm.RSA)
        self.assertEqual(prof_2048.effective_security_bits, 112)
        self.assertTrue(prof_2048.nist_compliant)
        self.assertEqual(prof_2048.assessment, AssessmentStatus.DEGRADED)

        # RSA 3072 -> 128 bits (standard modern baseline)
        prof_3072 = PublicKeyProfile.compute(key_type="RSA", key_length=3072)
        self.assertEqual(prof_3072.algorithm, KeyAlgorithm.RSA)
        self.assertEqual(prof_3072.effective_security_bits, 128)
        self.assertTrue(prof_3072.nist_compliant)
        self.assertEqual(prof_3072.assessment, AssessmentStatus.PASS)

        # RSA 4096 -> 152 bits
        prof_4096 = PublicKeyProfile.compute(key_type="RSA", key_length=4096)
        self.assertEqual(prof_4096.algorithm, KeyAlgorithm.RSA)
        self.assertEqual(prof_4096.effective_security_bits, 152)
        self.assertTrue(prof_4096.nist_compliant)
        self.assertEqual(prof_4096.assessment, AssessmentStatus.PASS)

        # RSA 512 -> 64 bits
        prof_512 = PublicKeyProfile.compute(key_type="RSA", key_length=512)
        self.assertEqual(prof_512.effective_security_bits, 64)
        self.assertFalse(prof_512.nist_compliant)
        self.assertEqual(prof_512.assessment, AssessmentStatus.VIOLATION)

    def test_elliptic_curve_strengths(self):
        # EC 256 (secp256r1 / P-256) -> 128 bits
        prof_p256 = PublicKeyProfile.compute(key_type="EC", key_length=256, curve_name="secp256r1")
        self.assertEqual(prof_p256.algorithm, KeyAlgorithm.ECDSA)
        self.assertEqual(prof_p256.effective_security_bits, 128)
        self.assertTrue(prof_p256.nist_compliant)
        self.assertEqual(prof_p256.assessment, AssessmentStatus.PASS)

        # EC 384 (secp384r1 / P-384) -> 192 bits
        prof_p384 = PublicKeyProfile.compute(key_type="EC", key_length=384, curve_name="secp384r1")
        self.assertEqual(prof_p384.effective_security_bits, 192)
        self.assertTrue(prof_p384.nist_compliant)
        self.assertEqual(prof_p384.assessment, AssessmentStatus.PASS)

        # EC 521 (secp521r1 / P-521) -> 256 bits
        prof_p521 = PublicKeyProfile.compute(key_type="EC", key_length=521, curve_name="secp521r1")
        self.assertEqual(prof_p521.effective_security_bits, 256)
        self.assertTrue(prof_p521.nist_compliant)
        self.assertEqual(prof_p521.assessment, AssessmentStatus.PASS)

        # EC 224 (secp224r1) -> 112 bits (degraded legacy)
        prof_p224 = PublicKeyProfile.compute(key_type="EC", key_length=224, curve_name="secp224r1")
        self.assertEqual(prof_p224.effective_security_bits, 112)
        self.assertTrue(prof_p224.nist_compliant)
        self.assertEqual(prof_p224.assessment, AssessmentStatus.DEGRADED)

        # Weak EC 192 -> 80 bits (< 112 bits, disallowed)
        prof_192 = PublicKeyProfile.compute(key_type="EC", key_length=192)
        self.assertEqual(prof_192.effective_security_bits, 80)
        self.assertFalse(prof_192.nist_compliant)
        self.assertEqual(prof_192.assessment, AssessmentStatus.VIOLATION)

    def test_edwards_curves(self):
        # Ed25519 -> 128 bits
        prof_ed25519 = PublicKeyProfile.compute(key_type="Ed25519", key_length=256)
        self.assertEqual(prof_ed25519.algorithm, KeyAlgorithm.ED25519)
        self.assertEqual(prof_ed25519.effective_security_bits, 128)
        self.assertTrue(prof_ed25519.nist_compliant)
        self.assertEqual(prof_ed25519.assessment, AssessmentStatus.PASS)

        # Ed448 -> 224 bits
        prof_ed448 = PublicKeyProfile.compute(key_type="Ed448", key_length=448)
        self.assertEqual(prof_ed448.algorithm, KeyAlgorithm.ED448)
        self.assertEqual(prof_ed448.effective_security_bits, 224)
        self.assertTrue(prof_ed448.nist_compliant)
        self.assertEqual(prof_ed448.assessment, AssessmentStatus.PASS)

    def test_dsa_key_strengths(self):
        # DSA 1024 -> 80 bits (disallowed)
        prof_dsa_1024 = PublicKeyProfile.compute(key_type="DSA", key_length=1024)
        self.assertEqual(prof_dsa_1024.algorithm, KeyAlgorithm.DSA)
        self.assertEqual(prof_dsa_1024.effective_security_bits, 80)
        self.assertFalse(prof_dsa_1024.nist_compliant)
        self.assertEqual(prof_dsa_1024.assessment, AssessmentStatus.VIOLATION)

        # DSA 2048 -> 112 bits
        prof_dsa_2048 = PublicKeyProfile.compute(key_type="DSA", key_length=2048)
        self.assertEqual(prof_dsa_2048.effective_security_bits, 112)
        self.assertTrue(prof_dsa_2048.nist_compliant)
        self.assertEqual(prof_dsa_2048.assessment, AssessmentStatus.DEGRADED)

    def test_unknown_key(self):
        prof_unknown = PublicKeyProfile.compute(key_type=None, key_length=None)
        self.assertEqual(prof_unknown.algorithm, KeyAlgorithm.UNKNOWN)
        self.assertIsNone(prof_unknown.effective_security_bits)
        self.assertFalse(prof_unknown.nist_compliant)
        self.assertEqual(prof_unknown.assessment, AssessmentStatus.INCONCLUSIVE)

    def test_public_key_profile_serialization(self):
        prof = PublicKeyProfile.compute(key_type="RSA", key_length=2048)
        d = prof.to_dict()
        self.assertEqual(d["algorithm"], "RSA")
        self.assertEqual(d["raw_key_length"], 2048)
        self.assertEqual(d["effective_security_bits"], 112)
        self.assertTrue(d["nist_compliant"])
        self.assertEqual(d["assessment"], "DEGRADED")
        self.assertIn("112-bit security", d["notes"])


class TestForensicProvenanceAndFacts(unittest.TestCase):
    """Test PacketProvenance, ForensicFact[T], and FactOrigin models."""

    def test_provenance_dataclass(self):
        prov = PacketProvenance(
            packet_index=42,
            stream_id="192.168.1.10:50123-10.0.0.1:465",
            record_offset=128,
            timestamp=1700000000.5,
            frame_length=1420,
            diagnostic="ServerHello record boundary confirmed",
        )
        d = prov.to_dict()
        self.assertEqual(d["packet_index"], 42)
        self.assertEqual(d["stream_id"], "192.168.1.10:50123-10.0.0.1:465")
        self.assertEqual(d["record_offset"], 128)
        self.assertEqual(d["timestamp"], 1700000000.5)
        self.assertEqual(d["frame_length"], 1420)
        self.assertIn("ServerHello", d["diagnostic"])

    def test_forensic_fact_observed_vs_inferred(self):
        fact_obs = ForensicFact(
            name="tls_version",
            value=TLSVersion.TLS13,
            origin=FactOrigin.OBSERVED,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        d_obs = fact_obs.to_dict()
        self.assertEqual(d_obs["name"], "tls_version")
        self.assertEqual(d_obs["value"], "TLS1.3")
        self.assertEqual(d_obs["origin"], "OBSERVED")
        self.assertEqual(d_obs["confidence"], "CONFIRMED")

        fact_inf = ForensicFact(
            name="protocol",
            value="IMAP",
            origin=FactOrigin.INFERRED,
            confidence=ConfidenceLevel.HIGH,
            diagnostic="Inferred from destination port 993",
        )
        d_inf = fact_inf.to_dict()
        self.assertEqual(d_inf["origin"], "INFERRED")
        self.assertEqual(d_inf["confidence"], "HIGH")

    def test_unknown_vs_zero_separation(self):
        """Forensic separation: unmeasured (None/UNKNOWN) is never conflated with zero."""
        fact_unmeasured = ForensicFact(
            name="bytes_pre_tls",
            value=None,
            origin=FactOrigin.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            diagnostic="Not measured in capture",
        )
        self.assertIsNone(fact_unmeasured.value)
        self.assertEqual(fact_unmeasured.origin, FactOrigin.UNKNOWN)

        fact_zero_bytes = ForensicFact(
            name="bytes_pre_tls",
            value=0,
            origin=FactOrigin.OBSERVED,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostic="Zero cleartext bytes confirmed before TLS ClientHello",
        )
        self.assertEqual(fact_zero_bytes.value, 0)
        self.assertEqual(fact_zero_bytes.origin, FactOrigin.OBSERVED)


class TestCertHealthIntegration(unittest.TestCase):
    """Test CertHealth automatic public_key derivation and serialization."""

    def test_cert_health_auto_computes_public_key(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=2048,
            key_type="RSA",
            signature_algorithm="SHA256withRSA",
        )
        self.assertIsNotNone(cert.public_key)
        self.assertEqual(cert.public_key.algorithm, KeyAlgorithm.RSA)
        self.assertEqual(cert.public_key.effective_security_bits, 112)
        self.assertTrue(cert.public_key.nist_compliant)

        # Serialized dict includes public_key
        d = cert.to_dict()
        self.assertIn("public_key", d)
        self.assertEqual(d["public_key"]["algorithm"], "RSA")
        self.assertEqual(d["public_key"]["effective_security_bits"], 112)

    def test_cert_health_ec_auto_computes_public_key(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=256,
            key_type="EC",
            curve_name="secp256r1",
        )
        self.assertIsNotNone(cert.public_key)
        self.assertEqual(cert.public_key.algorithm, KeyAlgorithm.ECDSA)
        self.assertEqual(cert.public_key.effective_security_bits, 128)
        self.assertTrue(cert.public_key.nist_compliant)


class TestSchemaVersioning(unittest.TestCase):
    """Test schema and forensic engine version tracking in models."""

    def test_session_analysis_versions(self):
        s = SessionAnalysis(session_id="test1234")
        self.assertEqual(s.schema_version, SCHEMA_VERSION)
        self.assertEqual(s.forensic_engine_version, FORENSIC_ENGINE_VERSION)
        self.assertEqual(s.schema_version, "1.1.0")
        self.assertEqual(s.forensic_engine_version, "0.2.0")

        d = s.to_dict()
        self.assertEqual(d["schema_version"], "1.1.0")
        self.assertEqual(d["forensic_engine_version"], "0.2.0")
        self.assertIn("facts", d)

    def test_enterprise_summary_versions(self):
        summary = EnterpriseSummary()
        self.assertEqual(summary.schema_version, SCHEMA_VERSION)
        self.assertEqual(summary.forensic_engine_version, FORENSIC_ENGINE_VERSION)

        d = summary.to_dict()
        self.assertEqual(d["schema_version"], "1.1.0")
        self.assertEqual(d["forensic_engine_version"], "0.2.0")


class TestScorerCertNistIntegration(unittest.TestCase):
    """Test scorer cert health assessment with NIST SP 800-57 security profiles."""

    def test_rsa_2048_profile_in_score(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=2048,
            key_type="RSA",
            signature_algorithm="SHA256withRSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        exp = assess_cert_health(s)
        self.assertEqual(exp.component_score, 100.0)
        self.assertEqual(exp.assessment, AssessmentStatus.PASS)
        self.assertIn("112b sec", exp.observed)
        self.assertIn("112-bit security baseline", exp.reason)

    def test_rsa_1024_profile_in_score(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=1024,
            key_type="RSA",
            signature_algorithm="SHA256withRSA",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        exp = assess_cert_health(s)
        self.assertEqual(exp.component_score, 70.0)
        self.assertEqual(exp.assessment, AssessmentStatus.VIOLATION)
        self.assertIn("80b sec", exp.observed)
        self.assertIn("below NIST minimum 112 bits", exp.reason)

    def test_ec_256_profile_in_score(self):
        cert = CertHealth(
            validity=CertValidity.VALID,
            key_length_bits=256,
            key_type="EC",
            curve_name="secp256r1",
            signature_algorithm="ECDSA-with-SHA256",
        )
        s = SessionAnalysis(channel_type=ChannelType.IMPLICIT_TLS, cert=cert)
        exp = assess_cert_health(s)
        self.assertEqual(exp.component_score, 100.0)
        self.assertEqual(exp.assessment, AssessmentStatus.PASS)
        self.assertIn("128b sec", exp.observed)
        self.assertIn("modern security baseline", exp.reason)


if __name__ == "__main__":
    unittest.main()
