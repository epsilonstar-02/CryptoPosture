"""
tests/test_rule_engine.py
Policy and compliance test matrix for core/rule_engine.py.
Validates:
  1. PolicyCatalog JSON serialization, deserialization, and metadata integrity
  2. TLS version rules matrix (SSLv2/3, TLS 1.0, TLS 1.1, Plaintext, Inconclusive)
  3. Cipher suite rules matrix (RC4, 3DES, NULL, Export, Generic weak, Clean AEAD)
  4. Forward secrecy evaluation & rule deduplication (FS-001 vs FS-002)
  5. Certificate rules matrix (Expired, Not yet valid, Self-signed, Key lengths, Broken hashes, SNI mismatch, Signature failure)
  6. STARTTLS attack indicators & calibrated confidence (Confirmed vs. Suspected stripping, Buffer injection)
  7. Protocol context rules matrix (Port 587 submission MUST NOT, Port 143/110 access, Opportunistic vs Implicit)
  8. Auditable evidence traceability and explicit outcomes (VIOLATION / PASS / NOT_EVALUATED / INCONCLUSIVE)
"""

import unittest
from datetime import datetime, timezone, timedelta

from core.models import (
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    FindingStatus,
    KeyExchange,
    Protocol,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)
from core.rule_engine import (
    DEFAULT_POLICY_CATALOG,
    PolicyCatalog,
    PolicyEngine,
    RuleDefinition,
    run_rules,
)


class TestPolicyCatalogConfiguration(unittest.TestCase):
    """Test policy catalog serialization and metadata integrity."""

    def test_default_catalog_integrity(self):
        catalog = DEFAULT_POLICY_CATALOG
        self.assertEqual(catalog.policy_id, "nist-bcp-forensic-v1")
        self.assertEqual(catalog.version, "1.2.0")
        self.assertGreater(len(catalog.rules), 20)

        # Check required fields on every rule definition
        for rule_id, rule_def in catalog.rules.items():
            self.assertEqual(rule_id, rule_def.rule_id)
            self.assertTrue(rule_def.title, f"Missing title on {rule_id}")
            self.assertTrue(rule_def.description, f"Missing description on {rule_id}")
            self.assertIn(rule_def.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertTrue(rule_def.reference, f"Missing reference citation on {rule_id}")
            self.assertTrue(rule_def.remediation, f"Missing remediation guidance on {rule_id}")
            self.assertGreater(len(rule_def.source_fields), 0, f"Missing source fields on {rule_id}")

    def test_catalog_json_roundtrip(self):
        catalog = DEFAULT_POLICY_CATALOG
        json_str = catalog.to_json()
        loaded = PolicyCatalog.from_json(json_str)

        self.assertEqual(loaded.policy_id, catalog.policy_id)
        self.assertEqual(loaded.version, catalog.version)
        self.assertEqual(len(loaded.rules), len(catalog.rules))
        self.assertEqual(loaded.rules["DEPR-TLS-001"].severity, "CRITICAL")


class TestTLSVersionRulesMatrix(unittest.TestCase):
    """Test matrix for TLS version deprecation and plaintext rules."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_clean_tls13_session(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS13,
            protocol     = Protocol.SMTP,
            cipher_suite = "TLS_AES_128_GCM_SHA256",
            key_exchange = KeyExchange.ECDHE,
            handshake_status = "COMPLETED",
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        self.assertEqual(findings_by_id["DEPR-TLS-001"].status, FindingStatus.PASS)
        self.assertEqual(findings_by_id["DEPR-TLS-002"].status, FindingStatus.PASS)
        self.assertEqual(findings_by_id["DEPR-TLS-003"].status, FindingStatus.PASS)
        self.assertEqual(findings_by_id["DEPR-TLS-004"].status, FindingStatus.PASS)
        self.assertEqual(len(report.violations), 0)

    def test_sslv3_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.SSLv3,
            protocol     = Protocol.SMTP,
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        v = findings_by_id["DEPR-TLS-001"]
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.confidence, ConfidenceLevel.CONFIRMED)
        self.assertEqual(v.evidence["observed"], "SSLv3")
        self.assertIn("RFC 8996", v.reference)

    def test_tls10_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS10,
            protocol     = Protocol.SMTP,
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        v = findings_by_id["DEPR-TLS-002"]
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "HIGH")

    def test_tls11_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS11,
            protocol     = Protocol.SMTP,
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        v = findings_by_id["DEPR-TLS-003"]
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "HIGH")

    def test_plaintext_session_outcomes(self):
        s = SessionAnalysis(
            channel_type = ChannelType.PLAINTEXT,
            protocol     = Protocol.SMTP,
            dst_port     = 587,
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        # DEPR-TLS-004 is violated
        self.assertEqual(findings_by_id["DEPR-TLS-004"].status, FindingStatus.VIOLATION)
        # Other TLS version rules are NOT_EVALUATED
        self.assertEqual(findings_by_id["DEPR-TLS-001"].status, FindingStatus.NOT_EVALUATED)
        self.assertEqual(findings_by_id["DEPR-TLS-002"].status, FindingStatus.NOT_EVALUATED)

    def test_inconclusive_tls_handshake(self):
        s = SessionAnalysis(
            channel_type     = ChannelType.STARTTLS,
            tls_version      = None,
            handshake_status = "INCONCLUSIVE_TRUNCATED",
            tls_diagnostics  = ["Handshake cut off before ServerHello"],
        )
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}

        # Should explicitly report INCONCLUSIVE rather than silent PASS
        self.assertEqual(findings_by_id["DEPR-TLS-001"].status, FindingStatus.INCONCLUSIVE)
        self.assertEqual(findings_by_id["DEPR-TLS-004"].status, FindingStatus.INCONCLUSIVE)


class TestCipherSuiteRulesMatrix(unittest.TestCase):
    """Test matrix for cipher suite security rules."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_rc4_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cipher_suite = "TLS_RSA_WITH_RC4_128_SHA",
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "WEAK-CIPH-001")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.evidence["observed"], "TLS_RSA_WITH_RC4_128_SHA")

    def test_3des_sweet32_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "WEAK-CIPH-002")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "HIGH")

    def test_null_cipher_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cipher_suite = "TLS_RSA_WITH_NULL_SHA256",
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "WEAK-CIPH-003")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")

    def test_export_cipher_violation(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cipher_suite = "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "WEAK-CIPH-004")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")

    def test_plaintext_ciphers_not_evaluated(self):
        s = SessionAnalysis(channel_type=ChannelType.PLAINTEXT)
        report = self.engine.evaluate(s)
        findings_by_id = {f.rule_id: f for f in report.all_findings}
        self.assertEqual(findings_by_id["WEAK-CIPH-001"].status, FindingStatus.NOT_EVALUATED)


class TestForwardSecrecyAndDeduplication(unittest.TestCase):
    """Test forward secrecy evaluation and dependency deduplication."""

    def test_static_rsa_deduplication(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cipher_suite = "TLS_RSA_WITH_AES_128_CBC_SHA",
            key_exchange = KeyExchange.RSA,
        )

        # With deduplication enabled (default):
        engine_dedup = PolicyEngine(deduplicate=True)
        report_dedup = engine_dedup.evaluate(s)

        # FS-001 is primary violation
        fs1 = next(f for f in report_dedup.all_findings if f.rule_id == "FS-001")
        self.assertEqual(fs1.status, FindingStatus.VIOLATION)
        self.assertTrue(fs1.is_primary)

        # FS-002 is secondary / suppressed
        fs2 = next(f for f in report_dedup.all_findings if f.rule_id == "FS-002")
        self.assertEqual(fs2.status, FindingStatus.VIOLATION)
        self.assertFalse(fs2.is_primary)
        self.assertEqual(fs2.evidence["suppressed_by"], "FS-001")

        # Active violations list should NOT contain suppressed FS-002
        violation_ids = [v.rule_id for v in report_dedup.violations]
        self.assertIn("FS-001", violation_ids)
        self.assertNotIn("FS-002", violation_ids)

        # With deduplication disabled:
        engine_raw = PolicyEngine(deduplicate=False)
        report_raw = engine_raw.evaluate(s)
        raw_ids = [v.rule_id for v in report_raw.violations]
        self.assertIn("FS-001", raw_ids)
        self.assertIn("FS-002", raw_ids)


class TestCertificateRulesMatrix(unittest.TestCase):
    """Test matrix for X.509 certificate compliance and integrity rules."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_expired_certificate(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cert = CertHealth(
                validity = CertValidity.EXPIRED,
                not_after = "2024-01-01T00:00:00+00:00",
                key_length_bits = 2048,
                key_type = "RSA",
                signature_algorithm = "sha256WithRSAEncryption",
            ),
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "CERT-001")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.confidence, ConfidenceLevel.CONFIRMED)

    def test_not_yet_valid_certificate(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cert = CertHealth(
                validity = CertValidity.NOT_YET_VALID,
                not_before = "2030-01-01T00:00:00+00:00",
                key_length_bits = 2048,
                key_type = "RSA",
                signature_algorithm = "sha256WithRSAEncryption",
            ),
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "CERT-002")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "HIGH")

    def test_self_signed_certificate(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            tls_version  = TLSVersion.TLS12,
            cert = CertHealth(
                validity = CertValidity.SELF_SIGNED,
                is_self_signed = True,
                subject_cn = "internal.corp.com",
                key_length_bits = 2048,
                signature_algorithm = "sha256WithRSAEncryption",
            ),
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "CERT-003")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "MEDIUM")

    def test_weak_rsa_and_ec_key_lengths(self):
        # 1024-bit RSA
        s_rsa = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            cert = CertHealth(
                validity = CertValidity.VALID,
                key_length_bits = 1024,
                key_type = "RSA",
                signature_algorithm = "sha256WithRSAEncryption",
            ),
        )
        report_rsa = self.engine.evaluate(s_rsa)
        v_rsa = next(f for f in report_rsa.violations if f.rule_id == "CERT-004")
        self.assertEqual(v_rsa.severity, "HIGH")

        # 192-bit EC
        s_ec = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            cert = CertHealth(
                validity = CertValidity.VALID,
                key_length_bits = 192,
                key_type = "EC",
                signature_algorithm = "ecdsa-with-SHA256",
            ),
        )
        report_ec = self.engine.evaluate(s_ec)
        v_ec = next(f for f in report_ec.violations if f.rule_id == "CERT-005")
        self.assertEqual(v_ec.severity, "HIGH")

    def test_broken_hash_signatures(self):
        # SHA-1
        s_sha1 = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            cert = CertHealth(
                validity = CertValidity.VALID,
                signature_algorithm = "sha1WithRSAEncryption",
            ),
        )
        report_sha1 = self.engine.evaluate(s_sha1)
        self.assertTrue(any(f.rule_id == "CERT-006" for f in report_sha1.violations))

        # MD5
        s_md5 = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            cert = CertHealth(
                validity = CertValidity.VALID,
                signature_algorithm = "md5WithRSAEncryption",
            ),
        )
        report_md5 = self.engine.evaluate(s_md5)
        self.assertTrue(any(f.rule_id == "CERT-007" for f in report_md5.violations))

    def test_certificate_signature_failure_and_sni_mismatch(self):
        s = SessionAnalysis(
            channel_type = ChannelType.IMPLICIT_TLS,
            sni = "mail.company.com",
            cert = CertHealth(
                validity = CertValidity.VALID,
                signature_valid = False,
                san_matches_sni = False,
                san_list = ["other.domain.com"],
                subject_cn = "other.domain.com",
            ),
        )
        report = self.engine.evaluate(s)
        violation_ids = [v.rule_id for v in report.violations]
        self.assertIn("CERT-008", violation_ids)  # Signature verify fail
        self.assertIn("CERT-009", violation_ids)  # SNI mismatch


class TestStarttlsAttackIndicatorsMatrix(unittest.TestCase):
    """Test STARTTLS attack indicator classification and calibrated confidence."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_confirmed_stripping_attack(self):
        s = SessionAnalysis(
            channel_type    = ChannelType.PLAINTEXT,
            starttls_status = StarttlsStatus.STRIPPED,
            protocol        = Protocol.SMTP,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "STARTTLS-001")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.confidence, ConfidenceLevel.CONFIRMED)
        self.assertIn("STRIPTLS", v.description)

    def test_possible_stripping_indicator(self):
        s = SessionAnalysis(
            channel_type    = ChannelType.PLAINTEXT,
            starttls_status = StarttlsStatus.POSSIBLE_STRIPPING,
            protocol        = Protocol.SMTP,
            dst_port        = 587,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "STARTTLS-005")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "HIGH")
        self.assertEqual(v.confidence, ConfidenceLevel.MEDIUM)

    def test_buffer_injection_attack(self):
        s = SessionAnalysis(
            channel_type              = ChannelType.STARTTLS,
            starttls_status           = StarttlsStatus.NEGOTIATED,
            buffer_injection_detected = True,
            protocol                  = Protocol.SMTP,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "STARTTLS-004")
        self.assertEqual(v.status, FindingStatus.VIOLATION)
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.confidence, ConfidenceLevel.CONFIRMED)
        self.assertIn("Poddebniak", v.reference)


class TestProtocolContextMatrix(unittest.TestCase):
    """Test protocol context rules separating RFC MUST vs SHOULD."""

    def setUp(self):
        self.engine = PolicyEngine()

    def test_cleartext_submission_port_587(self):
        s = SessionAnalysis(
            channel_type = ChannelType.PLAINTEXT,
            protocol     = Protocol.SMTP,
            dst_port     = 587,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "PROTO-001")
        self.assertEqual(v.severity, "CRITICAL")
        self.assertEqual(v.mandate_level, "MUST NOT")

    def test_cleartext_mail_access_port_143(self):
        s = SessionAnalysis(
            channel_type = ChannelType.PLAINTEXT,
            protocol     = Protocol.IMAP,
            dst_port     = 143,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "PROTO-002")
        self.assertEqual(v.severity, "CRITICAL")

    def test_opportunistic_starttls_for_access(self):
        s = SessionAnalysis(
            channel_type = ChannelType.STARTTLS,
            protocol     = Protocol.IMAP,
            dst_port     = 143,
        )
        report = self.engine.evaluate(s)
        v = next(f for f in report.violations if f.rule_id == "PROTO-003")
        self.assertEqual(v.severity, "LOW")
        self.assertEqual(v.mandate_level, "SHOULD")


class TestPublicAPIAndSessionIntegration(unittest.TestCase):
    """Verify run_rules attaches policy_findings and populates violations."""

    def test_run_rules_integration(self):
        s = SessionAnalysis(
            channel_type = ChannelType.PLAINTEXT,
            protocol     = Protocol.SMTP,
            dst_port     = 25,
        )
        violations = run_rules(s)
        self.assertIsInstance(violations, list)
        self.assertGreater(len(violations), 0)

        # Verify session has both violations and complete policy findings
        self.assertGreater(len(s.policy_findings), len(violations))
        self.assertTrue(any(f.status == FindingStatus.PASS for f in s.policy_findings))

        # Check to_dict serialization
        d = s.to_dict()
        self.assertIn("violations", d)
        self.assertIn("policy_findings", d)
        self.assertEqual(d["violations"][0]["code"], violations[0].code)
        self.assertIn("confidence", d["violations"][0])
        self.assertIn("evidence", d["violations"][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
