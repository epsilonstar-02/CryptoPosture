"""
tests/test_ground_truth_benchmark.py
Unit and integration tests for the Three-Tier Ground-Truth Benchmark Suite.

Validates:
  1. Independent Reference Verification: Raw PCAPs match their ground-truth specs
     using only raw packet/cryptography inspections (no core.pipeline bias).
  2. Pipeline Conformance: core.pipeline produces exact matches for expected channel types,
     STARTTLS states, TLS versions, cipher suites, certificate attributes, and violations.
  3. Clean Scenario Guarantee: clean_implicit_tls has ZERO false-positive violations
     (no CERT-003 self-signed violation).
  4. Weak Scenario Guarantee: weak_cipher_starttls has CERT-006 SHA-1 cert violation.
  5. Manifest & Forensic Lineage: manifest.json contains valid SHA-256 capture hashes.
"""

import json
import sys
import unittest
from pathlib import Path

# Ensure project root on path
_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root))

from core.pipeline import analyze_pcap
from core.models import ChannelType, StarttlsStatus, TLSVersion, CertValidity, RiskTier
from generator.pcap_generator import (
    generate_all,
    BENCHMARK_SPECS,
    DEFAULT_OUTPUT_DIR,
    ALL_SCENARIO_GENERATORS,
)
from generator.reference_verifier import (
    verify_scenario_against_spec,
    inspect_pcap_independently,
)


class TestGroundTruthBenchmarkSuite(unittest.TestCase):
    """Rigorous tests ensuring test laboratory fixtures meet ground-truth standards."""

    @classmethod
    def setUpClass(cls):
        """Generate all 15 PCAPs across all 3 tiers before running test suite."""
        DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        cls.paths = generate_all(DEFAULT_OUTPUT_DIR, tier="all", write_manifest=True)

    # -----------------------------------------------------------------------
    # Part 1: Independent Reference Verification (Raw Packet Inspection)
    # -----------------------------------------------------------------------
    def test_independent_reference_verification_all_scenarios(self):
        """
        Independent verification of raw packets against ground truth.
        Does NOT rely on core.pipeline, proving PCAP authenticity independently.
        """
        for scenario_id, path in self.paths.items():
            self.assertIsNotNone(path, f"PCAP missing for {scenario_id}")
            self.assertTrue(path.exists(), f"PCAP file not found: {path}")

            spec = BENCHMARK_SPECS.get(scenario_id)
            self.assertIsNotNone(spec, f"Benchmark spec missing for {scenario_id}")

            report = verify_scenario_against_spec(path, spec)
            self.assertTrue(
                report.passed,
                f"Independent verification failed for '{scenario_id}':\n" +
                "\n".join(f"  - {f}" for f in report.failures)
            )
            self.assertGreater(report.checks_passed, 0)
            self.assertEqual(report.checks_failed, 0)

    # -----------------------------------------------------------------------
    # Part 2: Tier 1 Synthetic Fixtures Ground-Truth Validation
    # -----------------------------------------------------------------------
    def test_tier1_clean_scenario_has_zero_violations(self):
        """Clean scenario must have 0 violations and high posture score (no self-signed bug)."""
        path = self.paths["clean_implicit_tls"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.IMPLICIT_TLS)
        self.assertEqual(sess.tls_version, TLSVersion.TLS13)
        self.assertFalse(sess.cert.is_self_signed, "Clean cert must NOT be flagged as self-signed")
        self.assertEqual(sess.cert.validity, CertValidity.VALID)

        codes = [v.code for v in sess.violations]
        self.assertEqual(codes, [], f"Clean scenario should have 0 violations, found: {codes}")
        self.assertNotIn("CERT-003", codes, "Clean cert must NOT trigger CERT-003")
        self.assertGreaterEqual(sess.posture_score, 90.0)
        self.assertEqual(sess.risk_tier, RiskTier.LOW)

    def test_tier1_weak_cipher_has_sha1_and_3des_violations(self):
        """Weak cipher scenario must trigger CERT-006 (SHA-1 cert) and 3DES/TLS1.0 rules."""
        path = self.paths["weak_cipher_starttls"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.STARTTLS)
        self.assertEqual(sess.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(sess.tls_version, TLSVersion.TLS10)

        codes = [v.code for v in sess.violations]
        self.assertIn("DEPR-TLS-002", codes, "Must flag deprecated TLS 1.0")
        self.assertIn("WEAK-CIPH-002", codes, "Must flag 3DES cipher")
        self.assertIn("CERT-006", codes, "Must flag SHA-1 certificate signature")
        self.assertIn("CERT-008", codes, "Must flag Signature Verification Failure (due to mismatched OID/hash)")
        self.assertNotIn("CERT-003", codes, "Should not falsely flag self-signed")
        self.assertEqual(sess.risk_tier, RiskTier.HIGH)

    def test_tier1_stripped_starttls_ground_truth(self):
        """Stripped STARTTLS scenario must detect stripping and cleartext fallback."""
        path = self.paths["stripped_starttls_plaintext"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.PLAINTEXT)
        self.assertEqual(sess.starttls_status, StarttlsStatus.STRIPPED)

        codes = [v.code for v in sess.violations]
        self.assertIn("STARTTLS-001", codes, "Must flag stripped STARTTLS")
        self.assertIn("DEPR-TLS-004", codes, "Must flag cleartext email transmission")
        self.assertEqual(sess.posture_score, 0.0)
        self.assertEqual(sess.risk_tier, RiskTier.CRITICAL)

    def test_tier1_expired_cert_ground_truth(self):
        """Expired cert scenario must flag CERT-001 without spurious self-signed violation."""
        path = self.paths["expired_cert_implicit_tls"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.cert.validity, CertValidity.EXPIRED)
        codes = [v.code for v in sess.violations]
        self.assertIn("CERT-001", codes, "Must flag expired certificate")
        self.assertNotIn("CERT-003", codes, "Should not falsely flag self-signed")

    def test_tier1_buffer_injection_ground_truth(self):
        """Buffer injection attack must flag STARTTLS-004."""
        path = self.paths["buffer_injection_attack"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertTrue(sess.buffer_injection_detected)
        codes = [v.code for v in sess.violations]
        self.assertIn("STARTTLS-004", codes, "Must flag STARTTLS buffer injection")
        self.assertEqual(sess.risk_tier, RiskTier.CRITICAL)

    # -----------------------------------------------------------------------
    # Part 3: Tier 2 Real Mail-Server Lab Captures Validation
    # -----------------------------------------------------------------------
    def test_tier2_postfix_submission_tls13(self):
        """Postfix 3.x submission session with TLS 1.3 must score high and have 0 violations."""
        path = self.paths["postfix_submission_tls13"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.STARTTLS)
        self.assertEqual(sess.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(sess.tls_version, TLSVersion.TLS13)
        self.assertEqual(len(sess.violations), 0)
        self.assertGreaterEqual(sess.posture_score, 90.0)
        self.assertEqual(sess.risk_tier, RiskTier.LOW)

    def test_tier2_dovecot_imaps_tls12(self):
        """Dovecot IMAPS session must parse full cert chain and score in LOW risk tier."""
        path = self.paths["dovecot_imaps_tls12"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.IMPLICIT_TLS)
        self.assertEqual(sess.tls_version, TLSVersion.TLS12)
        self.assertEqual(len(sess.violations), 0)
        self.assertGreaterEqual(sess.posture_score, 80.0)
        self.assertEqual(sess.risk_tier, RiskTier.LOW)

    def test_tier2_sendmail_opportunistic_starttls(self):
        """Sendmail opportunistic TLS exchange must parse STARTTLS upgrade on port 25."""
        path = self.paths["sendmail_opportunistic_starttls"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.channel_type, ChannelType.STARTTLS)
        self.assertEqual(sess.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(sess.tls_version, TLSVersion.TLS12)
        self.assertEqual(len(sess.violations), 0)
        self.assertGreaterEqual(sess.posture_score, 80.0)

    # -----------------------------------------------------------------------
    # Part 4: Tier 3 Adversarial & Edge-Case Validation
    # -----------------------------------------------------------------------
    def test_tier3_fragmentation_reassembly(self):
        """ClientHello fragmented across TCP segments must be reassembled properly."""
        path = self.paths["tcp_fragmented_client_hello"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.tls_version, TLSVersion.TLS12)
        self.assertIsNotNone(sess.cipher_suite)

    def test_tier3_out_of_order_tcp_delivery(self):
        """Out-of-order TCP segments must be sequenced correctly before TLS parsing."""
        path = self.paths["out_of_order_tcp_segments"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.tls_version, TLSVersion.TLS12)
        self.assertIsNotNone(sess.cipher_suite)

    def test_tier3_retransmission_duplicates(self):
        """Duplicate TCP segments must be ignored by deduplication."""
        path = self.paths["tcp_retransmission_duplicates"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        self.assertEqual(sess.tls_version, TLSVersion.TLS12)

    def test_tier3_incomplete_handshake_rst_isolation(self):
        """Abrupt RST before handshake completes must not crash analyzer."""
        path = self.paths["incomplete_tls_handshake_rst"]
        summary = analyze_pcap(str(path), run_ml=False)
        # Should complete analysis without throwing unhandled exceptions
        self.assertIsNotNone(summary)

    def test_tier3_malformed_record_length_isolation(self):
        """Corrupted TLS record length header must be isolated gracefully."""
        path = self.paths["malformed_tls_record_length"]
        summary = analyze_pcap(str(path), run_ml=False)
        self.assertIsNotNone(summary)

    def test_tier3_cert_weak_rsa1024_violation(self):
        """1024-bit RSA cert must trigger CERT-004 violation."""
        path = self.paths["cert_weak_rsa1024"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        codes = [v.code for v in sess.violations]
        self.assertIn("CERT-004", codes, "Must trigger CERT-004 for 1024-bit key")

    def test_tier3_cert_sni_mismatch_violation(self):
        """SNI hostname mismatch must trigger CERT-009 violation."""
        path = self.paths["cert_sni_mismatch"]
        summary = analyze_pcap(str(path), run_ml=False)
        sess = summary.sessions[0]

        codes = [v.code for v in sess.violations]
        self.assertIn("CERT-009", codes, "Must trigger CERT-009 for SNI mismatch")

    # -----------------------------------------------------------------------
    # Part 5: Manifest & Forensic Provenance Integrity
    # -----------------------------------------------------------------------
    def test_manifest_file_structure_and_hashes(self):
        """Verify manifest.json contains valid entries and matching SHA-256 hashes."""
        manifest_file = DEFAULT_OUTPUT_DIR / "manifest.json"
        self.assertTrue(manifest_file.exists(), "manifest.json must exist in sample_pcaps/")

        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["manifest_version"], "2.0.0")
        self.assertEqual(data["total_scenarios"], 15)
        self.assertIn("tier1_synthetic", data["tiers"])
        self.assertIn("tier2_real_lab", data["tiers"])
        self.assertIn("tier3_adversarial", data["tiers"])

        import hashlib
        for name, entry in data["scenarios"].items():
            pcap_path = DEFAULT_OUTPUT_DIR / entry["filename"]
            self.assertTrue(pcap_path.exists(), f"File {pcap_path} recorded in manifest does not exist")

            with open(pcap_path, "rb") as pf:
                disk_sha = hashlib.sha256(pf.read()).hexdigest()

            self.assertEqual(disk_sha, entry["sha256_hash"],
                             f"SHA-256 mismatch in manifest for {name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
