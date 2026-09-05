"""
tests/test_report_exporter.py
Comprehensive test suite for the redesigned forensic report exporter (core/report_exporter.py).

Verifies:
  1. Security & safe rendering: HTML escaping defense against XSS / injection attacks.
  2. Four-tier section architecture:
     - Section 1: Evidence Integrity & Chain of Custody
     - Section 2: Executive Assessment & Enterprise Risk
     - Section 3: Session Forensic Analysis & Telemetry
     - Section 4: Why This Score? (Standards-Informed Audit Trail)
  3. Structured 5-part Finding Audit (Evidence, Standards Basis, Interpretation, Confidence, Remediation).
  4. Policy & framework version integrity (scoring policy, rule policy, engine version, schema version).
  5. ML outlier inspection and baseline notice rendering.
  6. PRD §10 compliant JSON serialization.
"""

import json
import unittest
from typing import List

from core.models import (
    AnalysisConfig,
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    EnterpriseSummary,
    EvidenceMetadata,
    FindingStatus,
    KeyExchange,
    MLSettings,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
    Violation,
)
from core.report_exporter import export_html, export_json


def _make_sample_summary(
    inject_xss: bool = False,
    is_anomalous: bool = False,
    insufficient_baseline: bool = False,
) -> EnterpriseSummary:
    """Generate a controlled EnterpriseSummary for report exporter testing."""
    filename = "<script>alert('xss_file')</script>.pcap" if inject_xss else "audit_capture.pcap"
    ev = EvidenceMetadata(
        filename=filename,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=1048576,
        total_packets=5000,
        capture_duration=12.345,
        evidence_id="ev_test_12345",
        capture_format="PCAPNG",
        link_layer_type="Ethernet",
        is_tamper_free=True,
    )

    sni_val = "<img src=x onerror=alert('xss_sni')>" if inject_xss else "mail.enterprise.corp"
    subject_cn = "<b onmouseover=alert(1)>evil.com</b>" if inject_xss else "mail.enterprise.corp"

    v1 = Violation(
        code="TLS-001",
        rule_id="TLS-001",
        title="Deprecated Protocol Version" if not inject_xss else "<script>bad_title</script>",
        description="TLS 1.0 is deprecated and prohibited by RFC 8996.",
        severity="CRITICAL",
        reference="RFC 8996 §1, NIST SP 800-52r2 §3.1",
        status=FindingStatus.VIOLATION,
        confidence=ConfidenceLevel.CONFIRMED,
        evidence={"stream_id": "stream_1", "observed_version": "TLS 1.0", "packet_count": 42},
        remediation="Disable TLS 1.0/1.1; enforce minimum TLS 1.2 with AEAD ciphers.",
    )

    cert = CertHealth(
        validity=CertValidity.VALID,
        key_length_bits=2048,
        signature_algorithm="SHA256withRSA",
        subject_cn=subject_cn,
    )

    s1 = SessionAnalysis(
        session_id="sess_001",
        flow_id="stream_1",
        evidence_id=ev.evidence_id,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=993,
        protocol=Protocol.IMAP,
        channel_type=ChannelType.IMPLICIT_TLS,
        starttls_status=StarttlsStatus.NONE,
        tls_version=TLSVersion.TLS10,
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        key_exchange=KeyExchange.RSA,
        sni=sni_val,
        sni_present=True,
        cert=cert,
        violations=[v1],
        posture_score=28.5,
        risk_tier=RiskTier.CRITICAL,
        packet_count=42,
        byte_count=12800,
        scoring_explanation={
            "policy_id": "strict-audit-v2",
            "policy_version": "2.1",
            "overall_confidence": "CONFIRMED",
            "critical_caps_applied": [
                {
                    "finding": "Deprecated TLS Version (TLS 1.0)",
                    "cap_value": 30.0,
                    "reason": "RFC 8996 mandatory deprecation caps score",
                    "reference": "RFC 8996 §1",
                }
            ],
            "components": [
                {
                    "component": "tls_version",
                    "observed": "TLS 1.0",
                    "assessment": "VIOLATION",
                    "component_score": 10.0,
                    "weight": 0.25,
                    "contribution": 2.5,
                    "reason": "Deprecated protocol version",
                    "references": ["RFC 8996"],
                    "confidence": "CONFIRMED",
                }
            ],
        },
    )

    if is_anomalous:
        s1.is_anomalous = True
        s1.anomaly_score = 0.8452
        s1.anomaly_status = "CONFIRMED_ANOMALY"
        s1.anomaly_features = {"tls_version": 3.12, "key_exchange": 2.45}
    elif insufficient_baseline:
        s1.is_anomalous = False
        s1.anomaly_score = None
        s1.anomaly_status = "INSUFFICIENT_BASELINE"
        s1.anomaly_features = {}

    cfg = AnalysisConfig(
        config_id="enterprise-policy-2026",
        scoring_policy_id="strict-audit-v2",
        scoring_policy_version="2.1",
        rule_policy_id="nist-bcp-strict-v2",
        rule_policy_version="2.5",
        engine_version="1.2.0",
        schema_version="2.0.0",
    )

    summary = EnterpriseSummary(
        evidence=ev,
        sessions=[s1],
        enterprise_posture_index=28.5,
        overall_risk_tier=RiskTier.CRITICAL,
        scoring_policy_id="strict-audit-v2",
        scoring_policy_version="2.1",
        analysis_config=cfg.to_dict(),
        critical_sessions=1,
        total_violations=1,
        forensic_engine_version="1.2.0",
        schema_version="2.0.0",
    )
    return summary


class TestReportExporter(unittest.TestCase):
    """Test suite for forensic report generation."""

    # -----------------------------------------------------------------------
    # 1. Security & Safe Rendering (HTML Escaping Defense)
    # -----------------------------------------------------------------------
    def test_html_escaping_defends_against_xss(self):
        """All network and certificate strings must be safely HTML-escaped."""
        summary = _make_sample_summary(inject_xss=True)
        html_out = export_html(summary)

        # Unescaped executable script tags must NOT exist
        self.assertNotIn("<script>alert('xss_file')</script>", html_out)
        self.assertNotIn("<img src=x onerror=alert('xss_sni')>", html_out)
        self.assertNotIn("<b onmouseover=alert(1)>evil.com</b>", html_out)
        self.assertNotIn("<script>bad_title</script>", html_out)

        # Properly escaped forms MUST exist
        self.assertIn("&lt;script&gt;alert(&#x27;xss_file&#x27;)&lt;/script&gt;", html_out)
        self.assertIn("&lt;img src=x onerror=alert(&#x27;xss_sni&#x27;)&gt;", html_out)
        self.assertIn("&lt;b onmouseover=alert(1)&gt;evil.com&lt;/b&gt;", html_out)

    # -----------------------------------------------------------------------
    # 2. Four-Tier Section Architecture
    # -----------------------------------------------------------------------
    def test_four_core_sections_presence(self):
        """Report must contain all four definitive forensic sections."""
        summary = _make_sample_summary()
        html_out = export_html(summary)

        self.assertIn("1. Evidence Integrity &amp; Chain of Custody", html_out)
        self.assertIn("2. Executive Assessment &amp; Enterprise Risk", html_out)
        self.assertIn("3. Session Forensic Analysis &amp; Telemetry", html_out)
        self.assertIn("4. Why This Score? (Standards-Informed Audit Trail)", html_out)

    # -----------------------------------------------------------------------
    # 3. Structured 5-Part Finding Audit Cards
    # -----------------------------------------------------------------------
    def test_structured_five_part_finding_audit(self):
        """Each finding must render Evidence, Standards Basis, Interpretation, Confidence, and Remediation."""
        summary = _make_sample_summary()
        html_out = export_html(summary)

        self.assertIn("1. Evidence:", html_out)
        self.assertIn("2. Standards Basis:", html_out)
        self.assertIn("3. Interpretation:", html_out)
        self.assertIn("4. Recommended Remediation:", html_out)

        # Verify content items
        self.assertIn("RFC 8996 §1, NIST SP 800-52r2 §3.1", html_out)
        self.assertIn("Disable TLS 1.0/1.1; enforce minimum TLS 1.2 with AEAD ciphers.", html_out)
        self.assertIn("TLS-001", html_out)
        self.assertIn("CONFIRMED", html_out)

    # -----------------------------------------------------------------------
    # 4. Policy & Framework Version Integrity
    # -----------------------------------------------------------------------
    def test_policy_and_version_integrity(self):
        """Policy IDs, versions, engine version, and schema version must be bound and displayed."""
        summary = _make_sample_summary()
        html_out = export_html(summary)

        self.assertIn("strict-audit-v2 v2.1", html_out)
        self.assertIn("nist-bcp-strict-v2 v2.5", html_out)
        self.assertIn("enterprise-policy-2026", html_out)
        self.assertIn("v1.2.0", html_out)
        self.assertIn("v2.0.0", html_out)

    # -----------------------------------------------------------------------
    # 5. Machine Learning Anomaly Panel Semantics
    # -----------------------------------------------------------------------
    def test_ml_anomaly_panel_when_outlier(self):
        """When an anomaly is flagged, the capture-relative outlier panel must render."""
        summary = _make_sample_summary(is_anomalous=True)
        html_out = export_html(summary)

        self.assertIn("Capture-Relative Outlier Detected (Isolation Forest)", html_out)
        self.assertIn("Liu et al. Score: 0.8452", html_out)
        self.assertIn("Most Unusual Characteristics (Population Deviation):", html_out)
        self.assertIn("tls_version", html_out)

    def test_ml_panel_when_insufficient_baseline(self):
        """When baseline is insufficient (<5 sessions), a notice must be rendered."""
        summary = _make_sample_summary(insufficient_baseline=True)
        html_out = export_html(summary)

        self.assertIn("ML Anomaly Analysis:", html_out)
        self.assertIn("Capture contains fewer than 5 sessions", html_out)
        self.assertIn("ML: &lt;5 SESSIONS", html_out)

    # -----------------------------------------------------------------------
    # 6. PRD §10 JSON Serialization
    # -----------------------------------------------------------------------
    def test_json_export_validity(self):
        """export_json must generate valid JSON matching PRD §10 schema."""
        summary = _make_sample_summary()
        js_str = export_json(summary)
        data = json.loads(js_str)

        self.assertIn("evidence", data)
        self.assertIn("enterprise_posture_index", data)
        self.assertIn("overall_risk_tier", data)
        self.assertIn("sessions", data)
        self.assertEqual(len(data["sessions"]), 1)
        self.assertEqual(data["sessions"][0]["session_id"], "sess_001")


if __name__ == "__main__":
    unittest.main(verbosity=2)
