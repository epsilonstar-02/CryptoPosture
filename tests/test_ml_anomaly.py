"""
tests/test_ml_anomaly.py
Unit and integration tests for the redesigned Isolation Forest ML Anomaly Detection module.

Verifies:
  1. Zero feature leakage (posture_score and violations excluded from features).
  2. Genuine Liu et al. (ICDM 2008) anomaly scoring without min-max distortion.
  3. Insufficient baseline enforcement (INSUFFICIENT_BASELINE status for N < 5).
  4. Configurable contamination, threshold, and baseline settings via MLSettings.
  5. Descriptive population deviation Z-scores (Unusual Characteristics).
  6. Pipeline isolation (ML findings never mutate deterministic scores).
"""

import math
import unittest
from typing import List

import numpy as np

from core.ml_anomaly import (
    FEATURE_NAMES,
    TLSAnomalyDetector,
    extract_features,
    run_anomaly_detection,
)
from core.models import (
    AnalysisConfig,
    CertHealth,
    CertValidity,
    ChannelType,
    KeyExchange,
    MLSettings,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
    Violation,
)
from core.pipeline import stage11_ml_anomaly


def _make_dummy_session(
    session_id: str,
    tls_version: TLSVersion = TLSVersion.TLS13,
    channel_type: ChannelType = ChannelType.IMPLICIT_TLS,
    starttls_status: StarttlsStatus = StarttlsStatus.NONE,
    key_exchange: KeyExchange = KeyExchange.ECDHE,
    cert_validity: CertValidity = CertValidity.VALID,
    key_length: int = 2048,
    sig_algo: str = "SHA256withRSA",
    sni: str = "mail.example.com",
    bytes_pre_tls: int = 0,
    byte_count: int = 5000,
    buffer_injection: bool = False,
    posture_score: float = 95.0,
    violations: List[Violation] = None,
) -> SessionAnalysis:
    """Construct a synthetic SessionAnalysis with controllable parameters."""
    cert = CertHealth(
        validity=cert_validity,
        key_length_bits=key_length,
        signature_algorithm=sig_algo,
        subject_cn="mail.example.com",
    )
    return SessionAnalysis(
        session_id=session_id,
        protocol=Protocol.IMAP,
        channel_type=channel_type,
        starttls_status=starttls_status,
        tls_version=tls_version,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange=key_exchange,
        sni=sni,
        sni_present=bool(sni),
        cert=cert,
        buffer_injection_detected=buffer_injection,
        bytes_pre_tls=bytes_pre_tls,
        byte_count=byte_count,
        packet_count=20,
        posture_score=posture_score,
        risk_tier=RiskTier.LOW if posture_score > 70 else RiskTier.CRITICAL,
        violations=violations or [],
    )


class TestMLAnomalyRedesign(unittest.TestCase):
    """Test suite for the redesigned ML anomaly module."""

    # -----------------------------------------------------------------------
    # 1. Feature Leakage Verification
    # -----------------------------------------------------------------------
    def test_feature_vector_has_no_leakage(self):
        """Feature extraction must NOT consume posture_score or violations."""
        self.assertEqual(len(FEATURE_NAMES), 12)
        self.assertNotIn("posture_score_norm", FEATURE_NAMES)
        self.assertNotIn("violation_count", FEATURE_NAMES)

        # Build two sessions identical in network telemetry, but with opposite posture scores and violations
        s_clean = _make_dummy_session(
            "s_clean",
            posture_score=100.0,
            violations=[],
        )
        s_polluted = _make_dummy_session(
            "s_polluted",
            posture_score=0.0,
            violations=[
                Violation(code="ERR_CRIT", description="Critical test violation", severity="CRITICAL")
            ],
        )

        vec_clean = extract_features(s_clean)
        vec_polluted = extract_features(s_polluted)

        # Vectors must be bit-identical because telemetry is identical
        self.assertEqual(vec_clean, vec_polluted,
            "Feature vector leaked deterministic scores or violations!")

    def test_raw_feature_encodings(self):
        """Verify individual raw observable feature encodings."""
        s = _make_dummy_session(
            "s1",
            tls_version=TLSVersion.TLS13,
            channel_type=ChannelType.IMPLICIT_TLS,
            key_exchange=KeyExchange.ECDHE,
            buffer_injection=True,
            sni="mail.corp.com",
            bytes_pre_tls=100,
            byte_count=10000,
        )
        vec = extract_features(s)
        self.assertEqual(vec[0], 5.0)   # TLS 1.3
        self.assertEqual(vec[1], 2.0)   # Implicit TLS
        self.assertEqual(vec[4], 1.0)   # Forward secrecy (ECDHE)
        self.assertEqual(vec[5], 1.0)   # Buffer injection
        self.assertEqual(vec[9], 1.0)   # SNI present
        self.assertAlmostEqual(vec[10], min(1.0, math.log10(101.0) / 4.0), places=3)
        self.assertAlmostEqual(vec[11], min(1.0, math.log10(10001.0) / 7.0), places=3)

    # -----------------------------------------------------------------------
    # 2. Population Baseline Guard (INSUFFICIENT_BASELINE)
    # -----------------------------------------------------------------------
    def test_insufficient_baseline_guard(self):
        """Captures with fewer than min_baseline_sessions must return INSUFFICIENT_BASELINE."""
        detector = TLSAnomalyDetector(min_baseline_sessions=5)

        # 3 sessions (< 5)
        sessions = [_make_dummy_session(f"s_{i}") for i in range(3)]
        result = detector.fit_predict(sessions)

        for s in result:
            self.assertFalse(s.is_anomalous)
            self.assertIsNone(s.anomaly_score)
            self.assertEqual(s.anomaly_status, "INSUFFICIENT_BASELINE")
            self.assertEqual(s.anomaly_features, {})

    # -----------------------------------------------------------------------
    # 3. Liu et al. (ICDM 2008) Anomaly Score Computation
    # -----------------------------------------------------------------------
    def test_liu_anomaly_score_properties(self):
        """Scores must represent true Liu et al. isolation depth without min-max stretch."""
        # 14 homogeneous clean TLS 1.3 sessions + 1 stark outlier (SSLv2, Plaintext, Buffer Injection)
        sessions = [
            _make_dummy_session(f"clean_{i}", tls_version=TLSVersion.TLS13, byte_count=2000 + i * 10)
            for i in range(14)
        ]
        outlier = _make_dummy_session(
            "outlier_01",
            tls_version=TLSVersion.SSLv2,
            channel_type=ChannelType.PLAINTEXT,
            starttls_status=StarttlsStatus.STRIPPED,
            key_exchange=KeyExchange.RSA,
            cert_validity=CertValidity.EXPIRED,
            buffer_injection=True,
            sni="",
            bytes_pre_tls=5000,
            byte_count=900000,
        )
        sessions.append(outlier)

        detector = TLSAnomalyDetector(
            contamination=0.07,
            anomaly_threshold=0.60,
            random_state=42,
            min_baseline_sessions=5,
        )
        scored = detector.fit_predict(sessions)

        for s in scored:
            self.assertIsNotNone(s.anomaly_score)
            # Scores must be bounded in (0, 1)
            self.assertGreater(s.anomaly_score, 0.0)
            self.assertLess(s.anomaly_score, 1.0)

        # Verify no artificial min-max normalization:
        # Min-max would force min(scores) == 0.0 and max(scores) == 1.0
        scores = [s.anomaly_score for s in scored]
        self.assertNotEqual(min(scores), 0.0, "Score was artificially min-max normalized!")
        self.assertNotEqual(max(scores), 1.0, "Score was artificially min-max normalized!")

        # The outlier must be identified
        outlier_res = [s for s in scored if s.session_id == "outlier_01"][0]
        self.assertTrue(outlier_res.is_anomalous)
        self.assertEqual(outlier_res.anomaly_status, "CONFIRMED_ANOMALY")
        self.assertGreaterEqual(outlier_res.anomaly_score, 0.60)

    # -----------------------------------------------------------------------
    # 4. Descriptive Feature Deviations (Unusual Characteristics)
    # -----------------------------------------------------------------------
    def test_unusual_characteristics_descriptive_z_scores(self):
        """Top unusual characteristics must report population Z-scores."""
        sessions = [
            _make_dummy_session(f"clean_{i}", tls_version=TLSVersion.TLS13)
            for i in range(14)
        ]
        outlier = _make_dummy_session(
            "outlier",
            tls_version=TLSVersion.SSLv2,
            buffer_injection=True,
            bytes_pre_tls=8000,
        )
        sessions.append(outlier)

        detector = TLSAnomalyDetector(anomaly_threshold=0.55, random_state=42)
        detector.fit_predict(sessions)

        traits = outlier.anomaly_features
        self.assertIsInstance(traits, dict)
        self.assertGreater(len(traits), 0)
        # Buffer injection and bytes_pre_tls diverged heavily from the 14 clean sessions
        top_keys = list(traits.keys())
        self.assertTrue(
            any(k in top_keys for k in ("buffer_injection", "tls_version", "bytes_pre_tls_norm")),
            f"Expected major divergence features in {top_keys}",
        )
        for val in traits.values():
            self.assertGreater(val, 0.0)

    # -----------------------------------------------------------------------
    # 5. Serialization and Backwards Compatibility
    # -----------------------------------------------------------------------
    def test_serialization_contains_both_keys(self):
        """to_dict() must contain unusual_characteristics and top_features."""
        s = _make_dummy_session("s_ser")
        s.is_anomalous = True
        s.anomaly_score = 0.7234
        s.anomaly_status = "CONFIRMED_ANOMALY"
        s.anomaly_features = {"buffer_injection": 3.45}

        data = s.to_dict()["ml_anomaly"]
        self.assertEqual(data["status"], "CONFIRMED_ANOMALY")
        self.assertTrue(data["is_anomalous"])
        self.assertEqual(data["anomaly_score"], 0.7234)
        self.assertEqual(data["evaluation_mode"], "capture_relative")
        self.assertEqual(data["unusual_characteristics"], {"buffer_injection": 3.45})
        self.assertEqual(data["top_features"], {"buffer_injection": 3.45})

    # -----------------------------------------------------------------------
    # 6. Pipeline Isolation and Stage Execution
    # -----------------------------------------------------------------------
    def test_pipeline_stage11_isolation(self):
        """Stage 11 must leave deterministic posture scores and violations untouched."""
        sessions = [
            _make_dummy_session(f"sess_{i}", posture_score=88.5)
            for i in range(10)
        ]
        config = AnalysisConfig(
            ml_settings=MLSettings(enabled=True, anomaly_threshold=0.65)
        )

        updated_sessions, stage_res = stage11_ml_anomaly(sessions, config)

        self.assertEqual(stage_res.status.value, "SUCCESS")
        self.assertEqual(stage_res.metadata["model_family"], "IsolationForest")
        self.assertEqual(stage_res.metadata["feature_version"], "v2-raw-observable")
        self.assertEqual(stage_res.metadata["baseline_mode"], "capture_relative")

        for s in updated_sessions:
            # Deterministic score strictly untouched
            self.assertEqual(s.posture_score, 88.5)
            self.assertEqual(s.risk_tier, RiskTier.LOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
