"""
core/ml_anomaly.py
Isolation Forest unsupervised ML anomaly detection for TLS sessions.
Implements Pipeline Stage 9 (ML portion) from the project synopsis.

Implements the anomaly score formula from Liu et al., ICDM 2008:
  s(x, n) = 2^(-E(h(x)) / c(n))

Sessions with s(x, n) ≥ 0.65 are flagged as anomalous for forensic inspection.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from .models import (
    ChannelType,
    KeyExchange,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_TLS_VERSION_INT = {
    TLSVersion.SSLv2:   0,
    TLSVersion.SSLv3:   1,
    TLSVersion.TLS10:   2,
    TLSVersion.TLS11:   3,
    TLSVersion.TLS12:   4,
    TLSVersion.TLS13:   5,
    TLSVersion.UNKNOWN: 3,  # Treat as middle
    None:               0,
}

_KE_INT = {
    KeyExchange.RSA:     0,
    KeyExchange.DHE:     1,
    KeyExchange.ECDHE:   2,
    KeyExchange.UNKNOWN: 1,
    None:                0,
}

_CHANNEL_INT = {
    ChannelType.PLAINTEXT:    0,
    ChannelType.STARTTLS:     1,
    ChannelType.IMPLICIT_TLS: 2,
    ChannelType.UNKNOWN:      0,
}

_STARTTLS_INT = {
    StarttlsStatus.STRIPPED:   0,
    StarttlsStatus.FAILED:     1,
    StarttlsStatus.NONE:       2,
    StarttlsStatus.ADVERTISED: 3,
    StarttlsStatus.REQUESTED:  4,
    StarttlsStatus.NEGOTIATED: 5,
}


def extract_features(session: SessionAnalysis) -> List[float]:
    """
    Extract a fixed-length numeric feature vector from a SessionAnalysis.

    Features:
      0: TLS version (ordinal 0–5)
      1: Channel type (0=plain, 1=starttls, 2=implicit)
      2: STARTTLS status (ordinal 0–5)
      3: Key exchange type (0=RSA, 1=DHE, 2=ECDHE)
      4: Forward secrecy flag (0/1)
      5: Buffer injection detected (0/1)
      6: Cert validity (0=unknown, 1=expired, 2=self-signed, 3=valid)
      7: Key length normalized (key_bits / 4096, clamped 0–1)
      8: Has SHA1/MD5 signature (0/1)
      9: Posture score normalized (score / 100)
      10: Violation count
      11: Byte count log-normalized (log10(bytes+1) / 6)
    """
    from .models import CertValidity

    cert = session.cert
    cert_validity_map = {
        CertValidity.UNKNOWN: 0,
        CertValidity.EXPIRED: 1,
        CertValidity.NOT_YET_VALID: 1,
        CertValidity.SELF_SIGNED: 2,
        CertValidity.VALID: 3,
    }

    cert_validity = cert_validity_map.get(
        cert.validity if cert else CertValidity.UNKNOWN, 0
    )
    key_len = (cert.key_length_bits or 0) if cert else 0
    sig = ((cert.signature_algorithm or "")).upper() if cert else ""
    has_weak_sig = 1.0 if ("MD5" in sig or "SHA1" in sig or "SHA-1" in sig) else 0.0

    return [
        float(_TLS_VERSION_INT.get(session.tls_version, 0)),
        float(_CHANNEL_INT.get(session.channel_type, 0)),
        float(_STARTTLS_INT.get(session.starttls_status, 2)),
        float(_KE_INT.get(session.key_exchange, 0)),
        1.0 if (session.key_exchange == KeyExchange.ECDHE or
                session.key_exchange == KeyExchange.DHE) else 0.0,
        1.0 if session.buffer_injection_detected else 0.0,
        float(cert_validity),
        min(1.0, key_len / 4096.0),
        has_weak_sig,
        session.posture_score / 100.0,
        float(len(session.violations)),
        min(1.0, math.log10(session.byte_count + 1) / 6.0),
    ]


FEATURE_NAMES = [
    "tls_version",
    "channel_type",
    "starttls_status",
    "key_exchange",
    "forward_secrecy",
    "buffer_injection",
    "cert_validity",
    "key_length_norm",
    "weak_sig_algo",
    "posture_score_norm",
    "violation_count",
    "byte_count_norm",
]


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class TLSAnomalyDetector:
    """
    Isolation Forest based unsupervised anomaly detector for TLS sessions.

    Trains on the feature vectors of all sessions in a capture, then scores
    each session. Sessions with anomaly_score ≥ threshold are flagged.

    The contamination parameter reflects the expected fraction of anomalous
    sessions in a typical enterprise capture. We set it conservatively.
    """

    ANOMALY_THRESHOLD = 0.65   # From project synopsis

    def __init__(self, contamination: float = 0.15, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit_predict(self, sessions: List[SessionAnalysis]) -> List[SessionAnalysis]:
        """
        Fit the Isolation Forest on all session features and annotate each
        session with is_anomalous, anomaly_score, and anomaly_features.

        Returns the same sessions list with ML fields populated.
        """
        if len(sessions) < 2:
            # Can't train a meaningful model on a single session
            for s in sessions:
                s.is_anomalous  = False
                s.anomaly_score = None
            return sessions

        # Build feature matrix
        X = np.array([extract_features(s) for s in sessions], dtype=np.float64)

        # Fit and score
        self.model.fit(X)
        self._fitted = True

        # sklearn returns negative anomaly scores; we normalize to [0,1]
        raw_scores = self.model.score_samples(X)   # more negative = more anomalous
        # Convert: sklearn score ranges typically [-0.5, 0.5] → normalize to [0,1]
        # s = 1 - normalize(raw) so that higher score = more anomalous
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s == min_s:
            norm_scores = np.zeros(len(raw_scores))
        else:
            norm_scores = 1.0 - (raw_scores - min_s) / (max_s - min_s)

        for i, session in enumerate(sessions):
            score = float(norm_scores[i])
            session.anomaly_score = round(score, 4)
            session.is_anomalous  = score >= self.ANOMALY_THRESHOLD

            # Feature attribution: which features pushed this session toward anomaly?
            if session.is_anomalous:
                session.anomaly_features = self._attribute_features(X[i], X)

        return sessions

    def _attribute_features(self, x: np.ndarray, X: np.ndarray) -> dict:
        """
        Simple feature attribution: compute Z-score of each feature relative
        to the population, then return the top drivers sorted by deviation.
        """
        mean = X.mean(axis=0)
        std  = X.std(axis=0) + 1e-9
        z    = np.abs((x - mean) / std)

        top = sorted(
            zip(FEATURE_NAMES, z.tolist()),
            key=lambda kv: kv[1],
            reverse=True,
        )[:5]

        return {name: round(val, 3) for name, val in top}


def run_anomaly_detection(sessions: List[SessionAnalysis]) -> List[SessionAnalysis]:
    """Convenience function: run full fit-predict cycle on a session list."""
    detector = TLSAnomalyDetector()
    return detector.fit_predict(sessions)
