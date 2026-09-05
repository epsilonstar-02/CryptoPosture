"""
core/ml_anomaly.py
Isolation Forest unsupervised ML anomaly detection for TLS sessions.
Implements Pipeline Stage 11 from the project architecture.

Mathematical Foundation:
  Implements the genuine anomaly score formulation from Liu et al., ICDM 2008:
    s(x, n) = 2^(-E(h(x)) / c(n))

  In scikit-learn, IsolationForest.score_samples(X) computes:
    score_samples(X) = - 2^(-E(h(x)) / c(n)) = - s(x, n)
  Therefore, the true Liu et al. anomaly score is directly recovered by:
    s(x, n) = - score_samples(X) ∈ (0, 1)

  We deliberately eliminate artificial batch min-max normalization, preserving the
  absolute statistical isolation depth across different capture files.

Methodological Architecture:
  1. Strict Separation: Deterministic compliance (NIST / RFC rules) establishes the
     authoritative security posture. ML is a secondary unsupervised observer flagging
     statistical outliers relative to the capture population.
  2. Zero Score Leakage: Feature vector consists strictly of 12 raw observable network,
     cryptographic, and protocol telemetry parameters. No posture scores or violation counts.
  3. Population Baseline Guard: Requires at least `min_baseline_sessions` (default 5)
     to form a statistically meaningful cluster. Below this, sessions receive an explicit
     `INSUFFICIENT_BASELINE` status rather than a false negative.
  4. Descriptive Deviation: Z-scores across features are labeled as descriptive
     "unusual feature deviations" relative to the capture population, not causal tree attribution.
"""

from __future__ import annotations

import math
from typing import List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from .models import (
    CertValidity,
    ChannelType,
    KeyExchange,
    MLSettings,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)


# ---------------------------------------------------------------------------
# Feature Extraction (12 Raw Observable Parameters — Zero Derived Leakage)
# ---------------------------------------------------------------------------

_TLS_VERSION_INT = {
    TLSVersion.SSLv2:   0,
    TLSVersion.SSLv3:   1,
    TLSVersion.TLS10:   2,
    TLSVersion.TLS11:   3,
    TLSVersion.TLS12:   4,
    TLSVersion.TLS13:   5,
    TLSVersion.UNKNOWN: 3,  # Median default for unparsed/inconclusive
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
    StarttlsStatus.STRIPPED:           0,
    StarttlsStatus.POSSIBLE_STRIPPING: 0,
    StarttlsStatus.FAILED:             1,
    StarttlsStatus.NONE:               2,
    StarttlsStatus.INCONCLUSIVE:       2,
    StarttlsStatus.UNKNOWN:            2,
    StarttlsStatus.ADVERTISED:         3,
    StarttlsStatus.REQUESTED:          4,
    StarttlsStatus.NEGOTIATED:         5,
}

_CERT_VALIDITY_INT = {
    CertValidity.UNKNOWN:       0,
    CertValidity.EXPIRED:       1,
    CertValidity.NOT_YET_VALID: 1,
    CertValidity.SELF_SIGNED:   2,
    CertValidity.VALID:         3,
}


def extract_features(session: SessionAnalysis) -> List[float]:
    """
    Extract a fixed-length numeric feature vector of 12 raw observable parameters.

    Features:
      0: TLS version (ordinal 0–5)
      1: Channel type (0=plain, 1=starttls, 2=implicit)
      2: STARTTLS status (ordinal 0–5)
      3: Key exchange type (0=RSA, 1=DHE, 2=ECDHE)
      4: Forward secrecy flag (0/1)
      5: Buffer injection detected (0/1)
      6: Cert validity (0=unknown, 1=expired/invalid, 2=self-signed, 3=valid)
      7: Key length normalized (key_bits / 4096, clamped 0–1)
      8: Has SHA1/MD5 signature (0/1)
      9: SNI extension present (0/1) [Raw observable — replaces leaked posture score]
      10: Pre-TLS cleartext volume normalized (log10(bytes+1) / 4) [Raw observable — replaces leaked violations]
      11: Total session byte volume normalized (log10(bytes+1) / 7)
    """
    cert = session.cert
    cert_validity = _CERT_VALIDITY_INT.get(
        cert.validity if cert else CertValidity.UNKNOWN, 0
    )
    key_len = (cert.key_length_bits or 0) if cert else 0
    sig = (cert.signature_algorithm or "").upper() if cert else ""
    has_weak_sig = 1.0 if ("MD5" in sig or "SHA1" in sig or "SHA-1" in sig) else 0.0

    # Key exchange forward secrecy flag
    is_pfs = 1.0 if (
        session.key_exchange == KeyExchange.ECDHE or
        session.key_exchange == KeyExchange.DHE
    ) else 0.0

    # Buffer injection cleartext flag
    buffer_inj = 1.0 if session.buffer_injection_detected else 0.0

    # SNI presence observable
    sni_flag = 1.0 if (session.sni or session.sni_present) else 0.0

    # Pre-TLS cleartext bytes observed before TLS record layer
    pre_tls_norm = min(1.0, math.log10(max(0, session.bytes_pre_tls) + 1.0) / 4.0)

    # Total session flow byte volume log-normalized
    byte_count_norm = min(1.0, math.log10(max(0, session.byte_count) + 1.0) / 7.0)

    return [
        float(_TLS_VERSION_INT.get(session.tls_version, 0)),
        float(_CHANNEL_INT.get(session.channel_type, 0)),
        float(_STARTTLS_INT.get(session.starttls_status, 2)),
        float(_KE_INT.get(session.key_exchange, 0)),
        is_pfs,
        buffer_inj,
        float(cert_validity),
        min(1.0, key_len / 4096.0),
        has_weak_sig,
        sni_flag,
        pre_tls_norm,
        byte_count_norm,
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
    "sni_present",
    "bytes_pre_tls_norm",
    "byte_count_norm",
]


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class TLSAnomalyDetector:
    """
    Isolation Forest unsupervised anomaly detector for TLS sessions.

    Trains on the raw observable feature vectors of sessions within a capture
    or reference baseline, computing the Liu et al. (ICDM 2008) anomaly score:
      s(x, n) = 2^(-E(h(x)) / c(n))

    Sessions with s(x, n) ≥ anomaly_threshold are flagged as anomalous.
    """

    def __init__(
        self,
        settings: Optional[MLSettings] = None,
        contamination: Optional[float] = None,
        anomaly_threshold: Optional[float] = None,
        n_estimators: Optional[int] = None,
        random_state: Optional[int] = None,
        min_baseline_sessions: Optional[int] = None,
    ):
        base_settings = settings or MLSettings()
        self.contamination = (
            contamination if contamination is not None else base_settings.contamination
        )
        self.anomaly_threshold = (
            anomaly_threshold if anomaly_threshold is not None else base_settings.anomaly_threshold
        )
        self.n_estimators = (
            n_estimators if n_estimators is not None else base_settings.n_estimators
        )
        self.random_state = (
            random_state if random_state is not None else base_settings.random_state
        )
        self.min_baseline_sessions = (
            min_baseline_sessions if min_baseline_sessions is not None else base_settings.min_baseline_sessions
        )

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._fitted = False

    def fit_predict(self, sessions: List[SessionAnalysis]) -> List[SessionAnalysis]:
        """
        Fit the Isolation Forest on all session features and annotate each session:
          - anomaly_score: Liu et al. score s(x, n) ∈ (0, 1)
          - is_anomalous: boolean flag (s ≥ anomaly_threshold)
          - anomaly_status: 'CONFIRMED_ANOMALY', 'NORMAL', or 'INSUFFICIENT_BASELINE'
          - anomaly_features: Top unusual feature deviations (Z-score from population)

        Returns the same sessions list with ML fields populated.
        """
        if len(sessions) < self.min_baseline_sessions:
            # Cannot establish a statistically sound baseline on small sample sizes
            for s in sessions:
                s.is_anomalous = False
                s.anomaly_score = None
                s.anomaly_status = "INSUFFICIENT_BASELINE"
                s.anomaly_features = {}
            return sessions

        # Build raw feature matrix
        X = np.array([extract_features(s) for s in sessions], dtype=np.float64)

        # Fit Isolation Forest
        self.model.fit(X)
        self._fitted = True

        # scikit-learn returns -s(x, n) = -2^(-E(h(x))/c(n))
        raw_scores = self.model.score_samples(X)

        # Genuine Liu et al. anomaly score: negate score_samples
        liu_scores = -raw_scores
        # Bounded within [0, 1]
        liu_scores = np.clip(liu_scores, 0.0, 1.0)

        for i, session in enumerate(sessions):
            score = float(liu_scores[i])
            session.anomaly_score = round(score, 4)
            session.is_anomalous = score >= self.anomaly_threshold
            session.anomaly_status = "CONFIRMED_ANOMALY" if session.is_anomalous else "NORMAL"

            # Descriptive population deviation: which observable characteristics diverged most?
            if session.is_anomalous:
                session.anomaly_features = self._describe_unusual_characteristics(X[i], X)
            else:
                session.anomaly_features = {}

        return sessions

    def _describe_unusual_characteristics(self, x: np.ndarray, X: np.ndarray) -> dict:
        """
        Compute descriptive Z-score deviation of each feature relative to the population:
          z_j = |x_j - μ_j| / (σ_j + 1e-9)

        Returns top 5 features sorted by deviation magnitude.
        Note: This is a descriptive statistic showing feature divergence from the
        population mean, not causal model tree attribution.
        """
        mean = X.mean(axis=0)
        std = X.std(axis=0) + 1e-9
        z = np.abs((x - mean) / std)

        top = [
            (name, val)
            for name, val in sorted(
                zip(FEATURE_NAMES, z.tolist()),
                key=lambda kv: kv[1],
                reverse=True,
            )
            if val > 0.01
        ][:5]

        return {name: round(val, 3) for name, val in top}


def run_anomaly_detection(
    sessions: List[SessionAnalysis],
    settings: Optional[MLSettings] = None,
) -> List[SessionAnalysis]:
    """
    Convenience function: run full fit-predict cycle on a session list
    using the provided MLSettings.
    """
    detector = TLSAnomalyDetector(settings=settings)
    return detector.fit_predict(sessions)
