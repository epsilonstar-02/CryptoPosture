"""
core/scorer.py
Mathematically formulated Cryptographic Posture Scoring Engine.
Implements the scoring formula from §5 of the project synopsis and §4.1 of the PRD.

S_session = max(0, Σ(wᵢ·Sᵢ) − ΣPₖ)

Sub-domain weights:
  TLS Version          (w=0.25)
  Cipher Suite         (w=0.20)
  Certificate Health   (w=0.20)
  STARTTLS Transition  (w=0.15)
  Forward Secrecy      (w=0.10)
  Protocol Context     (w=0.10)

Enterprise Posture Index = volume-weighted harmonic mean across all sessions.
"""

from __future__ import annotations

from typing import List

from .models import (
    CertValidity,
    ChannelType,
    ComponentScores,
    KeyExchange,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
    EnterpriseSummary,
)


# ---------------------------------------------------------------------------
# Weight constants (must sum to 1.0)
# ---------------------------------------------------------------------------

W_TLS_VERSION   = 0.25
W_CIPHER        = 0.20
W_CERT          = 0.20
W_STARTTLS      = 0.15
W_FORWARD_SEC   = 0.10
W_PROTO_CONTEXT = 0.10

assert abs(W_TLS_VERSION + W_CIPHER + W_CERT + W_STARTTLS + W_FORWARD_SEC + W_PROTO_CONTEXT - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Penalty constants
# ---------------------------------------------------------------------------

P_SSLV2_SSLV3      = 50.0  # Total compromise
P_STARTTLS_INJECT  = 50.0  # Poddebniak buffer injection
P_STARTTLS_STRIP   = 40.0  # Active MITM stripping
P_RC4_NULL_EXPORT  = 30.0  # Completely broken ciphers
P_NO_TLS           = 60.0  # Full plaintext session penalty


# ---------------------------------------------------------------------------
# Sub-domain scoring functions  (each returns 0–100)
# ---------------------------------------------------------------------------

def _score_tls_version(session: SessionAnalysis) -> float:
    """Score TLS version quality (0–100)."""
    tv = session.tls_version
    channel = session.channel_type

    if channel == ChannelType.PLAINTEXT:
        return 0.0

    version_scores = {
        TLSVersion.TLS13:   100.0,
        TLSVersion.TLS12:    85.0,
        TLSVersion.TLS11:    30.0,
        TLSVersion.TLS10:    20.0,
        TLSVersion.SSLv3:     5.0,
        TLSVersion.SSLv2:     0.0,
        TLSVersion.UNKNOWN:  50.0,   # Cannot assess — moderate penalty
    }
    return version_scores.get(tv, 50.0)


def _score_cipher(session: SessionAnalysis) -> float:
    """Score cipher suite quality (0–100)."""
    channel = session.channel_type
    cipher  = (session.cipher_suite or "").upper()

    if channel == ChannelType.PLAINTEXT:
        return 0.0

    if not cipher or cipher.startswith("0X"):
        return 50.0   # Unknown — moderate

    # RC4, NULL, EXPORT: completely broken
    if "RC4" in cipher or "_NULL_" in cipher or "EXPORT" in cipher:
        return 0.0
    # 3DES: weak (SWEET32)
    if "3DES" in cipher or "TDEA" in cipher:
        return 20.0
    # CBC mode without SHA2 (older but still somewhat used)
    if "CBC" in cipher and ("SHA_" in cipher or cipher.endswith("_SHA")):
        return 60.0
    # CBC with SHA256+ is reasonable
    if "CBC" in cipher and "SHA256" in cipher:
        return 75.0
    # AEAD (GCM, CHACHA20) — best
    if "GCM" in cipher or "CHACHA20" in cipher or "CCM" in cipher:
        return 100.0

    return 70.0   # Fallback for unknown-but-not-bad ciphers


def _score_cert_health(session: SessionAnalysis) -> float:
    """Score X.509 certificate health (0–100)."""
    channel = session.channel_type
    cert    = session.cert

    if channel == ChannelType.PLAINTEXT:
        return 0.0
    if cert is None:
        return 50.0   # Cannot assess

    score = 100.0

    # Validity
    if cert.validity == CertValidity.EXPIRED:
        score -= 60.0
    elif cert.validity == CertValidity.NOT_YET_VALID:
        score -= 50.0
    elif cert.validity == CertValidity.SELF_SIGNED:
        score -= 30.0

    # Signature algorithm
    sig = (cert.signature_algorithm or "").upper()
    if "MD5" in sig:
        score -= 40.0
    elif "SHA1" in sig or "SHA-1" in sig:
        score -= 25.0

    # Key size
    key_len = cert.key_length_bits
    if key_len is not None:
        if "EC" in sig and key_len < 224:
            score -= 30.0
        elif key_len < 1024:
            score -= 50.0
        elif key_len < 2048:
            score -= 25.0

    return max(0.0, score)


def _score_starttls_transition(session: SessionAnalysis) -> float:
    """Score STARTTLS channel transition quality (0–100)."""
    channel = session.channel_type
    status  = session.starttls_status

    if channel == ChannelType.IMPLICIT_TLS:
        return 100.0   # Best — RFC 8314 compliant
    if channel == ChannelType.STARTTLS:
        if status == StarttlsStatus.NEGOTIATED:
            return 80.0   # Acceptable but not ideal
        if status == StarttlsStatus.FAILED:
            return 10.0
        if status in (StarttlsStatus.STRIPPED, StarttlsStatus.POSSIBLE_STRIPPING):
            return 0.0
        if status in (StarttlsStatus.INCONCLUSIVE, StarttlsStatus.UNKNOWN):
            return 40.0
    if channel == ChannelType.PLAINTEXT:
        if status == StarttlsStatus.ADVERTISED:
            return 20.0   # Server offered but client didn't take it
        if status in (StarttlsStatus.INCONCLUSIVE, StarttlsStatus.UNKNOWN):
            return 25.0
        return 0.0

    return 50.0


def _score_forward_secrecy(session: SessionAnalysis) -> float:
    """Score forward secrecy quality (0–100)."""
    channel = session.channel_type
    ke      = session.key_exchange

    if channel == ChannelType.PLAINTEXT:
        return 0.0

    if ke == KeyExchange.ECDHE:
        return 100.0
    if ke == KeyExchange.DHE:
        return 85.0
    if ke == KeyExchange.RSA:
        return 0.0   # No forward secrecy with static RSA
    return 50.0


def _score_protocol_context(session: SessionAnalysis) -> float:
    """Score protocol configuration context compliance (0–100)."""
    from .reassembly import IMPLICIT_TLS_PORTS

    port  = session.dst_port
    proto = session.protocol
    channel = session.channel_type

    # Full marks: using implicit TLS on correct port
    if session.is_implicit_tls if hasattr(session, 'is_implicit_tls') else port in IMPLICIT_TLS_PORTS:
        return 100.0

    # STARTTLS on submission/relay port (25/587) — acceptable per RFC 3207
    if channel == ChannelType.STARTTLS and port in (25, 587):
        return 70.0

    # STARTTLS on access ports — RFC 8314 discourages this
    if channel == ChannelType.STARTTLS and port in (143, 110):
        return 50.0

    # Plaintext
    if channel == ChannelType.PLAINTEXT:
        return 0.0

    return 70.0


def _compute_penalties(session: SessionAnalysis) -> float:
    """Compute dynamic penalty deductions for critical failure modes."""
    penalties = 0.0
    tv = session.tls_version
    cipher = (session.cipher_suite or "").upper()

    if tv in (TLSVersion.SSLv2, TLSVersion.SSLv3):
        penalties += P_SSLV2_SSLV3

    if session.buffer_injection_detected:
        penalties += P_STARTTLS_INJECT

    if session.starttls_status in (StarttlsStatus.STRIPPED, StarttlsStatus.POSSIBLE_STRIPPING):
        penalties += P_STARTTLS_STRIP

    if "RC4" in cipher or "_NULL_" in cipher or "EXPORT" in cipher:
        penalties += P_RC4_NULL_EXPORT

    if session.channel_type == ChannelType.PLAINTEXT:
        penalties += P_NO_TLS

    return penalties


# ---------------------------------------------------------------------------
# Session posture scorer
# ---------------------------------------------------------------------------

def score_session(session: SessionAnalysis) -> SessionAnalysis:
    """
    Compute and populate all posture scores and risk tier for a session.
    Mutates session in place and returns it.
    """
    cs = ComponentScores(
        tls_version        = _score_tls_version(session),
        cipher_suite       = _score_cipher(session),
        cert_health        = _score_cert_health(session),
        starttls_transition = _score_starttls_transition(session),
        forward_secrecy    = _score_forward_secrecy(session),
        protocol_context   = _score_protocol_context(session),
    )
    session.component_scores = cs

    weighted_sum = (
        W_TLS_VERSION   * cs.tls_version +
        W_CIPHER        * cs.cipher_suite +
        W_CERT          * cs.cert_health +
        W_STARTTLS      * cs.starttls_transition +
        W_FORWARD_SEC   * cs.forward_secrecy +
        W_PROTO_CONTEXT * cs.protocol_context
    )

    penalties = _compute_penalties(session)
    raw_score = max(0.0, weighted_sum - penalties)
    session.posture_score = round(min(100.0, raw_score), 2)

    # Risk tier mapping
    s = session.posture_score
    if s >= 80:
        session.risk_tier = RiskTier.LOW
    elif s >= 55:
        session.risk_tier = RiskTier.MEDIUM
    elif s >= 30:
        session.risk_tier = RiskTier.HIGH
    else:
        session.risk_tier = RiskTier.CRITICAL

    return session


# ---------------------------------------------------------------------------
# Enterprise Posture Index
# ---------------------------------------------------------------------------

def compute_enterprise_index(summary: EnterpriseSummary) -> EnterpriseSummary:
    """
    Compute the volume-weighted harmonic mean of session posture scores.
    S_enterprise = Σ Vm / Σ (Vm / S_session,m)

    Where Vm = byte_count for session m (proxy for traffic volume).
    Mutates summary.enterprise_posture_index and risk breakdown fields.
    """
    sessions = summary.sessions

    # Count risk tiers
    summary.critical_sessions = sum(1 for s in sessions if s.risk_tier == RiskTier.CRITICAL)
    summary.high_sessions     = sum(1 for s in sessions if s.risk_tier == RiskTier.HIGH)
    summary.medium_sessions   = sum(1 for s in sessions if s.risk_tier == RiskTier.MEDIUM)
    summary.low_sessions      = sum(1 for s in sessions if s.risk_tier == RiskTier.LOW)
    summary.total_violations  = sum(len(s.violations) for s in sessions)

    if not sessions:
        summary.enterprise_posture_index = 0.0
        summary.overall_risk_tier = RiskTier.CRITICAL
        return summary

    # Volume-weighted harmonic mean
    # Guard against 0-score sessions (add epsilon to avoid divide-by-zero)
    total_volume = sum(max(s.byte_count, 1) for s in sessions)
    harmonic_denom = sum(
        max(s.byte_count, 1) / max(s.posture_score, 0.01)
        for s in sessions
    )

    epi = total_volume / harmonic_denom
    summary.enterprise_posture_index = round(min(100.0, max(0.0, epi)), 2)

    # Overall risk tier from EPI
    epi_val = summary.enterprise_posture_index
    if epi_val >= 80:
        summary.overall_risk_tier = RiskTier.LOW
    elif epi_val >= 55:
        summary.overall_risk_tier = RiskTier.MEDIUM
    elif epi_val >= 30:
        summary.overall_risk_tier = RiskTier.HIGH
    else:
        summary.overall_risk_tier = RiskTier.CRITICAL

    return summary
