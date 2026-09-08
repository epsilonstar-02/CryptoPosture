"""
core/scorer.py
Mathematically formulated, standards-informed Cryptographic Posture Scoring Engine.
Implements the redesign specification from Docs/scorer_module_redesign.md.

Design principles:
1. Standards define security meaning (RFC 9325, RFC 8996, RFC 8446, RFC 8314, NIST SP 800-52r2, NIST SP 800-57).
2. Project calibrations map standards categories to 0–100 index values via a versioned ScoringPolicy.
3. Evidence-aware scoring: Inconclusive/missing observations yield INCONCLUSIVE status and 0 score, never misleading 50s.
4. Non-additive critical score caps replace cumulative penalties to avoid double-counting.
5. First-class structured explanations provide full forensic auditability.
6. Volume-weighted harmonic mean Enterprise Posture Index (EPI) with explicit zero-score handling and contributor breakdown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from .models import (
    AssessmentStatus,
    CertHealth,
    CertValidity,
    ChannelType,
    ComponentExplanation,
    ComponentScores,
    ConfidenceLevel,
    CriticalCapApplied,
    EnterpriseSummary,
    KeyAlgorithm,
    KeyExchange,
    RiskTier,
    ScoreExplanation,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
)


# ---------------------------------------------------------------------------
# Versioned Scoring Policy
# ---------------------------------------------------------------------------

@dataclass
class ScoringPolicy:
    """
    Versioned calibration configuration governing weights, category mappings,
    critical caps, and risk thresholds.
    """
    policy_id: str = "crypto-posture-v1"
    policy_version: str = "1.0"
    baseline: list[str] = field(default_factory=lambda: [
        "RFC 9325 (Secure Use of TLS/DTLS)",
        "RFC 8996 (Deprecating TLS 1.0/1.1)",
        "RFC 8446 (TLS 1.3 Specification)",
        "RFC 8314 (Cleartext Considered Obsolete for Email)",
        "NIST SP 800-52 Rev. 2 (Guidelines for TLS Implementations)",
        "NIST SP 800-57 Part 1 Rev. 5 (Cryptographic Key Management)",
    ])
    weights: dict[str, float] = field(default_factory=lambda: {
        "tls_version":         0.25,
        "cipher_suite":        0.20,
        "cert_health":         0.20,
        "starttls_transition": 0.15,
        "forward_secrecy":     0.10,
        "protocol_context":    0.10,
    })
    risk_thresholds: dict[str, float] = field(default_factory=lambda: {
        "low":    80.0,
        "medium": 55.0,
        "high":   30.0,
    })
    critical_caps: dict[str, float] = field(default_factory=lambda: {
        "plaintext":          0.0,
        "sslv2_sslv3":        15.0,
        "buffer_injection":   15.0,
        "starttls_stripping": 15.0,
        "broken_cipher":      20.0,
        "invalid_cert":       60.0,
    })
    weighting_method: str = "volume_weighted_harmonic_mean"

    def __post_init__(self):
        total_w = sum(self.weights.values())
        if abs(total_w - 1.0) > 1e-6:
            raise ValueError(f"ScoringPolicy weights must sum to 1.0, got {total_w}")


DEFAULT_POLICY = ScoringPolicy()


# ---------------------------------------------------------------------------
# Backward-compatible weight & penalty constants
# ---------------------------------------------------------------------------

W_TLS_VERSION   = DEFAULT_POLICY.weights["tls_version"]
W_CIPHER        = DEFAULT_POLICY.weights["cipher_suite"]
W_CERT          = DEFAULT_POLICY.weights["cert_health"]
W_STARTTLS      = DEFAULT_POLICY.weights["starttls_transition"]
W_FORWARD_SEC   = DEFAULT_POLICY.weights["forward_secrecy"]
W_PROTO_CONTEXT = DEFAULT_POLICY.weights["protocol_context"]

P_SSLV2_SSLV3      = 50.0
P_STARTTLS_INJECT  = 50.0
P_STARTTLS_STRIP   = 40.0
P_RC4_NULL_EXPORT  = 30.0
P_NO_TLS           = 60.0


# ---------------------------------------------------------------------------
# Pure Component Assessment Functions
# ---------------------------------------------------------------------------

def assess_tls_version(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess TLS protocol version modernity and compliance.
    Primary references: RFC 8446, RFC 9325 §3.1.1, RFC 8996, RFC 8314.
    """
    weight = policy.weights.get("tls_version", 0.25)
    channel = session.channel_type
    tv = session.tls_version

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="tls_version",
            observed="None (Plaintext)",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Session transmitted in cleartext without TLS encryption.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if tv == TLSVersion.TLS13:
        score = 100.0
        return ComponentExplanation(
            component="tls_version",
            observed="TLS 1.3",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="TLS 1.3 is the preferred modern cryptographic protocol version with improved handshake security.",
            references=["RFC 8446", "RFC 9325 §3.1.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    if tv == TLSVersion.TLS12:
        score = 92.0
        return ComponentExplanation(
            component="tls_version",
            observed="TLS 1.2",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="TLS 1.2 is an acceptable secure baseline when configured with modern AEAD cipher suites.",
            references=["RFC 9325 §3.1.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    if tv == TLSVersion.TLS11:
        score = 15.0
        return ComponentExplanation(
            component="tls_version",
            observed="TLS 1.1",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="TLS 1.1 is formally deprecated and prohibited due to lack of modern AEAD and weak PRF.",
            references=["RFC 8996", "RFC 9325 §3.1.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    if tv == TLSVersion.TLS10:
        score = 10.0
        return ComponentExplanation(
            component="tls_version",
            observed="TLS 1.0",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="TLS 1.0 is formally deprecated and prohibited due to CBC/BEAST vulnerabilities and lack of modern AEAD.",
            references=["RFC 8996", "RFC 9325 §3.1.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    if tv in (TLSVersion.SSLv3, TLSVersion.SSLv2):
        score = 0.0
        name = tv.value if hasattr(tv, "value") else str(tv)
        return ComponentExplanation(
            component="tls_version",
            observed=name,
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="SSLv2/SSLv3 are fundamentally broken, obsolete protocols vulnerable to known attacks (POODLE/DROWN).",
            references=["RFC 7568", "RFC 6176", "RFC 9325 §3.1.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Inconclusive / Unknown version: do not assign an arbitrary 50 score
    score = 0.0
    return ComponentExplanation(
        component="tls_version",
        observed="Unknown / Inconclusive",
        assessment=AssessmentStatus.INCONCLUSIVE,
        component_score=score,
        weight=weight,
        contribution=round(score * weight, 2),
        reason="TLS protocol version could not be determined from captured session evidence.",
        references=["RFC 9325 §3.1.1"],
        confidence=ConfidenceLevel.LOW,
    )


def assess_cipher(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess record-protection algorithm strength and modernity.
    Primary references: RFC 9325 §4.1/§4.2, RFC 7465, NIST SP 800-52r2 §3.3.1.
    """
    weight = policy.weights.get("cipher_suite", 0.20)
    channel = session.channel_type
    cipher = (session.cipher_suite or "").upper()

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="cipher_suite",
            observed="None (Plaintext)",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="No cipher suite negotiated in plaintext session.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if not cipher or cipher.startswith("0X"):
        score = 0.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or "Unknown / Unparsed",
            assessment=AssessmentStatus.INCONCLUSIVE,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Cipher suite could not be identified or recognized from session evidence.",
            references=["RFC 9325 §4.1"],
            confidence=ConfidenceLevel.LOW,
        )

    # Broken/Prohibited
    if "RC4" in cipher or "_NULL_" in cipher or "EXPORT" in cipher:
        score = 0.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or cipher,
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Prohibited/broken cipher offering no effective confidentiality (RC4, NULL, or EXPORT).",
            references=["RFC 7465", "RFC 9325 §4.2.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Weak block ciphers (SWEET32)
    if "3DES" in cipher or "TDEA" in cipher or "DES" in cipher:
        score = 15.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or cipher,
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="3DES 64-bit block cipher vulnerable to collision attacks (SWEET32); formally deprecated.",
            references=["RFC 9325 §4.2.1", "NIST SP 800-131A"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Modern AEAD (Preferred)
    if "GCM" in cipher or "CHACHA20" in cipher or "CCM" in cipher:
        score = 100.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or cipher,
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Modern Authenticated Encryption with Associated Data (AEAD) record protection.",
            references=["RFC 9325 §4.1", "RFC 8446"],
            confidence=ConfidenceLevel.HIGH,
        )

    # CBC mode with SHA-2 family
    if "CBC" in cipher and any(s in cipher for s in ("SHA256", "SHA384", "SHA512")):
        score = 75.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or cipher,
            assessment=AssessmentStatus.DEGRADED,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Legacy CBC mode cipher with SHA-2 family HMAC; acceptable legacy but AEAD is preferred.",
            references=["RFC 9325 §4.2", "NIST SP 800-52r2 §3.3.1"],
            confidence=ConfidenceLevel.MEDIUM,
        )

    # CBC mode with SHA-1
    if "CBC" in cipher:
        score = 45.0
        return ComponentExplanation(
            component="cipher_suite",
            observed=session.cipher_suite or cipher,
            assessment=AssessmentStatus.DEGRADED,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Legacy CBC mode with SHA-1 HMAC; vulnerable to padding oracles and deprecated MAC hash.",
            references=["RFC 9325 §4.2.1", "NIST SP 800-52r2 §3.3.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Generic recognized cipher
    score = 65.0
    return ComponentExplanation(
        component="cipher_suite",
        observed=session.cipher_suite or cipher,
        assessment=AssessmentStatus.DEGRADED,
        component_score=score,
        weight=weight,
        contribution=round(score * weight, 2),
        reason="Recognized cipher construction lacking confirmed AEAD authenticated encryption.",
        references=["RFC 9325 §4.1"],
        confidence=ConfidenceLevel.MEDIUM,
    )


def assess_cert_health(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess X.509 certificate validity, key strength, and signature algorithm.
    Primary references: NIST SP 800-52r2 §3.1, NIST SP 800-57, RFC 5280.
    """
    weight = policy.weights.get("cert_health", 0.20)
    channel = session.channel_type
    cert = session.cert

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="cert_health",
            observed="None (Plaintext)",
            assessment=AssessmentStatus.NOT_APPLICABLE,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="No X.509 certificate used in plaintext session.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if cert is None or (cert.validity == CertValidity.UNKNOWN and cert.key_length_bits is None and not cert.signature_algorithm):
        score = 0.0
        return ComponentExplanation(
            component="cert_health",
            observed="Missing / Incomplete",
            assessment=AssessmentStatus.INCONCLUSIVE,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Certificate was not captured in session evidence or could not be parsed.",
            references=["NIST SP 800-52r2 §3.1"],
            confidence=ConfidenceLevel.LOW,
        )

    score = 100.0
    reasons: list[str] = []
    refs: list[str] = ["NIST SP 800-52r2 §3.1"]
    status = AssessmentStatus.PASS

    # 1. Validity window
    if cert.validity == CertValidity.EXPIRED:
        score -= 60.0
        status = AssessmentStatus.VIOLATION
        reasons.append("Certificate has expired")
        refs.append("RFC 5280 §4.1.2.5")
    elif cert.validity == CertValidity.NOT_YET_VALID:
        score -= 50.0
        status = AssessmentStatus.VIOLATION
        reasons.append("Certificate is not yet valid")
        refs.append("RFC 5280 §4.1.2.5")

    if cert.validity == CertValidity.SELF_SIGNED or cert.is_self_signed:
        score -= 20.0
        if status == AssessmentStatus.PASS:
            status = AssessmentStatus.DEGRADED
        reasons.append("Self-signed certificate (trust depends on enterprise PKI store)")
        refs.append("RFC 9325 §4.3")

    # 2. Signature algorithm
    sig = (cert.signature_algorithm or "").upper()
    if "MD5" in sig:
        score -= 45.0
        status = AssessmentStatus.VIOLATION
        reasons.append("Broken MD5 signature algorithm")
        refs.append("RFC 9325 §4.3.2")
    elif "SHA1" in sig or "SHA-1" in sig:
        score -= 25.0
        if status == AssessmentStatus.PASS:
            status = AssessmentStatus.DEGRADED
        reasons.append("Deprecated SHA-1 signature algorithm")
        refs.append("RFC 9325 §4.3.2")

    # 3. Public key strength (NIST SP 800-57 Part 1 Rev. 5 Table 2)
    key_len = cert.key_length_bits
    key_type = (cert.key_type or "").upper()

    if cert.public_key and cert.public_key.effective_security_bits is not None:
        sec_bits = cert.public_key.effective_security_bits
        raw_len = cert.public_key.raw_key_length or key_len
        algo = cert.public_key.algorithm
        algo_name = algo.value if hasattr(algo, "value") else str(algo)

        if not cert.public_key.nist_compliant:
            if algo == KeyAlgorithm.ECDSA or "EC" in algo_name:
                score -= 40.0
            elif sec_bits < 80:
                score -= 60.0
            else:
                score -= 30.0
            status = AssessmentStatus.VIOLATION
            reasons.append(f"{algo_name} key ({raw_len} bits) provides {sec_bits}-bit security, below NIST minimum 112 bits")
            refs.append("NIST SP 800-57 Part 1 §5.6.1")
        elif sec_bits == 112:
            reasons.append(f"{algo_name} key ({raw_len} bits) satisfies 112-bit security baseline (NIST SP 800-57 compliant through 2030)")
            refs.append("NIST SP 800-57 Part 1 §5.6.1")
        else:
            reasons.append(f"{algo_name} key ({raw_len} bits) satisfies modern security baseline ({sec_bits}-bit security; NIST SP 800-57 compliant)")
            refs.append("NIST SP 800-57 Part 1 §5.6.1")
    elif key_len is not None:
        if "EC" in key_type or "ECDSA" in sig or "EC" in sig:
            if key_len < 224:
                score -= 40.0
                status = AssessmentStatus.VIOLATION
                reasons.append(f"EC key length ({key_len} bits) is below NIST minimum 224 bits")
                refs.append("NIST SP 800-57 Part 1 §5.6.1")
            else:
                reasons.append(f"EC key length ({key_len} bits) meets modern security standards")
        else:
            if key_len < 1024:
                score -= 60.0
                status = AssessmentStatus.VIOLATION
                reasons.append(f"RSA key length ({key_len} bits) is critically weak (<1024 bits)")
                refs.append("NIST SP 800-57 Part 1 §5.6.1")
            elif key_len < 2048:
                score -= 30.0
                status = AssessmentStatus.VIOLATION
                reasons.append(f"RSA key length ({key_len} bits) is below standard minimum 2048 bits")
                refs.append("NIST SP 800-52r2 §3.1")
            else:
                reasons.append(f"RSA key length ({key_len} bits) satisfies modern security baseline (>=2048 bits)")

    final_component_score = max(0.0, min(100.0, score))
    val_name = cert.validity.value if hasattr(cert.validity, "value") else str(cert.validity)
    if cert.public_key and cert.public_key.algorithm != KeyAlgorithm.UNKNOWN and cert.public_key.effective_security_bits:
        observed_str = f"{val_name}, {cert.public_key.algorithm.value}-{cert.key_length_bits or '?'} ({cert.public_key.effective_security_bits}b sec), {cert.signature_algorithm or '?'}"
    else:
        observed_str = f"{val_name}, {cert.key_length_bits or '?'}b, {cert.signature_algorithm or '?'}"
    reason_str = "; ".join(reasons) if reasons else "Certificate parameters satisfy modern cryptographic baseline."

    return ComponentExplanation(
        component="cert_health",
        observed=observed_str,
        assessment=status,
        component_score=final_component_score,
        weight=weight,
        contribution=round(final_component_score * weight, 2),
        reason=reason_str,
        references=list(dict.fromkeys(refs)),
        confidence=ConfidenceLevel.HIGH,
    )


def assess_starttls_transition(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess STARTTLS channel upgrade integrity and resistance to tampering.
    Primary references: RFC 8314 §3, RFC 3207, Poddebniak et al. (USENIX 2021).
    """
    weight = policy.weights.get("starttls_transition", 0.15)
    channel = session.channel_type
    status = session.starttls_status

    if channel == ChannelType.IMPLICIT_TLS:
        score = 100.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="Implicit TLS",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Direct implicit TLS connection; immune to cleartext command injection and STARTTLS stripping.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if session.buffer_injection_detected:
        score = 0.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="Buffer Injection Attack Detected",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Cleartext SMTP commands injected into STARTTLS request segment executed in TLS context.",
            references=["Poddebniak et al. (USENIX 2021)", "CVE-2021-36159"],
            confidence=ConfidenceLevel.HIGH,
        )

    if status == StarttlsStatus.STRIPPED:
        score = 0.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="STARTTLS Stripped by MITM",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Active adversary stripped STARTTLS capability advertisement, forcing cleartext fallback.",
            references=["RFC 8314 §3", "RFC 3207"],
            confidence=ConfidenceLevel.HIGH,
        )

    if status == StarttlsStatus.POSSIBLE_STRIPPING:
        score = 15.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="Possible STARTTLS Stripping",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Submission/relay session completed without STARTTLS advertisement; possible MITM suppression.",
            references=["RFC 8314 §3", "RFC 3207"],
            confidence=ConfidenceLevel.MEDIUM,
        )

    if status == StarttlsStatus.NEGOTIATED:
        score = 95.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="STARTTLS Negotiated Successfully",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="STARTTLS upgrade negotiated cleanly without tampering or cleartext command pipelining.",
            references=["RFC 3207"],
            confidence=ConfidenceLevel.HIGH,
        )

    if status == StarttlsStatus.ADVERTISED:
        score = 20.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="STARTTLS Advertised But Unused",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Server offered STARTTLS capability but client declined and continued in cleartext.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if status == StarttlsStatus.FAILED:
        score = 10.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="STARTTLS Upgrade Failed",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="STARTTLS command was rejected by server or failed during protocol upgrade.",
            references=["RFC 3207"],
            confidence=ConfidenceLevel.HIGH,
        )

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="starttls_transition",
            observed="Plaintext (No STARTTLS)",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Plaintext session without TLS negotiation or STARTTLS advertisement.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Inconclusive / Unknown
    score = 0.0
    status_str = status.value if hasattr(status, "value") else str(status)
    return ComponentExplanation(
        component="starttls_transition",
        observed=status_str or "Inconclusive",
        assessment=AssessmentStatus.INCONCLUSIVE,
        component_score=score,
        weight=weight,
        contribution=round(score * weight, 2),
        reason="STARTTLS transition evidence was inconclusive or incomplete.",
        references=["RFC 3207"],
        confidence=ConfidenceLevel.LOW,
    )


def assess_forward_secrecy(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess key exchange mechanism and Perfect Forward Secrecy (PFS).
    Primary references: RFC 9325 §4.1.1/§4.1.2, RFC 8446.
    """
    weight = policy.weights.get("forward_secrecy", 0.10)
    channel = session.channel_type
    ke = session.key_exchange

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="forward_secrecy",
            observed="None (Plaintext)",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="No key exchange mechanism in plaintext session.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if ke == KeyExchange.ECDHE:
        score = 100.0
        return ComponentExplanation(
            component="forward_secrecy",
            observed="ECDHE",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Elliptic Curve Ephemeral Diffie-Hellman provides strong Perfect Forward Secrecy (PFS).",
            references=["RFC 9325 §4.1.2", "RFC 8446"],
            confidence=ConfidenceLevel.HIGH,
        )

    if ke == KeyExchange.DHE:
        score = 85.0
        return ComponentExplanation(
            component="forward_secrecy",
            observed="DHE",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Finite Field Diffie-Hellman provides forward secrecy; ECDHE preferred for performance.",
            references=["RFC 9325 §4.1.2"],
            confidence=ConfidenceLevel.HIGH,
        )

    if ke == KeyExchange.RSA:
        score = 0.0
        return ComponentExplanation(
            component="forward_secrecy",
            observed="Static RSA",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason="Static RSA lacks forward secrecy; private key compromise allows retrospective decryption of past sessions.",
            references=["RFC 9325 §4.1.1", "RFC 8446"],
            confidence=ConfidenceLevel.HIGH,
        )

    # Unknown
    score = 0.0
    return ComponentExplanation(
        component="forward_secrecy",
        observed="Unknown / Missing",
        assessment=AssessmentStatus.INCONCLUSIVE,
        component_score=score,
        weight=weight,
        contribution=round(score * weight, 2),
        reason="Key exchange algorithm could not be determined from handshake evidence.",
        references=["RFC 9325 §4.1.2"],
        confidence=ConfidenceLevel.LOW,
    )


def assess_protocol_context(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> ComponentExplanation:
    """
    Assess appropriateness of protocol, port, and transport architecture combination.
    Primary references: RFC 8314 §3/§3.1, RFC 3207.
    """
    from .reassembly import IMPLICIT_TLS_PORTS

    weight = policy.weights.get("protocol_context", 0.10)
    port = session.dst_port
    channel = session.channel_type

    if channel == ChannelType.PLAINTEXT:
        score = 0.0
        return ComponentExplanation(
            component="protocol_context",
            observed=f"Plaintext on port {port}",
            assessment=AssessmentStatus.VIOLATION,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason=f"Cleartext transmission on email port {port}; cleartext protocols considered obsolete.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if channel == ChannelType.UNKNOWN:
        score = 0.0
        return ComponentExplanation(
            component="protocol_context",
            observed=f"Unknown/Malformed on port {port}",
            assessment=AssessmentStatus.INCONCLUSIVE,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason=f"Unrecognized or malformed protocol stream on port {port}.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.LOW,
        )

    is_implicit = getattr(session, "is_implicit_tls", False) or (port in IMPLICIT_TLS_PORTS) or (channel == ChannelType.IMPLICIT_TLS)

    if is_implicit and port in IMPLICIT_TLS_PORTS:
        score = 100.0
        return ComponentExplanation(
            component="protocol_context",
            observed=f"Implicit TLS on port {port}",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason=f"Dedicated implicit TLS on standard secure port {port} aligns with RFC 8314.",
            references=["RFC 8314 §3"],
            confidence=ConfidenceLevel.HIGH,
        )

    if channel == ChannelType.STARTTLS and port in (25, 587):
        score = 85.0
        return ComponentExplanation(
            component="protocol_context",
            observed=f"STARTTLS on relay/submission port {port}",
            assessment=AssessmentStatus.PASS,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason=f"STARTTLS on MTA relay/submission port {port} conforms to RFC 3207 standard.",
            references=["RFC 3207", "RFC 8314 §3.2"],
            confidence=ConfidenceLevel.HIGH,
        )

    if channel == ChannelType.STARTTLS and port in (143, 110):
        score = 50.0
        return ComponentExplanation(
            component="protocol_context",
            observed=f"STARTTLS on mail access port {port}",
            assessment=AssessmentStatus.DEGRADED,
            component_score=score,
            weight=weight,
            contribution=round(score * weight, 2),
            reason=f"STARTTLS used on mail retrieval port {port}; RFC 8314 strongly advises implicit TLS (ports 993/995).",
            references=["RFC 8314 §3.1"],
            confidence=ConfidenceLevel.HIGH,
        )

    score = 70.0
    channel_str = channel.value if hasattr(channel, "value") else str(channel)
    return ComponentExplanation(
        component="protocol_context",
        observed=f"{channel_str} on port {port}",
        assessment=AssessmentStatus.PASS,
        component_score=score,
        weight=weight,
        contribution=round(score * weight, 2),
        reason=f"Port {port} configuration evaluated under standard protocol security context.",
        references=["RFC 8314 §3"],
        confidence=ConfidenceLevel.MEDIUM,
    )


# Backward-compatible individual score wrappers
def _score_tls_version(session: SessionAnalysis) -> float:
    return assess_tls_version(session).component_score

def _score_cipher(session: SessionAnalysis) -> float:
    return assess_cipher(session).component_score

def _score_cert_health(session: SessionAnalysis) -> float:
    return assess_cert_health(session).component_score

def _score_starttls_transition(session: SessionAnalysis) -> float:
    return assess_starttls_transition(session).component_score

def _score_forward_secrecy(session: SessionAnalysis) -> float:
    return assess_forward_secrecy(session).component_score

def _score_protocol_context(session: SessionAnalysis) -> float:
    return assess_protocol_context(session).component_score


# ---------------------------------------------------------------------------
# Critical Findings and Caps Evaluator
# ---------------------------------------------------------------------------

def evaluate_critical_caps(
    session: SessionAnalysis,
    policy: ScoringPolicy = DEFAULT_POLICY,
) -> list[CriticalCapApplied]:
    """
    Evaluate critical security findings that impose non-additive score caps.
    Prevents catastrophic flaws from being averaged away while avoiding double-counting.
    """
    caps: list[CriticalCapApplied] = []
    tv = session.tls_version
    cipher = (session.cipher_suite or "").upper()
    caps_cfg = policy.critical_caps

    # 1. Plaintext session
    if session.channel_type == ChannelType.PLAINTEXT:
        caps.append(CriticalCapApplied(
            finding="Plaintext Transmission",
            cap_value=caps_cfg.get("plaintext", 0.0),
            reason="Cleartext communication without cryptographic protection exposes credentials and content.",
            reference="RFC 8314 §3",
            observed=f"{session.protocol.value if hasattr(session.protocol, 'value') else session.protocol} plaintext flow",
        ))

    # 2. SSLv2 / SSLv3
    if tv in (TLSVersion.SSLv2, TLSVersion.SSLv3):
        caps.append(CriticalCapApplied(
            finding="Prohibited Legacy SSL Protocol",
            cap_value=caps_cfg.get("sslv2_sslv3", 15.0),
            reason="SSLv2/SSLv3 protocols are fundamentally broken and subject to POODLE/DROWN attacks.",
            reference="RFC 7568 / RFC 9325 §3.1.1",
            observed=tv.value if hasattr(tv, "value") else str(tv),
        ))

    # 3. Buffer injection
    if session.buffer_injection_detected:
        caps.append(CriticalCapApplied(
            finding="STARTTLS Command Buffer Injection",
            cap_value=caps_cfg.get("buffer_injection", 15.0),
            reason="Unencrypted commands injected into STARTTLS handshake buffer execute in subsequent TLS context.",
            reference="Poddebniak et al. (USENIX 2021) / CVE-2021-36159",
            observed="Cleartext commands pipelined with STARTTLS request",
        ))

    # 4. STARTTLS stripping
    if session.starttls_status in (StarttlsStatus.STRIPPED, StarttlsStatus.POSSIBLE_STRIPPING):
        caps.append(CriticalCapApplied(
            finding="STARTTLS MITM Stripping",
            cap_value=caps_cfg.get("starttls_stripping", 15.0),
            reason="STARTTLS capability stripped or suppressed by active MITM, degrading channel security.",
            reference="RFC 8314 §3 / RFC 3207",
            observed=session.starttls_status.value if hasattr(session.starttls_status, "value") else str(session.starttls_status),
        ))

    # 5. Broken cipher (RC4, NULL, EXPORT)
    if any(broken in cipher for broken in ("RC4", "_NULL_", "EXPORT")):
        caps.append(CriticalCapApplied(
            finding="Prohibited Broken Cipher Suite",
            cap_value=caps_cfg.get("broken_cipher", 20.0),
            reason="Cipher suite provides null, export-grade, or broken stream encryption (RC4).",
            reference="RFC 7465 / RFC 9325 §4.2.1",
            observed=session.cipher_suite or "Broken Cipher",
        ))

    # 6. Expired / Invalid Certificate
    if session.cert and session.cert.validity in (CertValidity.EXPIRED, CertValidity.NOT_YET_VALID):
        caps.append(CriticalCapApplied(
            finding="Expired or Invalid Certificate",
            cap_value=caps_cfg.get("invalid_cert", 60.0),
            reason="Certificate validity period is invalid (expired or not yet valid); trust verification fails.",
            reference="RFC 5280 §4.1.2.5",
            observed=session.cert.validity.value if hasattr(session.cert.validity, "value") else str(session.cert.validity),
        ))

    return caps


# Backward-compatible penalty function
def _compute_penalties(session: SessionAnalysis) -> float:
    """Legacy helper for backward compatibility."""
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
# Session Posture Scorer
# ---------------------------------------------------------------------------

def score_session(
    session: SessionAnalysis,
    policy: Optional[ScoringPolicy] = None,
) -> SessionAnalysis:
    """
    Compute and populate evidence-aware posture scores, risk tier, and structured
    explanation for a single session according to the versioned ScoringPolicy.

    Mutates session in place and returns it.
    """
    if policy is None:
        policy = DEFAULT_POLICY

    # 1. Assess all six dimensions
    exp_tv    = assess_tls_version(session, policy)
    exp_ciph  = assess_cipher(session, policy)
    exp_cert  = assess_cert_health(session, policy)
    exp_stls  = assess_starttls_transition(session, policy)
    exp_fs    = assess_forward_secrecy(session, policy)
    exp_proto = assess_protocol_context(session, policy)

    components = [exp_tv, exp_ciph, exp_cert, exp_stls, exp_fs, exp_proto]

    # Populate backward-compatible ComponentScores model
    session.component_scores = ComponentScores(
        tls_version         = exp_tv.component_score,
        cipher_suite        = exp_ciph.component_score,
        cert_health         = exp_cert.component_score,
        starttls_transition = exp_stls.component_score,
        forward_secrecy     = exp_fs.component_score,
        protocol_context    = exp_proto.component_score,
    )

    # 2. 🔴 Fix 4: Evidence-aware weight renormalization
    # Split components into ASSESSED (PASS / DEGRADED / VIOLATION — actual security evidence)
    # vs INCONCLUSIVE / NOT_APPLICABLE (no security meaning observed).
    # The raw sum includes INCONCLUSIVE zeros which drag the score down as if they
    # were insecure. We renormalize over the assessed weight fraction only.
    _ASSESSED_STATUSES = {AssessmentStatus.PASS, AssessmentStatus.DEGRADED, AssessmentStatus.VIOLATION}

    assessed = [c for c in components if c.assessment in _ASSESSED_STATUSES]
    inconclusive = [c for c in components if c.assessment not in _ASSESSED_STATUSES]

    assessed_weight_sum = sum(c.weight for c in assessed)
    raw_quality_score = sum(c.contribution for c in components)
    raw_quality_score = max(0.0, min(100.0, raw_quality_score))

    if assessed_weight_sum > 1e-6:
        # Scale each assessed contribution up by 1/assessed_weight_sum so the
        # score still lives on [0, 100] even when some components are inconclusive.
        for c in components:
            if c.assessment in _ASSESSED_STATUSES:
                c.effective_weight = round(c.weight / assessed_weight_sum, 4)
                c.effective_contribution = round(c.component_score * c.effective_weight, 2)
            else:
                c.effective_weight = 0.0
                c.effective_contribution = 0.0
        renorm_quality_score = sum(c.contribution for c in assessed) / assessed_weight_sum
        renorm_quality_score = max(0.0, min(100.0, renorm_quality_score))
    else:
        # Zero assessed weight — nothing was observable; score is definitively inconclusive
        for c in components:
            c.effective_weight = 0.0
            c.effective_contribution = 0.0
        renorm_quality_score = 0.0

    evidence_completeness = assessed_weight_sum  # fraction of total weight that was assessed
    assessed_count = len(assessed)

    # Build the evidence note for the report
    if inconclusive:
        inconclusive_names = ", ".join(c.component for c in inconclusive)
        if evidence_completeness < 0.5:
            evidence_note = (
                f"LOW COMPLETENESS: Only {evidence_completeness:.0%} of scoring weight was "
                f"assessable. Components with no captured evidence "
                f"({inconclusive_names}) are excluded from the renormalized score. "
                f"Score should be treated as INDICATIVE only."
            )
        else:
            evidence_note = (
                f"{evidence_completeness:.0%} of scoring weight assessed. "
                f"Components not observed in this capture ({inconclusive_names}) "
                f"are excluded from the score; the score reflects observed evidence only."
            )
    else:
        evidence_note = "All 6 scoring dimensions were assessed from capture evidence."

    # Use the renormalized score as the quality score
    quality_score = renorm_quality_score

    # Populate backward-compatible ComponentScores model

    # 3. Evaluate critical caps
    caps_applied = evaluate_critical_caps(session, policy)
    if caps_applied:
        min_cap = min(cap.cap_value for cap in caps_applied)
        final_score = min(quality_score, min_cap)
    else:
        final_score = quality_score

    final_score = round(max(0.0, min(100.0, final_score)), 2)
    session.posture_score = final_score

    # 4. Determine risk tier
    thresholds = policy.risk_thresholds
    # Critical attack finding forces CRITICAL tier irrespective of quality score
    if caps_applied and any(cap.cap_value <= 15.0 for cap in caps_applied):
        session.risk_tier = RiskTier.CRITICAL
    elif final_score >= thresholds.get("low", 80.0):
        session.risk_tier = RiskTier.LOW
    elif final_score >= thresholds.get("medium", 55.0):
        session.risk_tier = RiskTier.MEDIUM
    elif final_score >= thresholds.get("high", 30.0):
        session.risk_tier = RiskTier.HIGH
    else:
        session.risk_tier = RiskTier.CRITICAL

    # 5. Determine overall confidence
    confidences = [c.confidence for c in components]
    if ConfidenceLevel.LOW in confidences:
        overall_conf = "LOW"
    elif ConfidenceLevel.MEDIUM in confidences:
        overall_conf = "MEDIUM"
    else:
        overall_conf = "HIGH"

    session.confidence = overall_conf
    session.scoring_policy_id = policy.policy_id
    session.scoring_policy_version = policy.policy_version

    # 6. Structured explanation model
    summary_text = (
        f"Final score capped at {min([c.cap_value for c in caps_applied]):.1f} due to critical finding: {caps_applied[0].finding}."
        if (caps_applied and final_score < quality_score)
        else f"Evidence-aware renormalized score: {quality_score:.1f}/100 over {assessed_count}/{len(components)} assessed dimensions."
    )

    explanation = ScoreExplanation(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        quality_score=round(raw_quality_score, 2),
        renormalized_quality_score=round(renorm_quality_score, 2),
        evidence_completeness_ratio=round(evidence_completeness, 4),
        assessed_component_count=assessed_count,
        evidence_note=evidence_note,
        final_score=final_score,
        risk_tier=session.risk_tier.value,
        overall_confidence=overall_conf,
        components=components,
        critical_caps_applied=caps_applied,
        summary=summary_text,
    )
    session.scoring_explanation = explanation.to_dict()

    return session


# ---------------------------------------------------------------------------
# Enterprise Posture Index
# ---------------------------------------------------------------------------

def compute_enterprise_index(
    summary: EnterpriseSummary,
    policy: Optional[ScoringPolicy] = None,
) -> EnterpriseSummary:
    """
    Compute volume-weighted harmonic mean of session posture scores with explicit
    zero-score handling and detailed exposure explanation breakdown.

    S_enterprise = Σ Vm / Σ (Vm / S_eff,m)
    Where Vm = byte_count for session m (traffic volume exposure proxy).
    """
    if policy is None:
        policy = DEFAULT_POLICY

    sessions = summary.sessions
    summary.scoring_policy_id = policy.policy_id
    summary.scoring_policy_version = policy.policy_version

    # Count risk tiers
    summary.critical_sessions = sum(1 for s in sessions if s.risk_tier == RiskTier.CRITICAL)
    summary.high_sessions     = sum(1 for s in sessions if s.risk_tier == RiskTier.HIGH)
    summary.medium_sessions   = sum(1 for s in sessions if s.risk_tier == RiskTier.MEDIUM)
    summary.low_sessions      = sum(1 for s in sessions if s.risk_tier == RiskTier.LOW)
    summary.total_violations  = sum(len(s.violations) for s in sessions)

    if not sessions:
        summary.enterprise_posture_index = 0.0
        summary.overall_risk_tier = RiskTier.CRITICAL
        summary.enterprise_explanation = {
            "weighting_method": policy.weighting_method,
            "proxy": "byte_count",
            "total_volume_bytes": 0,
            "session_count": 0,
            "session_contributions": [],
            "top_risk_contributors": [],
            "rationale": "Volume-weighted harmonic mean penalizes weakest links in enterprise traffic.",
        }
        return summary

    total_volume = sum(max(s.byte_count, 1) for s in sessions)

    # If all sessions have a posture score of 0.0, the enterprise posture is definitively 0.0
    if all(s.posture_score == 0.0 for s in sessions):
        summary.enterprise_posture_index = 0.0
        summary.overall_risk_tier = RiskTier.CRITICAL
    else:
        # Harmonic mean calculation with explicit handling of zero-score sessions:
        # A zero-score session represents severe weakest-link risk.
        # We clamp S_eff at 0.01 to compute harmonic denominator and document per-session impact.
        harmonic_denom = sum(
            max(s.byte_count, 1) / max(s.posture_score, 0.01)
            for s in sessions
        )

        epi = total_volume / harmonic_denom if harmonic_denom > 0 else 0.0
        if epi < 0.05:
            epi = 0.0
        summary.enterprise_posture_index = round(min(100.0, max(0.0, epi)), 2)

    # Risk tier from EPI
    thresholds = policy.risk_thresholds
    epi_val = summary.enterprise_posture_index
    if summary.critical_sessions > 0 and epi_val < thresholds.get("high", 30.0):
        summary.overall_risk_tier = RiskTier.CRITICAL
    elif epi_val >= thresholds.get("low", 80.0):
        summary.overall_risk_tier = RiskTier.LOW
    elif epi_val >= thresholds.get("medium", 55.0):
        summary.overall_risk_tier = RiskTier.MEDIUM
    elif epi_val >= thresholds.get("high", 30.0):
        summary.overall_risk_tier = RiskTier.HIGH
    else:
        summary.overall_risk_tier = RiskTier.CRITICAL

    # Session contributions breakdown
    session_contribs = []
    for s in sessions:
        vol = max(s.byte_count, 1)
        vol_pct = (vol / total_volume) * 100.0
        denom_part = vol / max(s.posture_score, 0.01)
        impact_pct = (denom_part / harmonic_denom) * 100.0 if harmonic_denom > 0 else 0.0
        session_contribs.append({
            "session_id": s.session_id,
            "protocol": s.protocol.value if hasattr(s.protocol, "value") else str(s.protocol),
            "flow": f"{s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}",
            "byte_count": s.byte_count,
            "volume_percent": round(vol_pct, 1),
            "posture_score": s.posture_score,
            "risk_tier": s.risk_tier.value if hasattr(s.risk_tier, "value") else str(s.risk_tier),
            "harmonic_drag_percent": round(impact_pct, 1),
        })

    # Sort risk contributors by volume among CRITICAL / HIGH sessions
    top_risk = [
        c for c in session_contribs
        if c["risk_tier"] in ("CRITICAL", "HIGH")
    ]
    top_risk.sort(key=lambda x: x["byte_count"], reverse=True)

    summary.enterprise_explanation = {
        "weighting_method": policy.weighting_method,
        "proxy": "byte_count",
        "total_volume_bytes": total_volume,
        "session_count": len(sessions),
        "critical_count": summary.critical_sessions,
        "high_count": summary.high_sessions,
        "session_contributions": session_contribs,
        "top_risk_contributors": top_risk[:5],
        "rationale": (
            "Volume-weighted harmonic mean penalizes critical security deficiencies disproportionately, "
            "reflecting weakest-link enterprise exposure where traffic volume acts as a proxy for operational importance."
        ),
    }

    return summary
