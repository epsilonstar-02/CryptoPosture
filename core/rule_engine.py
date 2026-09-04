"""
core/rule_engine.py
Deterministic cryptographic compliance rule engine.
Implements Pipeline Stage 9 (Rule Engine portion) from the project synopsis.

Standards enforced:
  - NIST SP 800-52 Rev. 2 (TLS implementation guidelines)
  - RFC 9325 / BCP 195 (Secure TLS usage recommendations)
  - RFC 8314 (Implicit TLS mandate — cleartext obsolete)
  - RFC 8996 (TLS 1.0/1.1 deprecation)

Each rule check returns zero or more Violation objects.
"""

from __future__ import annotations

from typing import List

from .models import (
    CertValidity,
    ChannelType,
    KeyExchange,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
    Violation,
)


# ---------------------------------------------------------------------------
# Violation code registry — keeps rule definitions close to checks
# ---------------------------------------------------------------------------

class V:
    """Violation code constants with metadata."""

    # Protocol / TLS version
    SSLV2_SSLV3          = ("DEPR-TLS-001", "SSLv2/SSLv3 is completely broken and formally deprecated (RFC 8996)", "CRITICAL", "RFC 8996, RFC 9325 §3.1.1")
    TLS10_DEPRECATED      = ("DEPR-TLS-002", "TLS 1.0 is deprecated (RFC 8996) — vulnerable to POODLE, BEAST, CRIME", "HIGH",     "RFC 8996, NIST SP 800-52r2")
    TLS11_DEPRECATED      = ("DEPR-TLS-003", "TLS 1.1 is deprecated (RFC 8996)", "HIGH", "RFC 8996, NIST SP 800-52r2")
    NO_TLS                = ("DEPR-TLS-004", "No TLS detected — all email traffic is transmitted in plaintext", "CRITICAL", "RFC 8314, RFC 9325")

    # Cipher suite
    RC4_CIPHER            = ("WEAK-CIPH-001", "RC4 cipher is cryptographically broken and forbidden (RFC 7465)", "CRITICAL", "RFC 7465, NIST SP 800-52r2 §3.3")
    THREE_DES_CIPHER      = ("WEAK-CIPH-002", "3DES/TDEA cipher vulnerable to SWEET32 birthday attack (CVE-2016-2183)", "HIGH",     "NIST SP 800-131A, RFC 9325 §4.1")
    NULL_CIPHER           = ("WEAK-CIPH-003", "NULL cipher provides no encryption — plaintext on wire", "CRITICAL", "NIST SP 800-52r2")
    EXPORT_CIPHER         = ("WEAK-CIPH-004", "Export-grade cipher is intentionally weakened — vulnerable to FREAK/LOGJAM", "CRITICAL", "RFC 9325 §4.1")
    WEAK_CIPHER_GENERIC   = ("WEAK-CIPH-005", "Weak or deprecated cipher suite detected", "HIGH", "NIST SP 800-52r2 §3.3")

    # Forward secrecy
    NO_FORWARD_SECRECY    = ("FS-001", "No forward secrecy — static RSA key exchange allows decryption of past sessions", "HIGH", "NIST SP 800-52r2 §3.3.1, RFC 9325 §3")
    STATIC_RSA            = ("FS-002", "Static RSA key exchange detected — compromised server key exposes all past sessions", "HIGH", "RFC 9325 §3")

    # Certificate
    CERT_EXPIRED          = ("CERT-001", "X.509 certificate has expired — TLS chain is invalid", "CRITICAL", "RFC 5280 §4.1.2.5")
    CERT_NOT_YET_VALID    = ("CERT-002", "X.509 certificate is not yet valid (notBefore in the future)", "HIGH",     "RFC 5280")
    CERT_SELF_SIGNED      = ("CERT-003", "Certificate is self-signed — no trusted CA chain", "MEDIUM",   "RFC 5280, NIST SP 800-52r2 §3.2")
    CERT_WEAK_KEY_RSA     = ("CERT-004", "RSA/DH key size < 2048 bits — insufficient for security (NIST deprecated < 2048)", "HIGH", "NIST SP 800-131A, NIST SP 800-52r2 §3.2")
    CERT_WEAK_KEY_EC      = ("CERT-005", "EC key size < 224 bits — insufficient for security", "HIGH", "NIST SP 800-57")
    CERT_SHA1_SIG         = ("CERT-006", "SHA-1 signature algorithm is cryptographically broken (SHATTERED attack)", "HIGH", "NIST SP 800-131A, RFC 9325 §3")
    CERT_MD5_SIG          = ("CERT-007", "MD5 signature algorithm is completely broken — collision attacks demonstrated", "CRITICAL", "RFC 9325, NIST SP 800-131A")

    # STARTTLS
    STARTTLS_STRIPPED     = ("STARTTLS-001", "STARTTLS capability was stripped by on-path adversary (STRIPTLS attack)", "CRITICAL", "Durumeric et al. IMC 2015, RFC 8314")
    STARTTLS_FAILED       = ("STARTTLS-002", "STARTTLS negotiation failed — session fell back to plaintext", "CRITICAL", "RFC 3207, RFC 8314")
    STARTTLS_UNADVERTISED = ("STARTTLS-003", "Server advertised STARTTLS but client never upgraded", "MEDIUM",   "RFC 3207")
    BUFFER_INJECTION      = ("STARTTLS-004", "STARTTLS buffer injection attack detected — cleartext commands pipelined across TLS boundary (Poddebniak et al., USENIX '21)", "CRITICAL", "Poddebniak et al. USENIX Security 2021")
    STARTTLS_POSSIBLE_STRIP = ("STARTTLS-005", "Possible STARTTLS stripping detected on untrusted cleartext channel", "HIGH", "Durumeric et al. IMC 2015")

    # Protocol context
    CLEARTEXT_SUBMISSION  = ("PROTO-001", "Email submission on port 587/25 without TLS — cleartext submission (RFC 8314 §3 obsoletes this)", "CRITICAL", "RFC 8314 §3")
    CLEARTEXT_ACCESS      = ("PROTO-002", "Email access (IMAP/POP3) without TLS — RFC 8314 §3 mandates Implicit TLS", "CRITICAL", "RFC 8314 §3")
    OPPORTUNISTIC_NOT_IMPLICIT = ("PROTO-003", "Using STARTTLS instead of Implicit TLS for mail access — RFC 8314 recommends Implicit TLS on ports 993/995", "LOW", "RFC 8314 §3")


def _make(v_tuple, extra_desc: str = "") -> Violation:
    code, desc, sev, ref = v_tuple
    full_desc = f"{desc}. {extra_desc}".strip(" .") if extra_desc else desc
    return Violation(code=code, description=full_desc, severity=sev, reference=ref)


# ---------------------------------------------------------------------------
# Rule check functions
# ---------------------------------------------------------------------------

def _check_tls_version(session: SessionAnalysis) -> List[Violation]:
    violations = []
    tv = session.tls_version

    if tv is None and session.channel_type in (ChannelType.IMPLICIT_TLS, ChannelType.STARTTLS):
        # TLS expected but not detected (parse fail or incomplete capture)
        return violations   # Don't flag a missing parse as a violation

    if session.channel_type == ChannelType.PLAINTEXT:
        proto = session.protocol
        if proto in (Protocol.SMTP, Protocol.IMAP, Protocol.POP3):
            violations.append(_make(V.NO_TLS))
        return violations

    if tv in (TLSVersion.SSLv2, TLSVersion.SSLv3):
        violations.append(_make(V.SSLV2_SSLV3, f"Detected: {tv.value}"))
    elif tv == TLSVersion.TLS10:
        violations.append(_make(V.TLS10_DEPRECATED))
    elif tv == TLSVersion.TLS11:
        violations.append(_make(V.TLS11_DEPRECATED))

    return violations


def _check_cipher(session: SessionAnalysis) -> List[Violation]:
    violations = []
    cipher = (session.cipher_suite or "").upper()
    ke     = session.key_exchange

    if session.channel_type == ChannelType.PLAINTEXT:
        return violations   # Already flagged by TLS version check

    if not cipher or cipher.startswith("0X"):
        return violations   # Unknown cipher — can't evaluate

    if "RC4" in cipher:
        violations.append(_make(V.RC4_CIPHER, f"Detected: {session.cipher_suite}"))
    elif "3DES" in cipher or "TDEA" in cipher:
        violations.append(_make(V.THREE_DES_CIPHER, f"Detected: {session.cipher_suite}"))
    elif "_NULL_" in cipher or cipher.endswith("_NULL"):
        violations.append(_make(V.NULL_CIPHER, f"Detected: {session.cipher_suite}"))
    elif "EXPORT" in cipher:
        violations.append(_make(V.EXPORT_CIPHER, f"Detected: {session.cipher_suite}"))

    return violations


def _check_forward_secrecy(session: SessionAnalysis) -> List[Violation]:
    violations = []
    if session.channel_type == ChannelType.PLAINTEXT:
        return violations
    if session.key_exchange in (KeyExchange.RSA,):
        violations.append(_make(V.NO_FORWARD_SECRECY, f"Key exchange: {session.key_exchange.value if session.key_exchange else 'Unknown'}"))
    return violations


def _check_certificate(session: SessionAnalysis) -> List[Violation]:
    violations = []
    cert = session.cert

    if cert is None:
        return violations
    if session.channel_type == ChannelType.PLAINTEXT:
        return violations

    if cert.validity == CertValidity.EXPIRED:
        violations.append(_make(V.CERT_EXPIRED, f"Expired: {cert.not_after}"))
    elif cert.validity == CertValidity.NOT_YET_VALID:
        violations.append(_make(V.CERT_NOT_YET_VALID, f"NotBefore: {cert.not_before}"))
    elif cert.validity == CertValidity.SELF_SIGNED:
        violations.append(_make(V.CERT_SELF_SIGNED, f"Subject=Issuer: {cert.subject_cn}"))

    sig = (cert.signature_algorithm or "").upper()
    if "MD5" in sig:
        violations.append(_make(V.CERT_MD5_SIG, f"Algorithm: {cert.signature_algorithm}"))
    elif "SHA1" in sig or "SHA-1" in sig:
        violations.append(_make(V.CERT_SHA1_SIG, f"Algorithm: {cert.signature_algorithm}"))

    key_len = cert.key_length_bits
    if key_len is not None:
        if key_len < 224 and ("EC" in (cert.signature_algorithm or "").upper()):
            violations.append(_make(V.CERT_WEAK_KEY_EC, f"EC key size: {key_len} bits"))
        elif key_len < 2048:
            violations.append(_make(V.CERT_WEAK_KEY_RSA, f"Key size: {key_len} bits"))

    return violations


def _check_starttls(session: SessionAnalysis) -> List[Violation]:
    violations = []

    if session.starttls_status == StarttlsStatus.STRIPPED:
        violations.append(_make(V.STARTTLS_STRIPPED))
    elif session.starttls_status == StarttlsStatus.POSSIBLE_STRIPPING:
        violations.append(_make(V.STARTTLS_POSSIBLE_STRIP))
    elif session.starttls_status == StarttlsStatus.FAILED:
        violations.append(_make(V.STARTTLS_FAILED))
    elif session.starttls_status == StarttlsStatus.ADVERTISED:
        violations.append(_make(V.STARTTLS_UNADVERTISED))

    if session.buffer_injection_detected:
        violations.append(_make(V.BUFFER_INJECTION))

    return violations


def _check_protocol_context(session: SessionAnalysis) -> List[Violation]:
    violations = []
    port = session.dst_port
    proto = session.protocol

    # RFC 8314: cleartext submission (SMTP 25/587) or cleartext access (IMAP 143, POP3 110)
    if session.channel_type == ChannelType.PLAINTEXT:
        if proto == Protocol.SMTP and port in (25, 587):
            violations.append(_make(V.CLEARTEXT_SUBMISSION, f"Port: {port}"))
        elif proto in (Protocol.IMAP, Protocol.POP3) and port in (143, 110):
            violations.append(_make(V.CLEARTEXT_ACCESS, f"Port: {port}"))

    # Recommend Implicit TLS over STARTTLS for client access (RFC 8314 §3)
    if session.channel_type == ChannelType.STARTTLS:
        if proto == Protocol.IMAP and port == 143:
            violations.append(_make(V.OPPORTUNISTIC_NOT_IMPLICIT, "Use port 993 (IMAPS) instead"))
        elif proto == Protocol.POP3 and port == 110:
            violations.append(_make(V.OPPORTUNISTIC_NOT_IMPLICIT, "Use port 995 (POP3S) instead"))

    return violations


# ---------------------------------------------------------------------------
# Master rule runner
# ---------------------------------------------------------------------------

def run_rules(session: SessionAnalysis) -> List[Violation]:
    """
    Run all compliance checks on a SessionAnalysis and return a flat list of violations.
    This is the main entry point for the rule engine.
    """
    all_violations: List[Violation] = []

    all_violations.extend(_check_tls_version(session))
    all_violations.extend(_check_cipher(session))
    all_violations.extend(_check_forward_secrecy(session))
    all_violations.extend(_check_certificate(session))
    all_violations.extend(_check_starttls(session))
    all_violations.extend(_check_protocol_context(session))

    return all_violations
