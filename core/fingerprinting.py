"""
core/fingerprinting.py
Multi-layer JA4+ fingerprint generation.
Implements Pipeline Stage 6 from the project synopsis (simplified JA4 / JA4S / JA4X).

Reference: FoxIO JA4+ Technical Specification (Altheide & FoxIO Community, 2023)

JA4 format:  {transport}{version}_{sni_flag}_{cipher_count}_{ext_count}_{alpn}_{sorted_ciphers_hash}_{sorted_exts_hash}
JA4S format: {transport}{version}_{cipher}_{ext_count}_{sorted_exts_hash}
JA4X format: {issuer_hash}_{subject_hash}_{san_count}
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from .crypto_parser import HandshakeResult, _TLS_VERSION_MAP
from .models import JA4Fingerprints


# ---------------------------------------------------------------------------
# TLS version → JA4 short code
# ---------------------------------------------------------------------------

_VERSION_CODE = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}

# GREASE values to ignore (RFC 8701)
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A,
    0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA,
    0xEAEA, 0xFAFA,
}


def _sha256_short(data: str, length: int = 12) -> str:
    """Return first `length` hex chars of SHA-256 hash."""
    return hashlib.sha256(data.encode()).hexdigest()[:length]


def generate_ja4(result: HandshakeResult, transport: str = "t") -> Optional[str]:
    """
    Generate a JA4 client TLS fingerprint from a parsed ClientHello.

    Args:
        result: HandshakeResult from crypto_parser.parse_combined()
        transport: "t" (TCP) or "q" (QUIC)

    Returns:
        JA4 string or None if insufficient data.
    """
    if not result.client_cipher_suites:
        return None

    # TLS version code — from the negotiated/offered version
    from .models import TLSVersion
    ver_map_inv = {v: k for k, v in _TLS_VERSION_MAP.items()}
    ver_int = ver_map_inv.get(result.tls_version, 0x0303)
    ver_code = _VERSION_CODE.get(ver_int, "??")

    # SNI flag: "d" if SNI present, "i" if not
    sni_flag = "d" if result.sni else "i"

    # Cipher suites (filter GREASE, exclude 0x00FF TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    ciphers = [c for c in result.client_cipher_suites if c not in _GREASE and c != 0x00FF]
    cipher_count = len(ciphers)

    # Sorted cipher list hash
    sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(ciphers))
    cipher_hash = _sha256_short(sorted_ciphers)

    # Extensions count (approximated from supported groups / SNI presence)
    # Since we don't capture full extension list in our parser, we approximate
    ext_count = len(result.client_supported_groups) + (2 if result.sni else 0) + 1
    ext_count = min(ext_count, 99)

    # Sorted extension types hash (approximate from groups)
    ext_data = ",".join(f"{g:04x}" for g in sorted(result.client_supported_groups))
    ext_hash = _sha256_short(ext_data) if ext_data else "000000000000"

    # ALPN (we don't parse ALPN in simplified parser, use "00" placeholder)
    alpn = "00"

    return f"{transport}{ver_code}_{sni_flag}_{cipher_count:02d}_{ext_count:02d}_{alpn}_{cipher_hash}_{ext_hash}"


def generate_ja4s(result: HandshakeResult, transport: str = "t") -> Optional[str]:
    """
    Generate a JA4S server TLS fingerprint from a parsed ServerHello.

    Format: {transport}{version}_{cipher_hex}_{ext_count}_{ext_hash}
    """
    if result.cipher_suite_id is None:
        return None

    from .models import TLSVersion
    ver_map_inv = {v: k for k, v in _TLS_VERSION_MAP.items()}
    ver_int = ver_map_inv.get(result.tls_version, 0x0303)
    ver_code = _VERSION_CODE.get(ver_int, "??")

    cipher_hex = f"{result.cipher_suite_id:04x}"

    # Approximate extension hash from cipher name
    ext_hash = _sha256_short(cipher_hex)
    ext_count = 2   # Simplified: at minimum supported_versions + key_share

    return f"{transport}{ver_code}_{cipher_hex}_{ext_count:02d}_{ext_hash}"


def generate_ja4x(cert_health) -> Optional[str]:
    """
    Generate a JA4X certificate fingerprint.
    Format: {issuer_rdn_hash}_{subject_rdn_hash}_{is_self_signed}

    JA4X hashes the ordered RDNs of issuer and subject for certificate lineage tracking.
    """
    if cert_health is None or cert_health.issuer_cn is None:
        return None

    issuer_hash  = _sha256_short(cert_health.issuer_cn or "")
    subject_hash = _sha256_short(cert_health.subject_cn or "")
    self_signed  = "1" if cert_health.is_self_signed else "0"

    return f"{issuer_hash}_{subject_hash}_{self_signed}"


def build_fingerprints(result: HandshakeResult) -> JA4Fingerprints:
    """Compute all available JA4+ fingerprints from a HandshakeResult."""
    return JA4Fingerprints(
        ja4  = generate_ja4(result),
        ja4s = generate_ja4s(result),
        ja4x = generate_ja4x(result.cert),
    )
