"""
core/crypto_parser.py
Deep TLS handshake and X.509 certificate parser.
Implements Pipeline Stages 4 and 5 from the project synopsis.

Extracts from raw stream bytes:
  - TLS ClientHello: version, cipher suites, extensions, SNI, supported groups
  - TLS ServerHello: selected version, selected cipher suite
  - X.509 certificate: validity, key size, signature algorithm, self-signed flag

Falls back gracefully on parse failures — no crash on partial/malformed handshakes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .models import CertHealth, CertValidity, KeyExchange, TLSVersion


# ---------------------------------------------------------------------------
# TLS Version byte-map
# ---------------------------------------------------------------------------

_TLS_VERSION_MAP: dict[int, TLSVersion] = {
    0x0002: TLSVersion.SSLv2,
    0x0300: TLSVersion.SSLv3,
    0x0301: TLSVersion.TLS10,
    0x0302: TLSVersion.TLS11,
    0x0303: TLSVersion.TLS12,
    0x0304: TLSVersion.TLS13,
}

# ---------------------------------------------------------------------------
# Cipher suite → (name, forward_secret, weak) lookup table
# Source: IANA TLS Cipher Suite Registry + NIST SP 800-52 r2 / RFC 9325
# ---------------------------------------------------------------------------

@dataclass
class CipherInfo:
    name: str
    key_exchange: KeyExchange = KeyExchange.UNKNOWN
    is_forward_secret: bool   = False
    is_weak: bool             = False


# fmt: off
_CIPHER_MAP: dict[int, CipherInfo] = {
    # ---- NULL / Export ----
    0x0000: CipherInfo("TLS_NULL_WITH_NULL_NULL",         KeyExchange.UNKNOWN, False, True),
    0x0060: CipherInfo("TLS_RSA_EXPORT_WITH_RC4_40_MD5",  KeyExchange.RSA,     False, True),
    # ---- RC4 ----
    0x0004: CipherInfo("TLS_RSA_WITH_RC4_128_MD5",        KeyExchange.RSA,     False, True),
    0x0005: CipherInfo("TLS_RSA_WITH_RC4_128_SHA",        KeyExchange.RSA,     False, True),
    # ---- 3DES ----
    0x000A: CipherInfo("TLS_RSA_WITH_3DES_EDE_CBC_SHA",   KeyExchange.RSA,     False, True),
    0x001F: CipherInfo("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",KeyExchange.DHE,    True,  True),
    # ---- Static RSA (no FS) ----
    0x002F: CipherInfo("TLS_RSA_WITH_AES_128_CBC_SHA",    KeyExchange.RSA,     False, False),
    0x0035: CipherInfo("TLS_RSA_WITH_AES_256_CBC_SHA",    KeyExchange.RSA,     False, False),
    0x003C: CipherInfo("TLS_RSA_WITH_AES_128_CBC_SHA256", KeyExchange.RSA,     False, False),
    0x003D: CipherInfo("TLS_RSA_WITH_AES_256_CBC_SHA256", KeyExchange.RSA,     False, False),
    0x009C: CipherInfo("TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExchange.RSA,     False, False),
    0x009D: CipherInfo("TLS_RSA_WITH_AES_256_GCM_SHA384", KeyExchange.RSA,     False, False),
    # ---- DHE (forward secret, but check group size) ----
    0x0033: CipherInfo("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange.DHE,    True,  False),
    0x0039: CipherInfo("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", KeyExchange.DHE,    True,  False),
    0x009E: CipherInfo("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",KeyExchange.DHE,  True,  False),
    0x009F: CipherInfo("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",KeyExchange.DHE,  True,  False),
    # ---- ECDHE (forward secret, preferred) ----
    0xC013: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",    KeyExchange.ECDHE, True,  False),
    0xC014: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",    KeyExchange.ECDHE, True,  False),
    0xC027: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", KeyExchange.ECDHE, True,  False),
    0xC028: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", KeyExchange.ECDHE, True,  False),
    0xC02B: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",KeyExchange.ECDHE,True, False),
    0xC02C: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",KeyExchange.ECDHE,True, False),
    0xC02F: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange.ECDHE, True,  False),
    0xC030: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExchange.ECDHE, True,  False),
    0xC09C: CipherInfo("TLS_RSA_WITH_AES_128_CCM",               KeyExchange.RSA,   False, False),
    # ---- TLS 1.3 AEAD (always ECDHE/implicit) ----
    0x1301: CipherInfo("TLS_AES_128_GCM_SHA256",          KeyExchange.ECDHE, True,  False),
    0x1302: CipherInfo("TLS_AES_256_GCM_SHA384",          KeyExchange.ECDHE, True,  False),
    0x1303: CipherInfo("TLS_CHACHA20_POLY1305_SHA256",    KeyExchange.ECDHE, True,  False),
}
# fmt: on

# Supported groups (IANA); 0x11ec = X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem)
_PQC_GROUP = 0x11EC
_PQC_GROUP_NAME = "X25519MLKEM768"

# ---------------------------------------------------------------------------
# Raw TLS record / handshake parser helpers
# ---------------------------------------------------------------------------

def _find_tls_records(data: bytes) -> list[tuple[int, int, bytes]]:
    """
    Scan a byte buffer and yield (content_type, tls_version_int, record_body)
    for each TLS record found.
    Content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=AppData
    """
    records = []
    i = 0
    while i + 5 <= len(data):
        ct = data[i]
        if ct not in (0x14, 0x15, 0x16, 0x17):
            i += 1
            continue
        ver  = struct.unpack(">H", data[i+1:i+3])[0]
        rlen = struct.unpack(">H", data[i+3:i+5])[0]
        if i + 5 + rlen > len(data):
            break
        body = data[i+5: i+5+rlen]
        records.append((ct, ver, body))
        i += 5 + rlen
    return records


def _parse_client_hello(body: bytes) -> Optional[dict]:
    """
    Parse a TLS ClientHello handshake message body.
    Returns dict with: version, cipher_suites, extensions, sni, supported_groups, has_pqc
    """
    try:
        if len(body) < 4:
            return None
        msg_type = body[0]
        if msg_type != 0x01:  # ClientHello = 1
            return None

        # Skip msg_type (1) + length (3)
        offset = 4
        if offset + 2 > len(body):
            return None

        client_version = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2
        # Skip 32-byte random
        offset += 32
        if offset >= len(body):
            return None

        # Session ID
        sid_len = body[offset]; offset += 1 + sid_len
        if offset + 2 > len(body):
            return None

        # Cipher suites
        cs_len = struct.unpack(">H", body[offset:offset+2])[0]; offset += 2
        cipher_suites = []
        for _ in range(cs_len // 2):
            cs = struct.unpack(">H", body[offset:offset+2])[0]
            cipher_suites.append(cs)
            offset += 2

        # Compression methods
        if offset >= len(body):
            return None
        comp_len = body[offset]; offset += 1 + comp_len

        # Extensions
        sni = None
        supported_groups = []
        has_pqc = False
        negotiated_version = client_version

        if offset + 2 <= len(body):
            ext_total = struct.unpack(">H", body[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= ext_end:
                ext_type = struct.unpack(">H", body[offset:offset+2])[0]
                ext_len  = struct.unpack(">H", body[offset+2:offset+4])[0]
                ext_data = body[offset+4: offset+4+ext_len]
                offset  += 4 + ext_len

                if ext_type == 0x0000:   # server_name
                    sni = _parse_sni(ext_data)
                elif ext_type == 0x000A: # supported_groups
                    supported_groups = _parse_supported_groups(ext_data)
                    has_pqc = _PQC_GROUP in supported_groups
                elif ext_type == 0x002B: # supported_versions (TLS 1.3)
                    negotiated_version = _parse_supported_versions(ext_data) or client_version

        return {
            "version":           negotiated_version,
            "cipher_suites":     cipher_suites,
            "sni":               sni,
            "supported_groups":  supported_groups,
            "has_pqc":           has_pqc,
        }
    except Exception:
        return None


def _parse_server_hello(body: bytes) -> Optional[dict]:
    """Parse TLS ServerHello → selected_version, selected_cipher"""
    try:
        if len(body) < 4 or body[0] != 0x02:
            return None
        offset = 4

        server_version = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2
        offset += 32  # random
        if offset >= len(body):
            return None
        sid_len = body[offset]; offset += 1 + sid_len
        if offset + 2 > len(body):
            return None
        cipher_suite = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2
        offset += 1   # compression

        # Check supported_versions extension for TLS 1.3
        selected_version = server_version
        if offset + 2 <= len(body):
            ext_total = struct.unpack(">H", body[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= ext_end:
                ext_type = struct.unpack(">H", body[offset:offset+2])[0]
                ext_len  = struct.unpack(">H", body[offset+2:offset+4])[0]
                ext_data = body[offset+4: offset+4+ext_len]
                offset  += 4 + ext_len
                if ext_type == 0x002B and len(ext_data) >= 2:
                    ver = struct.unpack(">H", ext_data[:2])[0]
                    selected_version = ver

        return {"version": selected_version, "cipher_suite": cipher_suite}
    except Exception:
        return None


def _parse_sni(ext_data: bytes) -> Optional[str]:
    try:
        if len(ext_data) < 5:
            return None
        list_len = struct.unpack(">H", ext_data[:2])[0]
        name_type = ext_data[2]
        name_len  = struct.unpack(">H", ext_data[3:5])[0]
        return ext_data[5:5+name_len].decode("ascii", errors="replace")
    except Exception:
        return None


def _parse_supported_groups(ext_data: bytes) -> list[int]:
    try:
        list_len = struct.unpack(">H", ext_data[:2])[0]
        groups = []
        for i in range(2, 2 + list_len, 2):
            groups.append(struct.unpack(">H", ext_data[i:i+2])[0])
        return groups
    except Exception:
        return []


def _parse_supported_versions(ext_data: bytes) -> Optional[int]:
    """Extract highest supported TLS version from supported_versions extension."""
    try:
        if len(ext_data) < 3:
            return None
        # Client: list_len byte, then pairs
        list_len = ext_data[0]
        best = 0
        for i in range(1, 1 + list_len, 2):
            ver = struct.unpack(">H", ext_data[i:i+2])[0]
            if ver > best:
                best = ver
        return best if best else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# X.509 certificate parser (uses `cryptography` library)
# ---------------------------------------------------------------------------

def _parse_certificate(cert_bytes: bytes) -> Optional[CertHealth]:
    """
    Parse a DER-encoded X.509 certificate using the `cryptography` library.
    Returns a CertHealth object with all relevant fields populated.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        now = datetime.now(timezone.utc)

        # Validity window
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc

        if now < not_before:
            validity = CertValidity.NOT_YET_VALID
        elif now > not_after:
            validity = CertValidity.EXPIRED
        else:
            validity = CertValidity.VALID

        # Subject / Issuer CN
        def get_cn(name):
            try:
                return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except Exception:
                return str(name)

        subject_cn = get_cn(cert.subject)
        issuer_cn  = get_cn(cert.issuer)
        is_self_signed = (subject_cn == issuer_cn)
        if is_self_signed:
            validity = CertValidity.SELF_SIGNED

        # Public key length
        pub_key = cert.public_key()
        key_length = None
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_length = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_length = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_length = pub_key.key_size

        # Signature algorithm
        try:
            sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
            sig_key = type(cert.signature_algorithm_parameters).__name__ if hasattr(cert, 'signature_algorithm_parameters') else ""
            sig_str = f"{sig_alg}with{type(pub_key).__name__}".replace("PublicKey", "")
        except Exception:
            sig_str = "UNKNOWN"

        return CertHealth(
            validity            = validity,
            key_length_bits     = key_length,
            signature_algorithm = sig_str,
            subject_cn          = subject_cn,
            issuer_cn           = issuer_cn,
            not_before          = not_before.isoformat(),
            not_after           = not_after.isoformat(),
            is_self_signed      = is_self_signed,
        )
    except Exception:
        return None


def _extract_cert_bytes(record_body: bytes) -> list[bytes]:
    """
    Extract DER certificate bytes from a TLS Certificate handshake message.
    TLS Certificate message format (TLS 1.2 style):
      msg_type=11, length(3), certs_length(3), [cert_length(3), cert_data, ...]+
    """
    certs = []
    try:
        if len(record_body) < 4 or record_body[0] != 0x0B:
            return certs
        offset = 4
        if offset + 3 > len(record_body):
            return certs
        certs_total = struct.unpack(">I", b"\x00" + record_body[offset:offset+3])[0]
        offset += 3
        end = offset + certs_total
        while offset + 3 <= end:
            cert_len = struct.unpack(">I", b"\x00" + record_body[offset:offset+3])[0]
            offset += 3
            cert_data = record_body[offset:offset+cert_len]
            certs.append(cert_data)
            offset += cert_len
    except Exception:
        pass
    return certs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class HandshakeResult:
    """Aggregated result of TLS handshake parsing from a single stream."""
    tls_version:       Optional[TLSVersion]  = None
    cipher_suite_id:   Optional[int]         = None
    cipher_suite_name: Optional[str]         = None
    key_exchange:      Optional[KeyExchange] = None
    is_forward_secret: bool                  = False
    is_weak_cipher:    bool                  = False
    sni:               Optional[str]         = None
    has_pqc:           bool                  = False
    cert:              Optional[CertHealth]  = None

    # Raw fields for JA4 fingerprinting
    client_cipher_suites:  list[int] = field(default_factory=list)
    client_supported_groups: list[int] = field(default_factory=list)


def parse_tls_handshake(stream_data: bytes) -> HandshakeResult:
    """
    Parse TLS ClientHello and ServerHello from raw stream bytes.
    Also extracts the first X.509 certificate from the Certificate message.
    """
    result = HandshakeResult()
    records = _find_tls_records(stream_data)

    client_hello_parsed = False
    server_hello_parsed = False

    for ct, ver, body in records:
        if ct != 0x16:   # Only handshake records
            continue

        # A single TLS record can contain multiple handshake messages
        offset = 0
        while offset < len(body):
            if offset + 4 > len(body):
                break
            msg_type = body[offset]
            msg_len  = struct.unpack(">I", b"\x00" + body[offset+1:offset+4])[0]
            msg_body = body[offset: offset+4+msg_len]
            offset  += 4 + msg_len

            if msg_type == 0x01 and not client_hello_parsed:  # ClientHello
                ch = _parse_client_hello(msg_body)
                if ch:
                    result.tls_version             = _TLS_VERSION_MAP.get(ch["version"], TLSVersion.UNKNOWN)
                    result.sni                     = ch.get("sni")
                    result.has_pqc                 = ch.get("has_pqc", False)
                    result.client_cipher_suites    = ch.get("cipher_suites", [])
                    result.client_supported_groups = ch.get("supported_groups", [])
                    client_hello_parsed = True

            elif msg_type == 0x02 and not server_hello_parsed:  # ServerHello
                sh = _parse_server_hello(msg_body)
                if sh:
                    ver_int = sh["version"]
                    result.tls_version = _TLS_VERSION_MAP.get(ver_int, TLSVersion.UNKNOWN)
                    cs_id = sh["cipher_suite"]
                    result.cipher_suite_id = cs_id
                    info = _CIPHER_MAP.get(cs_id)
                    if info:
                        result.cipher_suite_name  = info.name
                        result.key_exchange       = info.key_exchange
                        result.is_forward_secret  = info.is_forward_secret
                        result.is_weak_cipher     = info.is_weak
                    else:
                        result.cipher_suite_name  = f"0x{cs_id:04X}"
                    server_hello_parsed = True

            elif msg_type == 0x0B:  # Certificate
                if result.cert is None:
                    certs = _extract_cert_bytes(msg_body)
                    if certs:
                        result.cert = _parse_certificate(certs[0])

        if client_hello_parsed and server_hello_parsed and result.cert:
            break

    return result


def parse_combined(client_data: bytes, server_data: bytes) -> HandshakeResult:
    """
    Parse TLS handshake from both client and server stream data combined.
    ClientHello is in client→server; ServerHello and Certificate are in server→client.
    """
    ch_result = parse_tls_handshake(client_data)
    sv_result = parse_tls_handshake(server_data)

    # Merge: prefer server's selected version and cipher, but take client fields too
    final = HandshakeResult(
        tls_version       = sv_result.tls_version or ch_result.tls_version,
        cipher_suite_id   = sv_result.cipher_suite_id,
        cipher_suite_name = sv_result.cipher_suite_name,
        key_exchange      = sv_result.key_exchange,
        is_forward_secret = sv_result.is_forward_secret,
        is_weak_cipher    = sv_result.is_weak_cipher,
        sni               = ch_result.sni,
        has_pqc           = ch_result.has_pqc,
        cert              = sv_result.cert,
        client_cipher_suites    = ch_result.client_cipher_suites,
        client_supported_groups = ch_result.client_supported_groups,
    )
    return final
