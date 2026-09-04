"""
core/crypto_parser.py
Production-grade forensic TLS handshake and X.509 certificate parser.
Implements Pipeline Stages 4 and 5 from the project synopsis.

Capabilities:
  - Strict, stateful TLS record layer parsing with fragmentation & truncation handling
  - Multi-record handshake message reassembly (e.g. large X.509 Certificate chains)
  - Spec-complete TLS 1.3 & 1.2 version negotiation, GREASE filtering, and downgrade detection
  - IANA cipher suite interpretation (PFS, AEAD, export, broken/weak classification)
  - Full X.509 certificate chain extraction and link verification
  - Cryptographic self-signature and chain-link signature verification
  - Subject Alternative Name (SAN) extraction and RFC 6125 wildcard SNI matching
  - TLS Alert decoding and explicit INCONCLUSIVE/UNKNOWN state reporting
  - Detailed diagnostic reporting and auditable record provenance tracking
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from .models import CertHealth, CertValidity, KeyExchange, TLSVersion


# ---------------------------------------------------------------------------
# TLS Version byte-map (RFC 8446, RFC 5246, RFC 6101)
# ---------------------------------------------------------------------------

_TLS_VERSION_MAP: dict[int, TLSVersion] = {
    0x0002: TLSVersion.SSLv2,
    0x0300: TLSVersion.SSLv3,
    0x0301: TLSVersion.TLS10,
    0x0302: TLSVersion.TLS11,
    0x0303: TLSVersion.TLS12,
    0x0304: TLSVersion.TLS13,
}

_VERSION_TO_NAME: dict[int, str] = {
    0x0002: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# ---------------------------------------------------------------------------
# TLS Alert Description Map (RFC 8446 §B.2, RFC 5246 §7.2)
# ---------------------------------------------------------------------------

_ALERT_DESCRIPTIONS: dict[int, str] = {
    0:   "close_notify",
    10:  "unexpected_message",
    20:  "bad_record_mac",
    21:  "decryption_failed",
    22:  "record_overflow",
    30:  "decompression_failure",
    40:  "handshake_failure",
    41:  "no_certificate",
    42:  "bad_certificate",
    43:  "unsupported_certificate",
    44:  "certificate_revoked",
    45:  "certificate_expired",
    46:  "certificate_unknown",
    47:  "illegal_parameter",
    48:  "unknown_ca",
    49:  "access_denied",
    50:  "decode_error",
    51:  "decrypt_error",
    60:  "export_restriction",
    70:  "protocol_version",
    71:  "insufficient_security",
    80:  "internal_error",
    86:  "inappropriate_fallback",
    90:  "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}

# RFC 8446 §4.1.4 HelloRetryRequest random sentinel
_HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e5994dc7be7108be00df05b7715b7b52c056025282cd6fc08540d2a2"
)

# RFC 8446 §4.1.3 Downgrade protection sentinels in ServerHello.random
_DOWNGRADE_SENTINEL_TLS12 = bytes.fromhex("444f574e47524401")  # "DOWNGRD\x01"
_DOWNGRADE_SENTINEL_TLS11 = bytes.fromhex("444f574e47524400")  # "DOWNGRD\x00"

# Supported groups (IANA); PQC hybrid & ML-KEM groups
_PQC_GROUPS: set[int] = {
    0x11EC,  # X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem / IANA)
    0x6399,  # X25519Kyber768Draft00
    0x639A,  # SecP256r1Kyber768Draft00
    0x023A,  # X25519MLKEM768 (alternate)
}

_NAMED_GROUPS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x11EC: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0x023A: "X25519MLKEM768",
}


def is_grease(val: int) -> bool:
    """Check if 16-bit integer is a GREASE value (RFC 8701)."""
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF)


# ---------------------------------------------------------------------------
# Cipher suite metadata & expanded IANA lookup table
# ---------------------------------------------------------------------------

@dataclass
class CipherInfo:
    name: str
    key_exchange: KeyExchange = KeyExchange.UNKNOWN
    is_forward_secret: bool   = False
    is_weak: bool             = False
    is_aead: bool             = False
    encryption_alg: str       = ""
    hash_alg: str             = ""


# fmt: off
_CIPHER_MAP: dict[int, CipherInfo] = {
    # ---- TLS 1.3 AEAD Suites (RFC 8446) ----
    0x1301: CipherInfo("TLS_AES_128_GCM_SHA256",          KeyExchange.ECDHE, True,  False, True,  "AES_128_GCM",        "SHA256"),
    0x1302: CipherInfo("TLS_AES_256_GCM_SHA384",          KeyExchange.ECDHE, True,  False, True,  "AES_256_GCM",        "SHA384"),
    0x1303: CipherInfo("TLS_CHACHA20_POLY1305_SHA256",    KeyExchange.ECDHE, True,  False, True,  "CHACHA20_POLY1305",  "SHA256"),
    0x1304: CipherInfo("TLS_AES_128_CCM_SHA256",          KeyExchange.ECDHE, True,  False, True,  "AES_128_CCM",        "SHA256"),
    0x1305: CipherInfo("TLS_AES_128_CCM_8_SHA256",        KeyExchange.ECDHE, True,  False, True,  "AES_128_CCM_8",      "SHA256"),

    # ---- ECDHE AEAD Suites (Modern TLS 1.2, PFS) ----
    0xC02B: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExchange.ECDHE, True, False, True, "AES_128_GCM",       "SHA256"),
    0xC02C: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", KeyExchange.ECDHE, True, False, True, "AES_256_GCM",       "SHA384"),
    0xC02F: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   KeyExchange.ECDHE, True, False, True, "AES_128_GCM",       "SHA256"),
    0xC030: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   KeyExchange.ECDHE, True, False, True, "AES_256_GCM",       "SHA384"),
    0xCCA8: CipherInfo("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange.ECDHE, True, False, True, "CHACHA20_POLY1305", "SHA256"),
    0xCCA9: CipherInfo("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange.ECDHE, True, False, True, "CHACHA20_POLY1305", "SHA256"),

    # ---- ECDHE CBC Suites (TLS 1.2 PFS, Non-AEAD) ----
    0xC009: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    KeyExchange.ECDHE, True, False, False, "AES_128_CBC",      "SHA1"),
    0xC00A: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    KeyExchange.ECDHE, True, False, False, "AES_256_CBC",      "SHA1"),
    0xC013: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      KeyExchange.ECDHE, True, False, False, "AES_128_CBC",      "SHA1"),
    0xC014: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      KeyExchange.ECDHE, True, False, False, "AES_256_CBC",      "SHA1"),
    0xC023: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", KeyExchange.ECDHE, True, False, False, "AES_128_CBC",      "SHA256"),
    0xC024: CipherInfo("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", KeyExchange.ECDHE, True, False, False, "AES_256_CBC",      "SHA384"),
    0xC027: CipherInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   KeyExchange.ECDHE, True, False, False, "AES_128_CBC",      "SHA256"),
    0xC028: CipherInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   KeyExchange.ECDHE, True, False, False, "AES_256_CBC",      "SHA384"),

    # ---- DHE Suites (Forward Secret) ----
    0x009E: CipherInfo("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     KeyExchange.DHE,   True, False, True,  "AES_128_GCM",       "SHA256"),
    0x009F: CipherInfo("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     KeyExchange.DHE,   True, False, True,  "AES_256_GCM",       "SHA384"),
    0x0033: CipherInfo("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",        KeyExchange.DHE,   True, False, False, "AES_128_CBC",       "SHA1"),
    0x0039: CipherInfo("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",        KeyExchange.DHE,   True, False, False, "AES_256_CBC",       "SHA1"),
    0x0067: CipherInfo("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",     KeyExchange.DHE,   True, False, False, "AES_128_CBC",       "SHA256"),
    0x006B: CipherInfo("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",     KeyExchange.DHE,   True, False, False, "AES_256_CBC",       "SHA256"),
    0xCCAA: CipherInfo("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", KeyExchange.DHE, True, False, True, "CHACHA20_POLY1305", "SHA256"),

    # ---- Static RSA Suites (No Forward Secrecy) ----
    0x002F: CipherInfo("TLS_RSA_WITH_AES_128_CBC_SHA",            KeyExchange.RSA,   False, False, False, "AES_128_CBC",     "SHA1"),
    0x0035: CipherInfo("TLS_RSA_WITH_AES_256_CBC_SHA",            KeyExchange.RSA,   False, False, False, "AES_256_CBC",     "SHA1"),
    0x003C: CipherInfo("TLS_RSA_WITH_AES_128_CBC_SHA256",         KeyExchange.RSA,   False, False, False, "AES_128_CBC",     "SHA256"),
    0x003D: CipherInfo("TLS_RSA_WITH_AES_256_CBC_SHA256",         KeyExchange.RSA,   False, False, False, "AES_256_CBC",     "SHA256"),
    0x009C: CipherInfo("TLS_RSA_WITH_AES_128_GCM_SHA256",         KeyExchange.RSA,   False, False, True,  "AES_128_GCM",     "SHA256"),
    0x009D: CipherInfo("TLS_RSA_WITH_AES_256_GCM_SHA384",         KeyExchange.RSA,   False, False, True,  "AES_256_GCM",     "SHA384"),
    0xC09C: CipherInfo("TLS_RSA_WITH_AES_128_CCM",                KeyExchange.RSA,   False, False, True,  "AES_128_CCM",     "SHA256"),
    0xC09D: CipherInfo("TLS_RSA_WITH_AES_256_CCM",                KeyExchange.RSA,   False, False, True,  "AES_256_CCM",     "SHA256"),

    # ---- Insecure / Broken / Deprecated Suites (Weak) ----
    0x0000: CipherInfo("TLS_NULL_WITH_NULL_NULL",                 KeyExchange.UNKNOWN, False, True, False, "NULL",            "NULL"),
    0x0001: CipherInfo("TLS_RSA_WITH_NULL_MD5",                   KeyExchange.RSA,     False, True, False, "NULL",            "MD5"),
    0x0002: CipherInfo("TLS_RSA_WITH_NULL_SHA",                   KeyExchange.RSA,     False, True, False, "NULL",            "SHA1"),
    0x003B: CipherInfo("TLS_RSA_WITH_NULL_SHA256",                KeyExchange.RSA,     False, True, False, "NULL",            "SHA256"),

    # Export
    0x0003: CipherInfo("TLS_RSA_EXPORT_WITH_RC4_40_MD5",          KeyExchange.RSA,     False, True, False, "RC4_40",          "MD5"),
    0x0006: CipherInfo("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      KeyExchange.RSA,     False, True, False, "RC2_40",          "MD5"),
    0x0008: CipherInfo("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",       KeyExchange.RSA,     False, True, False, "DES40",           "SHA1"),
    0x0011: CipherInfo("TLS_DH_anon_EXPORT_WITH_EDH_40_DES_CBC_SHA", KeyExchange.UNKNOWN, False, True, False, "DES40",       "SHA1"),
    0x0060: CipherInfo("TLS_RSA_EXPORT_WITH_RC4_40_MD5",          KeyExchange.RSA,     False, True, False, "RC4_40",          "MD5"),
    0x0061: CipherInfo("TLS_RSA_EXPORT_WITH_RC2_56_CBC_MD5",      KeyExchange.RSA,     False, True, False, "RC2_56",          "MD5"),
    0x0062: CipherInfo("TLS_RSA_EXPORT_WITH_DES_CBC_56_SHA",      KeyExchange.RSA,     False, True, False, "DES56",           "SHA1"),
    0x0064: CipherInfo("TLS_RSA_EXPORT_WITH_RC4_56_SHA",          KeyExchange.RSA,     False, True, False, "RC4_56",          "SHA1"),

    # RC4
    0x0004: CipherInfo("TLS_RSA_WITH_RC4_128_MD5",                KeyExchange.RSA,     False, True, False, "RC4_128",         "MD5"),
    0x0005: CipherInfo("TLS_RSA_WITH_RC4_128_SHA",                KeyExchange.RSA,     False, True, False, "RC4_128",         "SHA1"),
    0xC007: CipherInfo("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        KeyExchange.ECDHE,   True,  True, False, "RC4_128",         "SHA1"),
    0xC011: CipherInfo("TLS_ECDHE_RSA_WITH_RC4_128_SHA",          KeyExchange.ECDHE,   True,  True, False, "RC4_128",         "SHA1"),

    # DES & 3DES (SWEET32)
    0x0009: CipherInfo("TLS_RSA_WITH_DES_CBC_SHA",                KeyExchange.RSA,     False, True, False, "DES_CBC",         "SHA1"),
    0x000A: CipherInfo("TLS_RSA_WITH_3DES_EDE_CBC_SHA",           KeyExchange.RSA,     False, True, False, "3DES_EDE_CBC",    "SHA1"),
    0x0015: CipherInfo("TLS_DHE_RSA_WITH_DES_CBC_SHA",            KeyExchange.DHE,     True,  True, False, "DES_CBC",         "SHA1"),
    0x0016: CipherInfo("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       KeyExchange.DHE,     True,  True, False, "3DES_EDE_CBC",    "SHA1"),
    0x001F: CipherInfo("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       KeyExchange.DHE,     True,  True, False, "3DES_EDE_CBC",    "SHA1"),
    0xC008: CipherInfo("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   KeyExchange.ECDHE,   True,  True, False, "3DES_EDE_CBC",    "SHA1"),
    0xC012: CipherInfo("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     KeyExchange.ECDHE,   True,  True, False, "3DES_EDE_CBC",    "SHA1"),

    # Anonymous (No Authentication - MITM vulnerable)
    0x0017: CipherInfo("TLS_DH_anon_WITH_RC4_128_MD5",            KeyExchange.UNKNOWN, False, True, False, "RC4_128",         "MD5"),
    0x0018: CipherInfo("TLS_DH_anon_WITH_DES_CBC_SHA",            KeyExchange.UNKNOWN, False, True, False, "DES_CBC",         "SHA1"),
    0x0019: CipherInfo("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",       KeyExchange.UNKNOWN, False, True, False, "3DES_EDE_CBC",    "SHA1"),
    0x001A: CipherInfo("TLS_DH_anon_WITH_AES_128_CBC_SHA",        KeyExchange.UNKNOWN, False, True, False, "AES_128_CBC",     "SHA1"),
    0x001B: CipherInfo("TLS_DH_anon_WITH_AES_256_CBC_SHA",        KeyExchange.UNKNOWN, False, True, False, "AES_256_CBC",     "SHA1"),
}
# fmt: on


def resolve_cipher_info(cipher_suite_id: int) -> CipherInfo:
    """Resolve cipher suite metadata with dynamic fallback and GREASE detection."""
    if cipher_suite_id in _CIPHER_MAP:
        return _CIPHER_MAP[cipher_suite_id]

    if is_grease(cipher_suite_id):
        return CipherInfo(
            name=f"TLS_GREASE_0x{cipher_suite_id:04X}",
            key_exchange=KeyExchange.UNKNOWN,
            is_forward_secret=False,
            is_weak=False,
            is_aead=False,
        )

    # Dynamic fallback for unlisted IANA ciphers
    return CipherInfo(
        name=f"0x{cipher_suite_id:04X}",
        key_exchange=KeyExchange.UNKNOWN,
        is_forward_secret=False,
        is_weak=False,
        is_aead=False,
    )


# ---------------------------------------------------------------------------
# Strict TLS Record Layer Parser & Provenance
# ---------------------------------------------------------------------------

@dataclass
class RecordProvenance:
    """Forensic provenance for a single TLS record on the wire."""
    offset: int
    content_type: int
    version_raw: int
    version: TLSVersion
    length: int
    payload_len: int
    is_truncated: bool = False
    handshake_types: list[int] = field(default_factory=list)
    direction: str = "unknown"


@dataclass
class TLSRecord:
    """A strictly parsed TLS record."""
    content_type: int
    version: int
    length: int
    payload: bytes
    offset: int
    is_truncated: bool = False


class TLSRecordStreamParser:
    """
    Stateful TLS Record Layer stream parser.
    Correctly handles fragmented TLS records, multi-record handshake streams,
    truncated captures, and corrupted/non-TLS desynchronization with error recovery.
    """

    def __init__(self, direction: str = "unknown"):
        self.direction = direction
        self.records: list[TLSRecord] = []
        self.provenance: list[RecordProvenance] = []
        self.diagnostics: list[str] = []
        self.handshake_stream: bytearray = bytearray()
        self.is_truncated: bool = False
        self.has_malformed_records: bool = False

    def feed(self, data: bytes) -> None:
        """Parse raw stream bytes into validated TLS records and handshake buffer."""
        buf = memoryview(data)
        offset = 0
        total_len = len(buf)

        while offset < total_len:
            # Check for truncated record header
            if total_len - offset < 5:
                self.is_truncated = True
                self.diagnostics.append(
                    f"TLS record header truncated at offset {offset}: "
                    f"only {total_len - offset} bytes available, expected 5"
                )
                break

            ct = buf[offset]
            ver = struct.unpack(">H", buf[offset+1:offset+3])[0]
            rlen = struct.unpack(">H", buf[offset+3:offset+5])[0]

            is_valid_ct = ct in (0x14, 0x15, 0x16, 0x17, 0x18)
            is_valid_ver = (0x0300 <= ver <= 0x0304) or (ver == 0x0002)
            is_valid_len = (0 <= rlen <= 18432)  # RFC 8446 2^14 + 2048 max

            if is_valid_ct and is_valid_ver and is_valid_len:
                avail = total_len - (offset + 5)
                if avail >= rlen:
                    payload = bytes(buf[offset+5: offset+5+rlen])
                    record = TLSRecord(ct, ver, rlen, payload, offset, is_truncated=False)
                    offset += 5 + rlen
                else:
                    # Record payload truncated at capture boundary
                    payload = bytes(buf[offset+5:])
                    self.is_truncated = True
                    self.diagnostics.append(
                        f"TLS record payload truncated at offset {offset}: "
                        f"declared {rlen} bytes, but only {avail} bytes available"
                    )
                    record = TLSRecord(ct, ver, rlen, payload, offset, is_truncated=True)
                    offset = total_len

                self.records.append(record)
                prov = RecordProvenance(
                    offset=record.offset,
                    content_type=ct,
                    version_raw=ver,
                    version=_TLS_VERSION_MAP.get(ver, TLSVersion.UNKNOWN),
                    length=rlen,
                    payload_len=len(payload),
                    is_truncated=record.is_truncated,
                    direction=self.direction,
                )
                self.provenance.append(prov)

                if ct == 0x16:  # Handshake record
                    self.handshake_stream.extend(payload)

            else:
                # Corrupted bytes or desynchronization
                self.has_malformed_records = True
                sync_idx = -1
                for j in range(offset + 1, total_len - 4):
                    cand_ct = buf[j]
                    cand_ver = struct.unpack(">H", buf[j+1:j+3])[0]
                    cand_len = struct.unpack(">H", buf[j+3:j+5])[0]
                    if (
                        cand_ct in (0x14, 0x15, 0x16, 0x17)
                        and 0x0300 <= cand_ver <= 0x0304
                        and cand_len <= 18432
                    ):
                        sync_idx = j
                        break

                if sync_idx != -1:
                    skipped = sync_idx - offset
                    self.diagnostics.append(
                        f"TLS desynchronization at offset {offset}: skipped {skipped} corrupt bytes, "
                        f"resynchronized at offset {sync_idx}"
                    )
                    offset = sync_idx
                else:
                    skipped = total_len - offset
                    self.diagnostics.append(
                        f"Malformed/non-TLS trailing bytes ({skipped} bytes) at offset {offset}"
                    )
                    break


def _find_tls_records(data: bytes) -> list[tuple[int, int, bytes]]:
    """
    Backwards-compatible helper returning list of (content_type, tls_version_int, record_body).
    """
    parser = TLSRecordStreamParser()
    parser.feed(data)
    return [(r.content_type, r.version, r.payload) for r in parser.records if not r.is_truncated]


# ---------------------------------------------------------------------------
# Handshake Message Stream Extractor (Multi-Record Reassembly)
# ---------------------------------------------------------------------------

@dataclass
class HandshakeMessage:
    msg_type: int
    length: int
    body: bytes
    is_truncated: bool = False


def extract_handshake_messages(stream: bytearray, diagnostics: list[str]) -> list[HandshakeMessage]:
    """
    Extract handshake messages from a reassembled handshake byte stream.
    Correctly handles messages that span across multiple TLS record boundaries.
    """
    messages = []
    offset = 0
    total = len(stream)

    while offset < total:
        if total - offset < 4:
            diagnostics.append(
                f"Handshake message header truncated at stream offset {offset}: "
                f"only {total - offset} bytes available, expected 4"
            )
            break

        msg_type = stream[offset]
        msg_len = struct.unpack(">I", b"\x00" + stream[offset+1:offset+4])[0]
        avail = total - (offset + 4)

        if avail >= msg_len:
            # Full handshake message
            body = bytes(stream[offset: offset + 4 + msg_len])
            messages.append(HandshakeMessage(msg_type, msg_len, body, is_truncated=False))
            offset += 4 + msg_len
        else:
            # Truncated handshake message
            body = bytes(stream[offset:])
            diagnostics.append(
                f"Handshake message type 0x{msg_type:02X} truncated: "
                f"declared {msg_len} bytes, but only {avail} bytes available"
            )
            messages.append(HandshakeMessage(msg_type, msg_len, body, is_truncated=True))
            break

    return messages


# ---------------------------------------------------------------------------
# ClientHello, ServerHello & Alert Parsers
# ---------------------------------------------------------------------------

def _parse_client_hello(body: bytes, diagnostics: list[str]) -> Optional[dict]:
    """
    Spec-complete ClientHello handshake parser.
    Extracts: legacy_version, offered_versions (GREASE filtered), cipher_suites,
    supported_groups, has_pqc, signature_algorithms, alpn, sni, key_share.
    """
    try:
        if len(body) < 4 or body[0] != 0x01:
            return None

        # body[0] = 0x01, body[1:4] = length
        offset = 4
        if offset + 2 > len(body):
            diagnostics.append("ClientHello truncated before client_version")
            return None

        legacy_version = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2

        # 32-byte random
        if offset + 32 > len(body):
            diagnostics.append("ClientHello truncated before random bytes")
            return None
        offset += 32

        # Session ID
        if offset >= len(body):
            diagnostics.append("ClientHello truncated before session_id length")
            return None
        sid_len = body[offset]
        offset += 1 + sid_len
        if offset + 2 > len(body):
            diagnostics.append("ClientHello truncated before cipher suites length")
            return None

        # Cipher suites
        cs_len = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2
        if offset + cs_len > len(body):
            diagnostics.append("ClientHello truncated within cipher suites list")
            return None

        cipher_suites = []
        for i in range(offset, offset + cs_len, 2):
            cs = struct.unpack(">H", body[i:i+2])[0]
            cipher_suites.append(cs)
        offset += cs_len

        # Compression methods
        if offset >= len(body):
            diagnostics.append("ClientHello truncated before compression methods")
            return None
        comp_len = body[offset]
        offset += 1 + comp_len

        # Extensions
        sni = None
        supported_groups = []
        signature_algorithms = []
        alpn_protocols = []
        offered_versions: list[int] = []
        key_share_groups: list[int] = []
        has_pqc = False

        if offset + 2 <= len(body):
            ext_total = struct.unpack(">H", body[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total, len(body))

            while offset + 4 <= ext_end:
                ext_type = struct.unpack(">H", body[offset:offset+2])[0]
                ext_len = struct.unpack(">H", body[offset+2:offset+4])[0]
                ext_data = body[offset+4: offset+4+ext_len]
                offset += 4 + ext_len

                if ext_type == 0x0000:  # server_name (SNI)
                    sni = _parse_sni(ext_data)
                elif ext_type == 0x000A:  # supported_groups
                    supported_groups = _parse_supported_groups(ext_data)
                    has_pqc = any(g in _PQC_GROUPS for g in supported_groups)
                elif ext_type == 0x000D:  # signature_algorithms
                    signature_algorithms = _parse_signature_algorithms(ext_data)
                elif ext_type == 0x0010:  # ALPN
                    alpn_protocols = _parse_alpn(ext_data)
                elif ext_type == 0x002B:  # supported_versions (TLS 1.3)
                    offered_versions = _parse_client_supported_versions(ext_data)
                elif ext_type == 0x0033:  # key_share (TLS 1.3)
                    key_share_groups = _parse_client_key_shares(ext_data)

        # Determine effective client offered version
        if offered_versions:
            # Highest real version (filter GREASE)
            real_versions = [v for v in offered_versions if not is_grease(v)]
            effective_version = max(real_versions) if real_versions else legacy_version
        else:
            effective_version = legacy_version

        return {
            "legacy_version":       legacy_version,
            "version":              effective_version,
            "offered_versions":     offered_versions,
            "cipher_suites":        cipher_suites,
            "sni":                  sni,
            "supported_groups":     supported_groups,
            "signature_algorithms": signature_algorithms,
            "alpn":                 alpn_protocols,
            "key_share_groups":     key_share_groups,
            "has_pqc":              has_pqc,
        }
    except Exception as e:
        diagnostics.append(f"ClientHello parsing error: {e}")
        return None


def _parse_server_hello(body: bytes, diagnostics: list[str]) -> Optional[dict]:
    """
    Spec-complete ServerHello handshake parser.
    Extracts: server_version, selected_cipher, selected_version (from supported_versions),
    HelloRetryRequest detection, and downgrade sentinel verification (RFC 8446).
    """
    try:
        if len(body) < 4 or body[0] != 0x02:
            return None

        offset = 4
        if offset + 2 > len(body):
            diagnostics.append("ServerHello truncated before server_version")
            return None

        server_version = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2

        # 32-byte random
        if offset + 32 > len(body):
            diagnostics.append("ServerHello truncated before random bytes")
            return None
        random_bytes = body[offset:offset+32]
        offset += 32

        # HelloRetryRequest detection (RFC 8446 §4.1.4)
        is_hello_retry_request = (random_bytes == _HELLO_RETRY_REQUEST_RANDOM)

        # Downgrade sentinel check (RFC 8446 §4.1.3)
        is_downgrade_detected = False
        downgrade_warning = None
        if len(random_bytes) >= 8:
            last8 = random_bytes[-8:]
            if last8 == _DOWNGRADE_SENTINEL_TLS12:
                is_downgrade_detected = True
                downgrade_warning = "TLS 1.2 downgrade sentinel detected in ServerHello.random (RFC 8446 §4.1.3)"
                diagnostics.append(downgrade_warning)
            elif last8 == _DOWNGRADE_SENTINEL_TLS11:
                is_downgrade_detected = True
                downgrade_warning = "TLS 1.1/1.0 downgrade sentinel detected in ServerHello.random (RFC 8446 §4.1.3)"
                diagnostics.append(downgrade_warning)

        # Session ID
        if offset >= len(body):
            diagnostics.append("ServerHello truncated before session_id")
            return None
        sid_len = body[offset]
        offset += 1 + sid_len

        # Selected cipher suite
        if offset + 2 > len(body):
            diagnostics.append("ServerHello truncated before cipher_suite")
            return None
        cipher_suite = struct.unpack(">H", body[offset:offset+2])[0]
        offset += 2

        # Compression method (1 byte)
        if offset < len(body):
            offset += 1

        # Extensions
        selected_version = None
        selected_group = None
        alpn_selected = None

        if offset + 2 <= len(body):
            ext_total = struct.unpack(">H", body[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total, len(body))

            while offset + 4 <= ext_end:
                ext_type = struct.unpack(">H", body[offset:offset+2])[0]
                ext_len = struct.unpack(">H", body[offset+2:offset+4])[0]
                ext_data = body[offset+4: offset+4+ext_len]
                offset += 4 + ext_len

                if ext_type == 0x002B and len(ext_data) >= 2:  # supported_versions
                    selected_version = struct.unpack(">H", ext_data[:2])[0]
                elif ext_type == 0x0033 and len(ext_data) >= 2:  # key_share
                    selected_group = struct.unpack(">H", ext_data[:2])[0]
                elif ext_type == 0x0010:  # ALPN
                    alpn_list = _parse_alpn(ext_data)
                    if alpn_list:
                        alpn_selected = alpn_list[0]

        # In TLS 1.3, selected version is in supported_versions extension;
        # In TLS 1.2 or earlier, selected version is in server_version header.
        negotiated_version = selected_version if selected_version is not None else server_version

        return {
            "server_version":         server_version,
            "version":                negotiated_version,
            "cipher_suite":           cipher_suite,
            "selected_group":         selected_group,
            "alpn":                   alpn_selected,
            "is_hello_retry_request": is_hello_retry_request,
            "is_downgrade_detected":  is_downgrade_detected,
            "downgrade_warning":      downgrade_warning,
        }
    except Exception as e:
        diagnostics.append(f"ServerHello parsing error: {e}")
        return None


def _parse_sni(ext_data: bytes) -> Optional[str]:
    """Parse Server Name Indication (SNI) extension."""
    try:
        if len(ext_data) < 5:
            return None
        list_len = struct.unpack(">H", ext_data[:2])[0]
        offset = 2
        end = min(2 + list_len, len(ext_data))
        while offset + 3 <= end:
            name_type = ext_data[offset]
            name_len = struct.unpack(">H", ext_data[offset+1:offset+3])[0]
            offset += 3
            if offset + name_len <= len(ext_data):
                if name_type == 0x00:  # host_name
                    return ext_data[offset:offset+name_len].decode("ascii", errors="replace")
            offset += name_len
        return None
    except Exception:
        return None


def _parse_supported_groups(ext_data: bytes) -> list[int]:
    """Parse Supported Groups / Elliptic Curves extension."""
    try:
        if len(ext_data) < 2:
            return []
        list_len = struct.unpack(">H", ext_data[:2])[0]
        groups = []
        for i in range(2, min(2 + list_len, len(ext_data)), 2):
            if i + 2 <= len(ext_data):
                g = struct.unpack(">H", ext_data[i:i+2])[0]
                if not is_grease(g):
                    groups.append(g)
        return groups
    except Exception:
        return []


def _parse_signature_algorithms(ext_data: bytes) -> list[int]:
    """Parse Signature Algorithms extension."""
    try:
        if len(ext_data) < 2:
            return []
        list_len = struct.unpack(">H", ext_data[:2])[0]
        algs = []
        for i in range(2, min(2 + list_len, len(ext_data)), 2):
            if i + 2 <= len(ext_data):
                algs.append(struct.unpack(">H", ext_data[i:i+2])[0])
        return algs
    except Exception:
        return []


def _parse_alpn(ext_data: bytes) -> list[str]:
    """Parse Application Layer Protocol Negotiation (ALPN) extension."""
    protocols = []
    try:
        if len(ext_data) < 2:
            return protocols
        list_len = struct.unpack(">H", ext_data[:2])[0]
        offset = 2
        end = min(2 + list_len, len(ext_data))
        while offset < end:
            proto_len = ext_data[offset]
            offset += 1
            if offset + proto_len <= len(ext_data):
                proto = ext_data[offset:offset+proto_len].decode("ascii", errors="replace")
                protocols.append(proto)
            offset += proto_len
    except Exception:
        pass
    return protocols


def _parse_client_supported_versions(ext_data: bytes) -> list[int]:
    """Parse Client supported_versions extension (list of 16-bit version numbers)."""
    try:
        if len(ext_data) < 1:
            return []
        list_len = ext_data[0]
        versions = []
        for i in range(1, min(1 + list_len, len(ext_data)), 2):
            if i + 2 <= len(ext_data):
                ver = struct.unpack(">H", ext_data[i:i+2])[0]
                versions.append(ver)
        return versions
    except Exception:
        return []


def _parse_client_key_shares(ext_data: bytes) -> list[int]:
    """Parse Client key_share extension offered groups."""
    groups = []
    try:
        if len(ext_data) < 2:
            return groups
        list_len = struct.unpack(">H", ext_data[:2])[0]
        offset = 2
        end = min(2 + list_len, len(ext_data))
        while offset + 4 <= end:
            grp = struct.unpack(">H", ext_data[offset:offset+2])[0]
            klen = struct.unpack(">H", ext_data[offset+2:offset+4])[0]
            if not is_grease(grp):
                groups.append(grp)
            offset += 4 + klen
    except Exception:
        pass
    return groups


# ---------------------------------------------------------------------------
# X.509 Certificate Chain Parser & Cryptographic Verification
# ---------------------------------------------------------------------------

def _extract_cert_bytes(msg_body: bytes) -> list[bytes]:
    """
    Extract DER-encoded certificate byte blobs from a Certificate handshake message.
    Supports both TLS 1.2 and TLS 1.3 Certificate message formats.
    """
    certs = []
    if len(msg_body) < 4 or msg_body[0] != 0x0B:
        return certs

    # Attempt TLS 1.3 format first:
    # msg_body[4] = request_context_len
    # followed by request_context, then 3-byte cert_list_len
    try:
        if len(msg_body) >= 8:
            ctx_len = msg_body[4]
            offset = 5 + ctx_len
            if offset + 3 <= len(msg_body):
                cert_list_len = struct.unpack(">I", b"\x00" + msg_body[offset:offset+3])[0]
                offset += 3
                end = offset + cert_list_len
                candidate_certs = []
                curr = offset
                valid_tls13 = True

                while curr + 3 <= end and curr + 3 <= len(msg_body):
                    clen = struct.unpack(">I", b"\x00" + msg_body[curr:curr+3])[0]
                    curr += 3
                    if curr + clen > len(msg_body):
                        valid_tls13 = False
                        break
                    cdata = msg_body[curr:curr+clen]
                    curr += clen
                    if curr + 2 > len(msg_body):
                        valid_tls13 = False
                        break
                    ext_len = struct.unpack(">H", msg_body[curr:curr+2])[0]
                    curr += 2 + ext_len
                    candidate_certs.append(cdata)

                if valid_tls13 and candidate_certs and curr == end:
                    return candidate_certs
    except Exception:
        pass

    # Fall back to TLS 1.2 format:
    # msg_body[4:7] = certificates_total_len
    # [cert_len(3), cert_data]+
    try:
        offset = 4
        if offset + 3 > len(msg_body):
            return certs
        certs_total = struct.unpack(">I", b"\x00" + msg_body[offset:offset+3])[0]
        offset += 3
        end = min(offset + certs_total, len(msg_body))
        while offset + 3 <= end:
            cert_len = struct.unpack(">I", b"\x00" + msg_body[offset:offset+3])[0]
            offset += 3
            if offset + cert_len > len(msg_body):
                break
            cert_data = msg_body[offset:offset+cert_len]
            certs.append(cert_data)
            offset += cert_len
    except Exception:
        pass

    return certs


def _verify_signature(cert, issuer_pub_key) -> bool:
    """
    Perform true cryptographic signature verification of an X.509 certificate
    against an issuer's public key (RSA, EC, Ed25519, Ed448, DSA).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, padding

        if isinstance(issuer_pub_key, rsa.RSAPublicKey):
            # Check for standard PKCS#1 v1.5 or PSS
            try:
                issuer_pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                return True
            except Exception:
                if hasattr(padding, "PSS") and hasattr(padding, "MGF1"):
                    issuer_pub_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(cert.signature_hash_algorithm),
                            salt_length=padding.PSS.AUTO,
                        ),
                        cert.signature_hash_algorithm,
                    )
                    return True
                return False

        elif isinstance(issuer_pub_key, ec.EllipticCurvePublicKey):
            issuer_pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return True

        elif isinstance(issuer_pub_key, ed25519.Ed25519PublicKey):
            issuer_pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return True

        elif isinstance(issuer_pub_key, ed448.Ed448PublicKey):
            issuer_pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return True

        elif isinstance(issuer_pub_key, dsa.DSAPublicKey):
            issuer_pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm,
            )
            return True

    except Exception:
        return False
    return False


def _matches_hostname(pattern: str, hostname: str) -> bool:
    """
    Check if hostname matches certificate SAN or CN pattern,
    including RFC 6125 wildcard matching.
    """
    p = pattern.lower().strip()
    h = hostname.lower().strip()
    if p == h:
        return True
    if p.startswith("*."):
        # Wildcard matches a single DNS label
        suffix = p[1:]  # e.g. .example.com
        if h.endswith(suffix):
            prefix = h[:-len(suffix)]
            if "." not in prefix and len(prefix) > 0:
                return True
    return False


def _parse_certificate_object(cert_bytes: bytes, sni: Optional[str] = None) -> Optional[Tuple[CertHealth, object]]:
    """
    Parse a DER X.509 certificate using `cryptography` and perform forensic analysis.
    Returns (CertHealth, cryptography_cert_object) tuple.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        now = datetime.now(timezone.utc)

        # Validity window
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        if now < not_before:
            validity = CertValidity.NOT_YET_VALID
        elif now > not_after:
            validity = CertValidity.EXPIRED
        else:
            validity = CertValidity.VALID

        # Subject & Issuer Common Name and RFC 4514 DN
        def get_cn(name):
            try:
                return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except Exception:
                return str(name)

        subject_cn = get_cn(cert.subject)
        issuer_cn = get_cn(cert.issuer)
        try:
            subject_dn = cert.subject.rfc4514_string()
            issuer_dn = cert.issuer.rfc4514_string()
        except Exception:
            subject_dn = str(cert.subject)
            issuer_dn = str(cert.issuer)

        # Serial number and SHA-256 fingerprint
        serial_number = f"{cert.serial_number:X}"
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()

        # Subject Alternative Names (SAN)
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for item in san_ext.value:
                if isinstance(item, x509.DNSName):
                    san_list.append(item.value)
                elif isinstance(item, x509.IPAddress):
                    san_list.append(str(item.value))
                elif isinstance(item, x509.RFC822Name):
                    san_list.append(item.value)
        except Exception:
            pass

        # Basic Constraints (CA flag)
        is_ca = False
        try:
            bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc_ext.value.ca
        except Exception:
            pass

        # Public key type, key size, and curve
        pub_key = cert.public_key()
        key_type = "UNKNOWN"
        key_length = None
        curve_name = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_length = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_length = pub_key.key_size
            curve_name = pub_key.curve.name
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_type = "Ed25519"
            key_length = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            key_type = "Ed448"
            key_length = 448
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_length = pub_key.key_size

        # Signature algorithm name
        try:
            if hasattr(cert, "signature_algorithm_oid") and cert.signature_algorithm_oid:
                sig_str = cert.signature_algorithm_oid._name
            elif cert.signature_hash_algorithm:
                sig_hash = cert.signature_hash_algorithm.name.upper()
                sig_str = f"{sig_hash}with{key_type}"
            else:
                sig_str = key_type
        except Exception:
            sig_str = "UNKNOWN"

        # Cryptographic self-signature check
        is_self_signed = False
        signature_valid = None
        cert_diagnostics = []

        is_dn_match = (cert.subject == cert.issuer)
        if is_dn_match:
            # Check cryptographic self-signature using own public key
            if _verify_signature(cert, pub_key):
                is_self_signed = True
                signature_valid = True
                if validity == CertValidity.VALID:
                    validity = CertValidity.SELF_SIGNED
            else:
                is_self_signed = False
                signature_valid = False
                cert_diagnostics.append(
                    f"Certificate '{subject_cn}' has matching Subject and Issuer DN, "
                    f"but cryptographic self-signature verification failed (forged or corrupted)"
                )

        # SNI consistency check
        san_matches_sni = None
        if sni:
            candidate_names = san_list + ([subject_cn] if subject_cn else [])
            san_matches_sni = any(_matches_hostname(name, sni) for name in candidate_names)
            if not san_matches_sni:
                cert_diagnostics.append(
                    f"SNI mismatch: client SNI '{sni}' does not match certificate SANs {san_list} or CN '{subject_cn}'"
                )

        cert_health = CertHealth(
            validity=validity,
            key_length_bits=key_length,
            signature_algorithm=sig_str,
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            is_self_signed=is_self_signed,
            san_list=san_list,
            key_type=key_type,
            curve_name=curve_name,
            serial_number=serial_number,
            fingerprint_sha256=fingerprint_sha256,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            is_ca=is_ca,
            signature_valid=signature_valid,
            san_matches_sni=san_matches_sni,
            diagnostics=cert_diagnostics,
        )
        return cert_health, cert

    except Exception:
        return None


def _parse_certificate(cert_bytes: bytes) -> Optional[CertHealth]:
    """Backwards-compatible certificate parser returning a single CertHealth object."""
    res = _parse_certificate_object(cert_bytes)
    return res[0] if res else None


def parse_certificate_chain(
    cert_bytes_list: list[bytes],
    sni: Optional[str] = None,
    diagnostics: Optional[list[str]] = None,
) -> list[CertHealth]:
    """
    Forensically parse and validate the full X.509 certificate chain.
    Validates each chain link (child signed by parent) and checks self-signature of root.
    """
    if diagnostics is None:
        diagnostics = []

    parsed_chain: list[CertHealth] = []
    crypto_objects = []

    for i, b in enumerate(cert_bytes_list):
        res = _parse_certificate_object(b, sni=sni if i == 0 else None)
        if res:
            ch, cobj = res
            parsed_chain.append(ch)
            crypto_objects.append(cobj)
        else:
            diagnostics.append(f"Failed to parse DER certificate at chain index {i}")

    # Validate chain links: child signed by parent
    if len(crypto_objects) > 1:
        for i in range(len(crypto_objects) - 1):
            child_cert = crypto_objects[i]
            parent_cert = crypto_objects[i+1]
            parent_pub_key = parent_cert.public_key()

            is_valid_link = _verify_signature(child_cert, parent_pub_key)
            if parsed_chain[i].signature_valid is None:
                parsed_chain[i].signature_valid = is_valid_link

            if not is_valid_link:
                diagnostics.append(
                    f"Broken certificate chain link: cert index {i} ('{parsed_chain[i].subject_cn}') "
                    f"failed cryptographic signature verification against issuer at index {i+1} "
                    f"('{parsed_chain[i+1].subject_cn}')"
                )

    return parsed_chain


# ---------------------------------------------------------------------------
# Public API & Handshake Aggregation
# ---------------------------------------------------------------------------

@dataclass
class HandshakeResult:
    """Aggregated result of TLS handshake parsing from single or combined streams."""
    tls_version:       Optional[TLSVersion]  = None
    cipher_suite_id:   Optional[int]         = None
    cipher_suite_name: Optional[str]         = None
    key_exchange:      Optional[KeyExchange] = None
    is_forward_secret: bool                  = False
    is_weak_cipher:    bool                  = False
    sni:               Optional[str]         = None
    has_pqc:           bool                  = False
    cert:              Optional[CertHealth]  = None

    # Full certificate chain & diagnostics
    cert_chain:        list[CertHealth]      = field(default_factory=list)
    diagnostics:       list[str]             = field(default_factory=list)
    record_provenance: list[RecordProvenance] = field(default_factory=list)
    handshake_status:  str                   = "UNKNOWN"

    # Negotiation & Extension metadata
    client_offered_versions: list[TLSVersion] = field(default_factory=list)
    client_alpn:             list[str]        = field(default_factory=list)
    client_signature_algorithms: list[int]    = field(default_factory=list)
    selected_group:          Optional[int]    = None
    selected_group_name:     Optional[str]    = None
    san_matches_sni:         Optional[bool]   = None
    is_downgrade_detected:   bool             = False
    downgrade_warning:       Optional[str]    = None

    # Alert metadata
    alert_level:             Optional[int]    = None
    alert_description:       Optional[int]    = None
    alert_description_name:  Optional[str]    = None

    # Raw fields for JA4 fingerprinting
    client_cipher_suites:    list[int] = field(default_factory=list)
    client_supported_groups: list[int] = field(default_factory=list)


def parse_tls_handshake(stream_data: bytes, direction: str = "unknown") -> HandshakeResult:
    """
    Parse TLS records and handshake messages from a single directional byte stream.
    Handles fragmentation, multi-record handshakes, and alerts.
    """
    result = HandshakeResult()
    parser = TLSRecordStreamParser(direction=direction)
    parser.feed(stream_data)

    result.diagnostics.extend(parser.diagnostics)
    result.record_provenance.extend(parser.provenance)

    # Check for TLS Alerts in records
    for r in parser.records:
        if r.content_type == 0x15 and len(r.payload) >= 2:
            lvl = r.payload[0]
            desc = r.payload[1]
            desc_name = _ALERT_DESCRIPTIONS.get(desc, f"alert_{desc}")
            result.alert_level = lvl
            result.alert_description = desc
            result.alert_description_name = desc_name
            result.diagnostics.append(
                f"TLS Alert (level={lvl}, desc={desc}:{desc_name}) at offset {r.offset}"
            )

    # Extract handshake messages from accumulated handshake record stream
    hs_messages = extract_handshake_messages(parser.handshake_stream, result.diagnostics)

    client_hello_parsed = False
    server_hello_parsed = False

    for msg in hs_messages:
        # Update provenance handshake_types
        for prov in result.record_provenance:
            if prov.content_type == 0x16 and msg.msg_type not in prov.handshake_types:
                prov.handshake_types.append(msg.msg_type)

        if msg.msg_type == 0x01 and not client_hello_parsed:  # ClientHello
            ch = _parse_client_hello(msg.body, result.diagnostics)
            if ch:
                result.tls_version = _TLS_VERSION_MAP.get(ch["version"], TLSVersion.UNKNOWN)
                result.sni = ch.get("sni")
                result.has_pqc = ch.get("has_pqc", False)
                result.client_cipher_suites = ch.get("cipher_suites", [])
                result.client_supported_groups = ch.get("supported_groups", [])
                result.client_alpn = ch.get("alpn", [])
                result.client_signature_algorithms = ch.get("signature_algorithms", [])
                result.client_offered_versions = [
                    _TLS_VERSION_MAP.get(v, TLSVersion.UNKNOWN)
                    for v in ch.get("offered_versions", [])
                    if not is_grease(v)
                ]
                client_hello_parsed = True

        elif msg.msg_type == 0x02 and not server_hello_parsed:  # ServerHello
            sh = _parse_server_hello(msg.body, result.diagnostics)
            if sh:
                result.tls_version = _TLS_VERSION_MAP.get(sh["version"], TLSVersion.UNKNOWN)
                cs_id = sh["cipher_suite"]
                result.cipher_suite_id = cs_id
                info = resolve_cipher_info(cs_id)
                result.cipher_suite_name = info.name
                result.key_exchange = info.key_exchange
                result.is_forward_secret = info.is_forward_secret
                result.is_weak_cipher = info.is_weak

                result.selected_group = sh.get("selected_group")
                if result.selected_group:
                    result.selected_group_name = _NAMED_GROUPS.get(
                        result.selected_group, f"group_0x{result.selected_group:04X}"
                    )
                    if result.selected_group in _PQC_GROUPS:
                        result.has_pqc = True

                result.is_downgrade_detected = sh.get("is_downgrade_detected", False)
                result.downgrade_warning = sh.get("downgrade_warning")
                server_hello_parsed = True

        elif msg.msg_type == 0x0B:  # Certificate
            if not result.cert_chain:
                raw_certs = _extract_cert_bytes(msg.body)
                if raw_certs:
                    chain = parse_certificate_chain(
                        raw_certs,
                        sni=result.sni,
                        diagnostics=result.diagnostics,
                    )
                    result.cert_chain = chain
                    if chain:
                        result.cert = chain[0]
                        result.san_matches_sni = chain[0].san_matches_sni

    # Set directional handshake status
    if client_hello_parsed and server_hello_parsed:
        result.handshake_status = "COMPLETED"
    elif client_hello_parsed:
        result.handshake_status = "INCONCLUSIVE_CLIENT_HELLO_ONLY"
    elif server_hello_parsed:
        result.handshake_status = "INCONCLUSIVE_SERVER_HELLO_ONLY"
    elif result.alert_level is not None:
        result.handshake_status = "ALERT_TERMINATED"
    elif parser.records:
        result.handshake_status = "INCONCLUSIVE_NO_HANDSHAKE"
    else:
        result.handshake_status = "UNKNOWN"

    return result


def parse_combined(client_data: bytes, server_data: bytes) -> HandshakeResult:
    """
    Parse TLS handshake from both client and server stream data combined.
    Merges ClientHello parameters (SNI, offered ciphers/groups, ALPN) with
    ServerHello parameters (negotiated version, selected cipher, certificate chain).
    """
    ch_result = parse_tls_handshake(client_data, direction="client")
    sv_result = parse_tls_handshake(server_data, direction="server")

    # If certificates exist on server side, check SNI from client side against them
    leaf_cert = sv_result.cert
    san_matches_sni = None
    if leaf_cert and ch_result.sni:
        candidate_names = leaf_cert.san_list + ([leaf_cert.subject_cn] if leaf_cert.subject_cn else [])
        san_matches_sni = any(_matches_hostname(n, ch_result.sni) for n in candidate_names)
        leaf_cert.san_matches_sni = san_matches_sni
        if not san_matches_sni:
            sv_result.diagnostics.append(
                f"SNI mismatch: client SNI '{ch_result.sni}' does not match leaf certificate SANs "
                f"{leaf_cert.san_list} or CN '{leaf_cert.subject_cn}'"
            )

    # Determine aggregated handshake status
    if sv_result.alert_level is not None or ch_result.alert_level is not None:
        status = "ALERT_TERMINATED"
    elif sv_result.cipher_suite_id is not None and sv_result.tls_version is not None:
        status = "COMPLETED"
    elif ch_result.client_cipher_suites and not sv_result.cipher_suite_id:
        if not server_data:
            status = "INCONCLUSIVE_CLIENT_HELLO_ONLY"
        else:
            status = "INCONCLUSIVE_TRUNCATED"
    elif not client_data and not server_data:
        status = "UNKNOWN"
    elif not ch_result.client_cipher_suites and not sv_result.cipher_suite_id:
        status = "INCONCLUSIVE_NO_HANDSHAKE"
    else:
        status = sv_result.handshake_status or ch_result.handshake_status

    final = HandshakeResult(
        tls_version                 = sv_result.tls_version or ch_result.tls_version,
        cipher_suite_id             = sv_result.cipher_suite_id,
        cipher_suite_name           = sv_result.cipher_suite_name,
        key_exchange                = sv_result.key_exchange,
        is_forward_secret           = sv_result.is_forward_secret,
        is_weak_cipher              = sv_result.is_weak_cipher,
        sni                         = ch_result.sni,
        has_pqc                     = sv_result.has_pqc or ch_result.has_pqc,
        cert                        = leaf_cert,
        cert_chain                  = sv_result.cert_chain,
        diagnostics                 = ch_result.diagnostics + sv_result.diagnostics,
        record_provenance           = ch_result.record_provenance + sv_result.record_provenance,
        handshake_status            = status,
        client_offered_versions     = ch_result.client_offered_versions,
        client_alpn                 = ch_result.client_alpn,
        client_signature_algorithms = ch_result.client_signature_algorithms,
        selected_group              = sv_result.selected_group,
        selected_group_name         = sv_result.selected_group_name,
        san_matches_sni             = san_matches_sni,
        is_downgrade_detected       = sv_result.is_downgrade_detected,
        downgrade_warning           = sv_result.downgrade_warning,
        alert_level                 = sv_result.alert_level or ch_result.alert_level,
        alert_description           = sv_result.alert_description or ch_result.alert_description,
        alert_description_name      = sv_result.alert_description_name or ch_result.alert_description_name,
        client_cipher_suites        = ch_result.client_cipher_suites,
        client_supported_groups     = ch_result.client_supported_groups,
    )
    return final
