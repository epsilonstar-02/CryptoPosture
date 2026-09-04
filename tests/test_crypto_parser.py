"""
tests/test_crypto_parser.py
Unit and regression test suite for core/crypto_parser.py.
Validates:
  1. Stateful TLS record stream parsing (fragmentation, truncation, corrupt byte resynchronization)
  2. Multi-record handshake message reassembly (messages spanning across record boundaries)
  3. TLS 1.2 vs TLS 1.3 negotiation, GREASE filtering, and downgrade sentinels
  4. Expanded IANA cipher suite interpretation (PFS, AEAD, weak/export, unlisted fallback)
  5. Forensic certificate analysis (cryptographic self-signature, forged cert rejection, chain link validation, SAN/SNI matching, EC/Ed25519 keys)
  6. Explicit inconclusive states, TLS alerts, and field provenance tracking
"""

import datetime
import ipaddress
import struct
import unittest
from datetime import timezone, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from core.crypto_parser import (
    CipherInfo,
    HandshakeResult,
    RecordProvenance,
    TLSRecord,
    TLSRecordStreamParser,
    extract_handshake_messages,
    is_grease,
    parse_certificate_chain,
    parse_combined,
    parse_tls_handshake,
    resolve_cipher_info,
)
from core.models import CertValidity, KeyExchange, TLSVersion


# ---------------------------------------------------------------------------
# Test Helpers to construct raw TLS bytes
# ---------------------------------------------------------------------------

def _build_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Pack a 5-byte TLS record header + payload."""
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _build_handshake_msg(msg_type: int, body: bytes) -> bytes:
    """Pack a 4-byte Handshake header (type uint8 + length uint24) + body."""
    header = struct.pack(">B", msg_type) + struct.pack(">I", len(body))[1:]
    return header + body


def _build_client_hello(
    legacy_version: int = 0x0303,
    cipher_suites: list[int] = None,
    sni: str = None,
    supported_groups: list[int] = None,
    supported_versions: list[int] = None,
) -> bytes:
    if cipher_suites is None:
        cipher_suites = [0xC02F, 0xC030]

    cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)
    cs_len = struct.pack(">H", len(cs_bytes))

    # Extensions
    ext_payload = bytearray()
    if sni:
        sni_raw = sni.encode("ascii")
        sni_entry = struct.pack(">BH", 0, len(sni_raw)) + sni_raw
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        ext_payload.extend(struct.pack(">HH", 0x0000, len(sni_list)) + sni_list)

    if supported_groups:
        sg_bytes = b"".join(struct.pack(">H", g) for g in supported_groups)
        sg_list = struct.pack(">H", len(sg_bytes)) + sg_bytes
        ext_payload.extend(struct.pack(">HH", 0x000A, len(sg_list)) + sg_list)

    if supported_versions:
        sv_bytes = b"".join(struct.pack(">H", v) for v in supported_versions)
        sv_list = struct.pack(">B", len(sv_bytes)) + sv_bytes
        ext_payload.extend(struct.pack(">HH", 0x002B, len(sv_list)) + sv_list)

    extensions_block = struct.pack(">H", len(ext_payload)) + bytes(ext_payload) if ext_payload else b""

    random_32 = b"\x01" * 32
    session_id = b"\x00"  # 0 length
    compression = b"\x01\x00"  # 1 method: null (0x00)

    body = (
        struct.pack(">H", legacy_version)
        + random_32
        + session_id
        + cs_len
        + cs_bytes
        + compression
        + extensions_block
    )
    return _build_handshake_msg(0x01, body)


def _build_server_hello(
    legacy_version: int = 0x0303,
    cipher_suite: int = 0xC02F,
    random_bytes: bytes = None,
    selected_version: int = None,
    selected_group: int = None,
) -> bytes:
    if random_bytes is None:
        random_bytes = b"\x02" * 32

    ext_payload = bytearray()
    if selected_version is not None:
        sv_data = struct.pack(">H", selected_version)
        ext_payload.extend(struct.pack(">HH", 0x002B, len(sv_data)) + sv_data)

    if selected_group is not None:
        # key_share selected group (2 bytes group + 2 bytes key exchange length + dummy key)
        dummy_key = b"\x00" * 32
        ks_data = struct.pack(">HH", selected_group, len(dummy_key)) + dummy_key
        ext_payload.extend(struct.pack(">HH", 0x0033, len(ks_data)) + ks_data)

    extensions_block = struct.pack(">H", len(ext_payload)) + bytes(ext_payload) if ext_payload else b""

    body = (
        struct.pack(">H", legacy_version)
        + random_bytes
        + b"\x00"  # session id len = 0
        + struct.pack(">H", cipher_suite)
        + b"\x00"  # null compression
        + extensions_block
    )
    return _build_handshake_msg(0x02, body)


def _build_cert_handshake_msg(cert_ders: list[bytes]) -> bytes:
    """Build a TLS 1.2 Certificate handshake message wrapping a list of DER certs."""
    certs_payload = bytearray()
    for c in cert_ders:
        certs_payload.extend(struct.pack(">I", len(c))[1:] + c)
    total_len = struct.pack(">I", len(certs_payload))[1:]
    return _build_handshake_msg(0x0B, total_len + bytes(certs_payload))


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestTLSRecordStreamParser(unittest.TestCase):
    """Test stateful record layer stream parsing."""

    def test_in_order_single_record(self):
        record_bytes = _build_record(0x16, 0x0303, b"HANDSHAKE_PAYLOAD")
        parser = TLSRecordStreamParser(direction="client")
        parser.feed(record_bytes)

        self.assertEqual(len(parser.records), 1)
        self.assertEqual(parser.records[0].content_type, 0x16)
        self.assertEqual(parser.records[0].version, 0x0303)
        self.assertEqual(parser.records[0].payload, b"HANDSHAKE_PAYLOAD")
        self.assertFalse(parser.records[0].is_truncated)
        self.assertFalse(parser.is_truncated)

    def test_fragmented_record_payload_across_feed(self):
        """Simulate record received as two partial chunks."""
        full_record = _build_record(0x16, 0x0303, b"A" * 100)
        chunk1 = full_record[:30]
        chunk2 = full_record[30:]

        # Feeding combined data simulates stream reassembly
        parser = TLSRecordStreamParser(direction="server")
        parser.feed(chunk1 + chunk2)

        self.assertEqual(len(parser.records), 1)
        self.assertEqual(len(parser.records[0].payload), 100)
        self.assertFalse(parser.records[0].is_truncated)

    def test_truncated_record_header(self):
        """Stream ends with fewer than 5 bytes."""
        parser = TLSRecordStreamParser(direction="client")
        parser.feed(b"\x16\x03\x03")  # Only 3 bytes

        self.assertEqual(len(parser.records), 0)
        self.assertTrue(parser.is_truncated)
        self.assertTrue(any("truncated" in d for d in parser.diagnostics))

    def test_truncated_record_payload(self):
        """Stream cuts off inside record payload."""
        # Declared length = 50, but only 20 bytes payload provided
        header = struct.pack(">BHH", 0x16, 0x0303, 50)
        partial_data = header + (b"B" * 20)

        parser = TLSRecordStreamParser(direction="server")
        parser.feed(partial_data)

        self.assertEqual(len(parser.records), 1)
        self.assertTrue(parser.records[0].is_truncated)
        self.assertEqual(len(parser.records[0].payload), 20)
        self.assertTrue(parser.is_truncated)
        self.assertTrue(any("payload truncated" in d for d in parser.diagnostics))

    def test_corrupt_bytes_resynchronization(self):
        """Corrupt/non-TLS garbage bytes ahead of valid TLS record are skipped and resynced."""
        garbage = b"GARBAGE_NOISE_12345"
        valid_rec = _build_record(0x16, 0x0303, b"VALID_HANDSHAKE")
        data = garbage + valid_rec

        parser = TLSRecordStreamParser(direction="client")
        parser.feed(data)

        self.assertEqual(len(parser.records), 1)
        self.assertEqual(parser.records[0].payload, b"VALID_HANDSHAKE")
        self.assertTrue(parser.has_malformed_records)
        self.assertTrue(any("resynchronized" in d for d in parser.diagnostics))


class TestMultiRecordHandshakeReassembly(unittest.TestCase):
    """Test reassembly of handshake messages split across multiple TLS records."""

    def test_handshake_split_across_records(self):
        """
        A large Handshake message (e.g. 10,000 bytes) split across two TLS records
        (each record content_type = 0x16).
        """
        large_body = b"X" * 10000
        full_hs = _build_handshake_msg(0x0B, large_body)  # 4 header bytes + 10,000 = 10,004 bytes

        # Split into two records: 6,000 bytes and 4,004 bytes
        rec1 = _build_record(0x16, 0x0303, full_hs[:6000])
        rec2 = _build_record(0x16, 0x0303, full_hs[6000:])

        parser = TLSRecordStreamParser(direction="server")
        parser.feed(rec1 + rec2)

        self.assertEqual(len(parser.records), 2)
        messages = extract_handshake_messages(parser.handshake_stream, parser.diagnostics)

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].msg_type, 0x0B)
        self.assertEqual(messages[0].length, 10000)
        self.assertEqual(len(messages[0].body), 10004)
        self.assertFalse(messages[0].is_truncated)

    def test_multiple_handshake_messages_coalesced_in_one_record(self):
        """Multiple handshake messages inside a single TLS Handshake record."""
        sh = _build_server_hello(legacy_version=0x0303, cipher_suite=0xC02F)
        shd = _build_handshake_msg(0x0E, b"")  # ServerHelloDone
        combined_payload = sh + shd

        rec = _build_record(0x16, 0x0303, combined_payload)
        parser = TLSRecordStreamParser(direction="server")
        parser.feed(rec)

        messages = extract_handshake_messages(parser.handshake_stream, parser.diagnostics)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].msg_type, 0x02)  # ServerHello
        self.assertEqual(messages[1].msg_type, 0x0E)  # ServerHelloDone


class TestTLSVersionAndCipherNegotiation(unittest.TestCase):
    """Test TLS version negotiation, GREASE filtering, downgrade sentinels, and PQC."""

    def test_tls12_server_hello(self):
        """Standard TLS 1.2 ServerHello with server_version = 0x0303."""
        sh = _build_server_hello(legacy_version=0x0303, cipher_suite=0xC02F)
        stream = _build_record(0x16, 0x0303, sh)

        res = parse_tls_handshake(stream, direction="server")
        self.assertEqual(res.tls_version, TLSVersion.TLS12)
        self.assertEqual(res.cipher_suite_id, 0xC02F)
        self.assertEqual(res.cipher_suite_name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        self.assertTrue(res.is_forward_secret)
        self.assertFalse(res.is_weak_cipher)

    def test_tls13_server_hello_with_supported_versions(self):
        """TLS 1.3 ServerHello: legacy_version = 0x0303, supported_versions = 0x0304."""
        sh = _build_server_hello(
            legacy_version=0x0303,
            cipher_suite=0x1301,
            selected_version=0x0304,
            selected_group=0x001D,  # x25519
        )
        stream = _build_record(0x16, 0x0301, sh)

        res = parse_tls_handshake(stream, direction="server")
        self.assertEqual(res.tls_version, TLSVersion.TLS13)
        self.assertEqual(res.cipher_suite_id, 0x1301)
        self.assertEqual(res.cipher_suite_name, "TLS_AES_128_GCM_SHA256")
        self.assertTrue(res.is_forward_secret)
        self.assertEqual(res.selected_group_name, "x25519")

    def test_client_hello_grease_filtering(self):
        """ClientHello with GREASE cipher suites and versions (RFC 8701)."""
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0x3A3A))
        self.assertFalse(is_grease(0xC02F))

        ch = _build_client_hello(
            legacy_version=0x0303,
            cipher_suites=[0x0A0A, 0x1301, 0x3A3A, 0xC02F],
            supported_versions=[0x1A1A, 0x0304, 0x0303],
            supported_groups=[0x2A2A, 0x001D],
            sni="mail.corp.com",
        )
        stream = _build_record(0x16, 0x0301, ch)

        res = parse_tls_handshake(stream, direction="client")
        self.assertEqual(res.tls_version, TLSVersion.TLS13)
        self.assertEqual(res.sni, "mail.corp.com")
        self.assertEqual(res.client_supported_groups, [0x001D])  # GREASE filtered out
        self.assertIn(TLSVersion.TLS13, res.client_offered_versions)
        self.assertIn(TLSVersion.TLS12, res.client_offered_versions)

    def test_pqc_group_detection(self):
        """Client offering X25519MLKEM768 (0x11EC) triggers has_pqc = True."""
        ch = _build_client_hello(
            legacy_version=0x0303,
            supported_groups=[0x001D, 0x11EC],
        )
        stream = _build_record(0x16, 0x0301, ch)
        res = parse_tls_handshake(stream, direction="client")
        self.assertTrue(res.has_pqc)

    def test_downgrade_sentinel_tls12(self):
        """ServerHello containing TLS 1.2 downgrade sentinel DOWNGRD\\x01."""
        random_with_sentinel = b"\xAA" * 24 + bytes.fromhex("444f574e47524401")
        sh = _build_server_hello(
            legacy_version=0x0303,
            cipher_suite=0xC02F,
            random_bytes=random_with_sentinel,
        )
        stream = _build_record(0x16, 0x0303, sh)
        res = parse_tls_handshake(stream, direction="server")

        self.assertTrue(res.is_downgrade_detected)
        self.assertIsNotNone(res.downgrade_warning)
        self.assertIn("downgrade sentinel detected", res.downgrade_warning)

    def test_hello_retry_request(self):
        """ServerHello containing HelloRetryRequest magic random."""
        hrr_random = bytes.fromhex("cf21ad74e5994dc7be7108be00df05b7715b7b52c056025282cd6fc08540d2a2")
        sh = _build_server_hello(
            legacy_version=0x0303,
            cipher_suite=0x1301,
            random_bytes=hrr_random,
            selected_version=0x0304,
        )
        stream = _build_record(0x16, 0x0301, sh)
        res = parse_tls_handshake(stream, direction="server")
        self.assertEqual(res.tls_version, TLSVersion.TLS13)


class TestExpandedCipherRegistry(unittest.TestCase):
    """Test cipher suite classification and fallbacks."""

    def test_tls13_aead_ciphers(self):
        for cs_id in (0x1301, 0x1302, 0x1303, 0x1304, 0x1305):
            info = resolve_cipher_info(cs_id)
            self.assertTrue(info.is_forward_secret)
            self.assertTrue(info.is_aead)
            self.assertFalse(info.is_weak)

    def test_weak_and_export_ciphers(self):
        weak_ids = [
            0x0000,  # NULL
            0x0004,  # RC4-MD5
            0x0005,  # RC4-SHA
            0x000A,  # 3DES-EDE-CBC-SHA
            0x0003,  # EXPORT-RC4
            0x0060,  # EXPORT-RC4-MD5
            0x0017,  # DH_anon RC4
        ]
        for cs_id in weak_ids:
            info = resolve_cipher_info(cs_id)
            self.assertTrue(info.is_weak, f"Cipher 0x{cs_id:04X} should be marked weak")

    def test_static_rsa_no_forward_secrecy(self):
        info = resolve_cipher_info(0x002F)  # TLS_RSA_WITH_AES_128_CBC_SHA
        self.assertEqual(info.key_exchange, KeyExchange.RSA)
        self.assertFalse(info.is_forward_secret)
        self.assertFalse(info.is_weak)

    def test_unlisted_and_grease_fallback(self):
        info_unlisted = resolve_cipher_info(0x9999)
        self.assertEqual(info_unlisted.name, "0x9999")
        self.assertFalse(info_unlisted.is_forward_secret)
        self.assertFalse(info_unlisted.is_weak)

        info_grease = resolve_cipher_info(0x4A4A)
        self.assertEqual(info_grease.name, "TLS_GREASE_0x4A4A")


class TestCertificateForensicAnalysis(unittest.TestCase):
    """Test cryptographic self-signature verification, chain links, SANs, and keys."""

    def test_cryptographically_verified_self_signed(self):
        """Generate genuine self-signed certificate and verify cryptographic validity."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "self.example.com")])
        now = datetime.datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(12345)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        chain = parse_certificate_chain([der])

        self.assertEqual(len(chain), 1)
        c = chain[0]
        self.assertTrue(c.is_self_signed)
        self.assertTrue(c.signature_valid)
        self.assertEqual(c.validity, CertValidity.SELF_SIGNED)
        self.assertEqual(c.key_type, "RSA")
        self.assertEqual(c.key_length_bits, 2048)
        self.assertEqual(c.subject_cn, "self.example.com")

    def test_forged_self_signed_cert_rejected(self):
        """
        Forged certificate where subject == issuer name, but signature is made
        with a completely different key. Verification MUST detect failure!
        """
        key1 = rsa.generate_private_key(65537, 2048, default_backend())
        key2 = rsa.generate_private_key(65537, 2048, default_backend())

        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "forged.example.com")])
        now = datetime.datetime.now(timezone.utc)

        # Subject and Issuer set to same name, public key is key1, but signed by key2!
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key1.public_key())
            .serial_number(67890)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key2, hashes.SHA256(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        chain = parse_certificate_chain([der])

        self.assertEqual(len(chain), 1)
        c = chain[0]
        self.assertFalse(c.is_self_signed, "Forged signature should NOT be verified as self-signed")
        self.assertFalse(c.signature_valid)
        self.assertTrue(any("cryptographic self-signature verification failed" in d for d in c.diagnostics))

    def test_two_certificate_chain_link_validation(self):
        """Leaf certificate issued by Intermediate CA -> link signature verified."""
        ca_key = rsa.generate_private_key(65537, 2048, default_backend())
        leaf_key = rsa.generate_private_key(65537, 2048, default_backend())

        ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Corporate Intermediate CA")])
        leaf_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "mail.company.internal")])
        now = datetime.datetime.now(timezone.utc)

        # Build CA
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        # Build Leaf signed by CA
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(2)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        ca_der = ca_cert.public_bytes(serialization.Encoding.DER)

        diagnostics = []
        chain = parse_certificate_chain([leaf_der, ca_der], diagnostics=diagnostics)

        self.assertEqual(len(chain), 2)
        # Leaf
        self.assertEqual(chain[0].subject_cn, "mail.company.internal")
        self.assertEqual(chain[0].issuer_cn, "Corporate Intermediate CA")
        self.assertFalse(chain[0].is_self_signed)
        self.assertTrue(chain[0].signature_valid)  # Cryptographically verified against CA key

        # Intermediate CA
        self.assertEqual(chain[1].subject_cn, "Corporate Intermediate CA")
        self.assertTrue(chain[1].is_ca)
        self.assertTrue(chain[1].is_self_signed)
        self.assertTrue(chain[1].signature_valid)

    def test_expired_certificate_detection(self):
        """Certificate with not_after in the past."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "expired.com")])
        now = datetime.datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(100)
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now - timedelta(days=10))
            .sign(key, hashes.SHA256(), default_backend())
        )
        chain = parse_certificate_chain([cert.public_bytes(serialization.Encoding.DER)])
        self.assertEqual(chain[0].validity, CertValidity.EXPIRED)

    def test_not_yet_valid_certificate_detection(self):
        """Certificate with not_before in the future."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "future.com")])
        now = datetime.datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(101)
            .not_valid_before(now + timedelta(days=5))
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        chain = parse_certificate_chain([cert.public_bytes(serialization.Encoding.DER)])
        self.assertEqual(chain[0].validity, CertValidity.NOT_YET_VALID)

    def test_ec_and_ed25519_cert_parsing(self):
        """Test EC secp256r1 and Ed25519 certificate key analysis."""
        # EC
        ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ec.com")])
        now = datetime.datetime.now(timezone.utc)
        ec_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ec_key.public_key())
            .serial_number(201)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(ec_key, hashes.SHA256(), default_backend())
        )
        ec_chain = parse_certificate_chain([ec_cert.public_bytes(serialization.Encoding.DER)])
        self.assertEqual(ec_chain[0].key_type, "EC")
        self.assertEqual(ec_chain[0].curve_name, "secp256r1")
        self.assertEqual(ec_chain[0].key_length_bits, 256)

        # Ed25519
        ed_key = ed25519.Ed25519PrivateKey.generate()
        ed_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ed_key.public_key())
            .serial_number(202)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(ed_key, None)
        )
        ed_chain = parse_certificate_chain([ed_cert.public_bytes(serialization.Encoding.DER)])
        self.assertEqual(ed_chain[0].key_type, "Ed25519")
        self.assertEqual(ed_chain[0].key_length_bits, 256)

    def test_san_extraction_and_sni_wildcard_matching(self):
        """Subject Alternative Names extraction and RFC 6125 wildcard matching."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "legacy.corp.com")])
        now = datetime.datetime.now(timezone.utc)

        sans = [
            x509.DNSName("mail.corp.com"),
            x509.DNSName("*.secure.corp.com"),
            x509.IPAddress(ipaddress.IPv4Address("192.168.1.50")),
        ]

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(301)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        der = cert.public_bytes(serialization.Encoding.DER)

        # Test exact match
        chain_exact = parse_certificate_chain([der], sni="mail.corp.com")
        self.assertTrue(chain_exact[0].san_matches_sni)
        self.assertIn("mail.corp.com", chain_exact[0].san_list)
        self.assertIn("192.168.1.50", chain_exact[0].san_list)

        # Test wildcard match
        chain_wc = parse_certificate_chain([der], sni="relay1.secure.corp.com")
        self.assertTrue(chain_wc[0].san_matches_sni)

        # Test mismatch
        chain_mismatch = parse_certificate_chain([der], sni="evil.attacker.com")
        self.assertFalse(chain_mismatch[0].san_matches_sni)


class TestInconclusiveAndAlertStates(unittest.TestCase):
    """Test explicit INCONCLUSIVE states, alerts, and field provenance."""

    def test_client_hello_only_inconclusive(self):
        """Client sends ClientHello, but server never replies (or capture stopped)."""
        ch = _build_client_hello(sni="mail.company.com")
        client_stream = _build_record(0x16, 0x0301, ch)

        combined = parse_combined(client_stream, b"")
        self.assertEqual(combined.handshake_status, "INCONCLUSIVE_CLIENT_HELLO_ONLY")
        self.assertEqual(combined.sni, "mail.company.com")
        self.assertIsNone(combined.cipher_suite_id)

    def test_app_data_only_inconclusive(self):
        """Session contains only encrypted ApplicationData records."""
        app_rec = _build_record(0x17, 0x0303, b"ENCRYPTED_PAYLOAD_123")
        combined = parse_combined(app_rec, app_rec)

        self.assertEqual(combined.handshake_status, "INCONCLUSIVE_NO_HANDSHAKE")
        self.assertIsNone(combined.cipher_suite_id)

    def test_tls_alert_terminated(self):
        """Session terminated by fatal TLS Alert (level=2, desc=40 handshake_failure)."""
        ch = _build_client_hello()
        client_stream = _build_record(0x16, 0x0301, ch)

        # Server sends fatal alert 40 (handshake_failure)
        alert_payload = struct.pack(">BB", 2, 40)
        server_stream = _build_record(0x15, 0x0303, alert_payload)

        combined = parse_combined(client_stream, server_stream)
        self.assertEqual(combined.handshake_status, "ALERT_TERMINATED")
        self.assertEqual(combined.alert_level, 2)
        self.assertEqual(combined.alert_description, 40)
        self.assertEqual(combined.alert_description_name, "handshake_failure")
        self.assertTrue(any("handshake_failure" in d for d in combined.diagnostics))

    def test_record_provenance_tracking(self):
        """Record provenance accurately records offsets, wire versions, and content types."""
        ch = _build_client_hello()
        rec1 = _build_record(0x16, 0x0301, ch)
        rec2 = _build_record(0x17, 0x0303, b"APP_DATA")

        res = parse_tls_handshake(rec1 + rec2, direction="client")
        self.assertEqual(len(res.record_provenance), 2)

        p1 = res.record_provenance[0]
        self.assertEqual(p1.offset, 0)
        self.assertEqual(p1.content_type, 0x16)
        self.assertEqual(p1.version_raw, 0x0301)
        self.assertEqual(p1.direction, "client")

        p2 = res.record_provenance[1]
        self.assertEqual(p2.offset, len(rec1))
        self.assertEqual(p2.content_type, 0x17)
        self.assertEqual(p2.version_raw, 0x0303)


if __name__ == "__main__":
    unittest.main(verbosity=2)
