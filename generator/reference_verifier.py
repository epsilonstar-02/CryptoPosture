"""
generator/reference_verifier.py
Independent reference verifier for forensic PCAP test fixtures.

Provides an objective, independent interpretation of network packets directly
from raw Scapy packet layers and Python's standard `cryptography` library.
Critically, this does NOT call `core.pipeline`, preventing self-referential bias:
it verifies that the generated PCAP physically and cryptographically matches
its ground-truth benchmark specification.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import IP, TCP, Raw, rdpcap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec


@dataclass
class ReferenceStreamObservation:
    """Independent observation of a single TCP stream in a PCAP."""
    flow_key: Tuple[str, int, str, int]
    sport: int
    dport: int
    total_packets: int = 0
    client_bytes: bytearray = field(default_factory=bytearray)
    server_bytes: bytearray = field(default_factory=bytearray)
    
    # Protocol facts inferred directly from raw payload
    is_smtp: bool = False
    is_imap: bool = False
    ehlo_seen: bool = False
    starttls_advertised: bool = False
    starttls_requested: bool = False
    starttls_ready_220: bool = False
    buffer_injection_detected: bool = False
    injected_commands: List[str] = field(default_factory=list)
    
    # TLS facts
    has_tls: bool = False
    tls_records_count: int = 0
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    negotiated_tls_version: Optional[str] = None
    selected_cipher_suite: Optional[int] = None
    sni: Optional[str] = None
    
    # X.509 cert facts
    cert_found: bool = False
    cert_subject_cn: Optional[str] = None
    cert_issuer_cn: Optional[str] = None
    cert_is_self_signed: Optional[bool] = None
    cert_sig_algo: Optional[str] = None
    cert_key_size: Optional[int] = None
    cert_is_expired: Optional[bool] = None
    cert_not_yet_valid: Optional[bool] = None
    cert_san_list: List[str] = field(default_factory=list)
    sni_matches_san: Optional[bool] = None


@dataclass
class ReferenceVerificationReport:
    """Result of independently verifying a PCAP against a benchmark spec."""
    pcap_path: str
    scenario_id: str
    passed: bool
    checks_passed: int
    checks_failed: int
    failures: List[str] = field(default_factory=list)
    observations: Dict[str, Any] = field(default_factory=dict)


def _extract_sni(exts_data: bytes) -> Optional[str]:
    """Parse Server Name Indication from TLS extensions bytes."""
    idx = 0
    while idx + 4 <= len(exts_data):
        ext_type, ext_len = struct.unpack(">HH", exts_data[idx:idx+4])
        idx += 4
        if idx + ext_len > len(exts_data):
            break
        if ext_type == 0x0000:  # server_name
            body = exts_data[idx:idx+ext_len]
            if len(body) >= 5:
                name_len = struct.unpack(">H", body[3:5])[0]
                return body[5:5+name_len].decode("ascii", errors="replace")
        idx += ext_len
    return None


def _extract_supported_version(exts_data: bytes) -> Optional[int]:
    """Parse supported_versions extension for TLS 1.3 indication."""
    idx = 0
    while idx + 4 <= len(exts_data):
        ext_type, ext_len = struct.unpack(">HH", exts_data[idx:idx+4])
        idx += 4
        if idx + ext_len > len(exts_data):
            break
        if ext_type == 0x002B:  # supported_versions
            body = exts_data[idx:idx+ext_len]
            if len(body) == 2:
                return struct.unpack(">H", body)[0]
            elif len(body) >= 3:
                return struct.unpack(">H", body[1:3])[0]
        idx += ext_len
    return None


def _parse_tls_handshakes(stream: ReferenceStreamObservation, payload: bytes, is_client: bool):
    """Independently parse TLS records and handshake structures."""
    idx = 0
    while idx + 5 <= len(payload):
        content_type, legacy_version, record_len = struct.unpack(">BHH", payload[idx:idx+5])
        record_bytes = payload[idx+5:idx+5+record_len]
        idx += 5 + record_len

        if content_type != 0x16:  # Handshake
            continue

        stream.has_tls = True
        stream.tls_records_count += 1

        # Walk Handshake messages
        h_idx = 0
        while h_idx + 4 <= len(record_bytes):
            msg_type = record_bytes[h_idx]
            msg_len = struct.unpack(">I", b"\x00" + record_bytes[h_idx+1:h_idx+4])[0]
            h_body = record_bytes[h_idx+4:h_idx+4+msg_len]
            h_idx += 4 + msg_len

            if msg_type == 0x01:  # ClientHello
                stream.client_hello_seen = True
                if len(h_body) >= 34:
                    sess_len = h_body[34]
                    c_idx = 35 + sess_len
                    if c_idx + 2 <= len(h_body):
                        cs_len = struct.unpack(">H", h_body[c_idx:c_idx+2])[0]
                        c_idx += 2 + cs_len
                        if c_idx + 1 <= len(h_body):
                            comp_len = h_body[c_idx]
                            c_idx += 1 + comp_len
                            if c_idx + 2 <= len(h_body):
                                ext_total = struct.unpack(">H", h_body[c_idx:c_idx+2])[0]
                                exts_data = h_body[c_idx+2:c_idx+2+ext_total]
                                stream.sni = _extract_sni(exts_data)

            elif msg_type == 0x02:  # ServerHello
                stream.server_hello_seen = True
                if len(h_body) >= 34:
                    sess_len = h_body[34]
                    c_idx = 35 + sess_len
                    if c_idx + 2 <= len(h_body):
                        stream.selected_cipher_suite = struct.unpack(">H", h_body[c_idx:c_idx+2])[0]
                        c_idx += 2 + 1
                        if c_idx + 2 <= len(h_body):
                            ext_total = struct.unpack(">H", h_body[c_idx:c_idx+2])[0]
                            exts_data = h_body[c_idx+2:c_idx+2+ext_total]
                            sv = _extract_supported_version(exts_data)
                            if sv == 0x0304:
                                stream.negotiated_tls_version = "TLS1.3"
                        if not stream.negotiated_tls_version:
                            v = struct.unpack(">H", h_body[:2])[0]
                            if v == 0x0303:
                                stream.negotiated_tls_version = "TLS1.2"
                            elif v == 0x0301:
                                stream.negotiated_tls_version = "TLS1.0"
                            elif v == 0x0302:
                                stream.negotiated_tls_version = "TLS1.1"

            elif msg_type == 0x0B:  # Certificate
                stream.cert_found = True
                if len(h_body) >= 6:
                    certs_total_len = struct.unpack(">I", b"\x00" + h_body[:3])[0]
                    first_cert_len = struct.unpack(">I", b"\x00" + h_body[3:6])[0]
                    first_cert_der = h_body[6:6+first_cert_len]
                    try:
                        cert = x509.load_der_x509_certificate(first_cert_der, default_backend())
                        # Subject & Issuer
                        stream.cert_subject_cn = next(
                            (a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
                            str(cert.subject)
                        )
                        stream.cert_issuer_cn = next(
                            (a.value for a in cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)),
                            str(cert.issuer)
                        )
                        stream.cert_is_self_signed = (cert.subject == cert.issuer)

                        # Validity
                        now = datetime.now(timezone.utc)
                        stream.cert_is_expired = (now > cert.not_valid_after_utc)
                        stream.cert_not_yet_valid = (now < cert.not_valid_before_utc)

                        # Key info
                        pub = cert.public_key()
                        if isinstance(pub, rsa.RSAPublicKey):
                            stream.cert_key_size = pub.key_size
                        elif isinstance(pub, ec.EllipticCurvePublicKey):
                            stream.cert_key_size = pub.key_size

                        # Signature algo
                        if hasattr(cert, "signature_algorithm_oid") and cert.signature_algorithm_oid:
                            stream.cert_sig_algo = cert.signature_algorithm_oid._name
                        else:
                            stream.cert_sig_algo = "UNKNOWN"

                        # SANs
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            stream.cert_san_list = [item.value for item in san_ext.value if isinstance(item, x509.DNSName)]
                        except Exception:
                            stream.cert_san_list = []

                        if stream.sni:
                            candidates = stream.cert_san_list + ([stream.cert_subject_cn] if stream.cert_subject_cn else [])
                            stream.sni_matches_san = (stream.sni in candidates)
                    except Exception:
                        pass


def inspect_pcap_independently(pcap_path: str | Path) -> List[ReferenceStreamObservation]:
    """
    Independently inspect all TCP streams in a PCAP file using raw Scapy packets.
    Reassembles TCP streams and parses TLS/SMTP structures objectively.
    """
    packets = rdpcap(str(pcap_path))
    streams: Dict[Tuple[str, int, str, int], ReferenceStreamObservation] = {}

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(tcp.payload) if tcp.haslayer(Raw) else b""

        sport, dport = tcp.sport, tcp.dport
        if dport in (25, 465, 587, 993, 110, 995) or sport > dport:
            fkey = (ip.src, sport, ip.dst, dport)
            is_client_to_server = True
        else:
            fkey = (ip.dst, dport, ip.src, sport)
            is_client_to_server = False

        if fkey not in streams:
            streams[fkey] = ReferenceStreamObservation(
                flow_key=fkey,
                sport=fkey[1],
                dport=fkey[3],
                is_smtp=(fkey[3] in (25, 465, 587) or fkey[1] in (25, 465, 587)),
                is_imap=(fkey[3] == 993 or fkey[1] == 993),
            )

        stream = streams[fkey]
        stream.total_packets += 1

        if is_client_to_server:
            if payload:
                if b"STARTTLS" in payload and (b"MAIL FROM" in payload or b"RCPT TO" in payload):
                    stream.buffer_injection_detected = True
                    lines = payload.decode("latin1", errors="replace").splitlines()
                    for line in lines:
                        if line.strip() and not line.strip().startswith("STARTTLS"):
                            stream.injected_commands.append(line.strip())
                if b"STARTTLS\r\n" in payload or b"STARTTLS\n" in payload:
                    stream.starttls_requested = True
                stream.client_bytes.extend(payload)
                _parse_tls_handshakes(stream, payload, is_client=True)
        else:
            if payload:
                if b"250-STARTTLS" in payload or b"250 STARTTLS" in payload:
                    stream.starttls_advertised = True
                if b"220 Ready to start TLS" in payload or b"220 2.0.0 Ready to start TLS" in payload:
                    stream.starttls_ready_220 = True
                stream.server_bytes.extend(payload)
                _parse_tls_handshakes(stream, payload, is_client=False)

    return list(streams.values())


def verify_scenario_against_spec(
    pcap_path: str | Path,
    spec: Any,
) -> ReferenceVerificationReport:
    """
    Verify that the actual PCAP conforms to its ScenarioBenchmarkSpec
    using only independent raw packet inspections.
    """
    streams = inspect_pcap_independently(pcap_path)
    failures = []
    checks_passed = 0
    checks_failed = 0

    def check(condition: bool, msg: str):
        nonlocal checks_passed, checks_failed
        if condition:
            checks_passed += 1
        else:
            checks_failed += 1
            failures.append(msg)

    check(len(streams) >= 1, f"Expected at least 1 stream, found {len(streams)}")
    if not streams:
        return ReferenceVerificationReport(
            pcap_path=str(pcap_path),
            scenario_id=spec.scenario_id,
            passed=False,
            checks_passed=0,
            checks_failed=1,
            failures=failures,
        )

    primary = streams[0]

    # 1. Port / Protocol verification
    if spec.expected_channel_type.value == "Implicit TLS":
        check(primary.has_tls, "Implicit TLS stream must contain TLS records")
    elif spec.expected_channel_type.value == "STARTTLS":
        check(primary.starttls_ready_220 or primary.starttls_requested or primary.has_tls,
              "STARTTLS stream must exhibit STARTTLS command exchange")
    elif spec.expected_channel_type.value == "Plaintext":
        check(not primary.has_tls, "Plaintext stream must not contain TLS handshake")

    # 2. STARTTLS specific state
    if spec.expected_starttls_status.value == "Stripped":
        check(not primary.starttls_advertised, "Stripped scenario must NOT advertise STARTTLS in EHLO")
        check(not primary.has_tls, "Stripped scenario must fall back to cleartext without TLS")
    elif spec.expected_starttls_status.value == "Negotiated":
        check(primary.starttls_ready_220 or primary.has_tls, "Negotiated STARTTLS must reach TLS state")

    # 3. Buffer Injection check
    if spec.expected_buffer_injection:
        check(primary.buffer_injection_detected, "Buffer injection attack must contain pipelined commands in STARTTLS segment")
    else:
        check(not primary.buffer_injection_detected, "Benign scenario must not trigger buffer injection condition")

    # 4. Negotiated TLS Version
    if spec.expected_tls_version:
        v_str = spec.expected_tls_version.value
        check(primary.negotiated_tls_version == v_str,
              f"Negotiated TLS version mismatch: expected {v_str}, observed {primary.negotiated_tls_version}")

    # 5. Certificate Verification
    if spec.expected_cert_self_signed is not None:
        check(primary.cert_is_self_signed == spec.expected_cert_self_signed,
              f"Cert self_signed mismatch: expected {spec.expected_cert_self_signed}, observed {primary.cert_is_self_signed}")

    if spec.expected_cert_weak_sig is True:
        check(primary.cert_sig_algo is not None and "sha1" in primary.cert_sig_algo.lower(),
              f"Cert weak sig mismatch: expected SHA-1, observed {primary.cert_sig_algo}")

    if spec.expected_cert_weak_key is True:
        check(primary.cert_key_size is not None and primary.cert_key_size < 2048,
              f"Cert weak key mismatch: expected < 2048 bits, observed {primary.cert_key_size}")

    if spec.expected_cert_validity:
        v_name = spec.expected_cert_validity.value
        if v_name == "Expired":
            check(primary.cert_is_expired is True, "Expected certificate to be expired")
        elif v_name == "Valid":
            check(primary.cert_is_expired is False and primary.cert_not_yet_valid is False,
                  "Expected certificate to be currently valid")

    obs = {
        "flow": f"{primary.sport}->{primary.dport}",
        "has_tls": primary.has_tls,
        "tls_version": primary.negotiated_tls_version,
        "cipher_suite": hex(primary.selected_cipher_suite) if primary.selected_cipher_suite else None,
        "cert_subject": primary.cert_subject_cn,
        "cert_issuer": primary.cert_issuer_cn,
        "cert_self_signed": primary.cert_is_self_signed,
        "cert_sig_algo": primary.cert_sig_algo,
        "cert_key_size": primary.cert_key_size,
        "buffer_injection": primary.buffer_injection_detected,
    }

    return ReferenceVerificationReport(
        pcap_path=str(pcap_path),
        scenario_id=spec.scenario_id,
        passed=(checks_failed == 0),
        checks_passed=checks_passed,
        checks_failed=checks_failed,
        failures=failures,
        observations=obs,
    )
