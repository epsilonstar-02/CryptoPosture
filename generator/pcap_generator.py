"""
generator/pcap_generator.py
Synthetic PCAP evidence generator for offline forensic testing and live demos.

Generates 5 realistic email packet captures covering key attack/configuration scenarios:
  1. clean_implicit_tls.pcap       — IMAPS, TLS 1.3, ECDHE, AES-256-GCM (GOOD)
  2. weak_cipher_starttls.pcap     — SMTP STARTTLS, TLS 1.0, 3DES (WEAK)
  3. stripped_starttls_plaintext.pcap — SMTP STARTTLS stripped by MITM (CRITICAL)
  4. expired_cert_implicit_tls.pcap   — IMAPS, TLS 1.2, expired certificate (CRITICAL)
  5. buffer_injection_attack.pcap     — SMTP STARTTLS + pipelined commands (CRITICAL)

All PCAPs use synthetic IP addresses (192.168.1.x / 10.0.0.x) and are
clearly labeled as synthetic forensic test data.
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path
from typing import List

from scapy.all import (
    IP, TCP, Raw, Ether, wrpcap,
    RandMAC,
)
from scapy.packet import Packet


# ---------------------------------------------------------------------------
# Default output directory
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "sample_pcaps"


# ---------------------------------------------------------------------------
# Helper: Build TCP packet
# ---------------------------------------------------------------------------

def _ts(base: float, offset: float) -> float:
    return base + offset


def _tcp_pkt(
    src_ip: str, dst_ip: str, sport: int, dport: int,
    payload: bytes, flags: str = "PA",
    seq: int = 1000, ack: int = 2000,
    ts: float = 0.0,
) -> Packet:
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) /
        Raw(load=payload)
    )
    pkt.time = ts
    return pkt


# ---------------------------------------------------------------------------
# TLS record builders (minimal synthetic handshake bytes)
# ---------------------------------------------------------------------------

def _tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Wrap payload in a TLS record header."""
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _client_hello(version: int = 0x0303, cipher_suites: List[int] = None, sni: str = "mail.example.com") -> bytes:
    """
    Build a minimal TLS ClientHello handshake message.
    version: TLS version (e.g. 0x0303 = TLS 1.2, 0x0304 = TLS 1.3 via extension)
    """
    if cipher_suites is None:
        cipher_suites = [0xC02F, 0xC030]   # ECDHE-RSA-AES128-GCM, ECDHE-RSA-AES256-GCM

    cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)
    cs_list  = struct.pack(">H", len(cs_bytes)) + cs_bytes

    # Random (32 bytes)
    random_bytes = b"\x5a" * 32

    # Session ID (empty)
    session_id = b"\x00"

    # Compression methods: null
    compression = b"\x01\x00"

    # Extensions
    # server_name (0x0000)
    sni_bytes  = sni.encode("ascii")
    sni_ext    = (struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes)
    sni_list   = struct.pack(">H", len(sni_ext)) + sni_ext
    sni_ext_full = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    # supported_groups (0x000A): x25519 (0x001D), secp256r1 (0x0017)
    groups     = struct.pack(">HH", 0x001D, 0x0017)
    groups_ext = struct.pack(">HHH", 0x000A, len(groups)+2, len(groups)) + groups

    # supported_versions (0x002B) - for TLS 1.3 indication
    sv_ext = b""
    if version >= 0x0304:
        sv_list  = struct.pack(">HH", 0x0304, 0x0303)  # TLS 1.3, TLS 1.2
        sv_ext   = struct.pack(">HH", 0x002B, len(sv_list)+1) + struct.pack(">B", len(sv_list)) + sv_list

    exts_body = sni_ext_full + groups_ext + sv_ext
    exts      = struct.pack(">H", len(exts_body)) + exts_body

    body = (
        struct.pack(">H", version) +  # client_version
        random_bytes +
        session_id +
        cs_list +
        compression +
        exts
    )

    # Handshake header: type=1 (ClientHello) + 3-byte length
    hs_header = struct.pack(">B", 0x01) + struct.pack(">I", len(body))[1:]
    handshake = hs_header + body

    return _tls_record(0x16, 0x0301, handshake)   # 0x16=Handshake, 0x0301 outer version


def _server_hello(version: int = 0x0303, cipher_suite: int = 0xC02F) -> bytes:
    """Build a minimal TLS ServerHello."""
    random_bytes = b"\x5b" * 32
    session_id   = b"\x00"
    compression  = b"\x00"

    # supported_versions ext for TLS 1.3
    sv_ext = b""
    if version >= 0x0304:
        sv_ext = struct.pack(">HHH", 0x002B, 2, version)

    exts = struct.pack(">H", len(sv_ext)) + sv_ext if sv_ext else b"\x00\x00"

    body = (
        struct.pack(">H", min(version, 0x0303)) +  # legacy field
        random_bytes +
        session_id +
        struct.pack(">H", cipher_suite) +
        compression +
        exts
    )

    hs_header = struct.pack(">B", 0x02) + struct.pack(">I", len(body))[1:]
    return _tls_record(0x16, 0x0301, hs_header + body)


def _minimal_cert(subject_cn: str = "mail.example.com", expired: bool = False) -> bytes:
    """
    Generate a minimal DER-encoded self-signed X.509 certificate using the
    `cryptography` library. Returns the TLS Certificate handshake message bytes.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime, timezone, timedelta

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(timezone.utc)

    if expired:
        not_before = now - timedelta(days=730)
        not_after  = now - timedelta(days=365)
    else:
        not_before = now - timedelta(days=1)
        not_after  = now + timedelta(days=364)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)           # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # TLS Certificate message:
    # type=0x0B, length, certs_total_length, cert_length, cert_data
    cert_len   = struct.pack(">I", len(cert_der))[1:]           # 3 bytes
    certs_total = struct.pack(">I", len(cert_der) + 3)[1:]      # 3 bytes
    msg_body   = certs_total + cert_len + cert_der
    hs_header  = struct.pack(">B", 0x0B) + struct.pack(">I", len(msg_body))[1:]
    return _tls_record(0x16, 0x0301, hs_header + msg_body)


def _change_cipher_spec() -> bytes:
    return _tls_record(0x14, 0x0303, b"\x01")


def _app_data(payload: bytes = b"EMAIL DATA") -> bytes:
    return _tls_record(0x17, 0x0303, payload)


# ---------------------------------------------------------------------------
# Scenario 1: Clean Implicit TLS (IMAPS port 993, TLS 1.3, ECDHE, AES-256-GCM)
# ---------------------------------------------------------------------------

def _gen_clean_implicit_tls(output_dir: Path) -> Path:
    base = time.time()
    pkts = []
    client_ip = "192.168.1.100"
    server_ip = "10.0.0.1"
    sport, dport = 54321, 993

    # TCP SYN / SYN-ACK / ACK (3-way handshake)
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "S",  seq=999, ack=0, ts=_ts(base, 0.000)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"", "SA", seq=1999, ack=1000, ts=_ts(base, 0.001)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "A",  seq=1000, ack=2000, ts=_ts(base, 0.002)))

    # ClientHello — TLS 1.3, ECDHE ciphers, SNI
    ch = _client_hello(version=0x0304, cipher_suites=[0x1302, 0x1301, 0x1303], sni="imap.example.com")
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, ch, seq=1000, ack=2000, ts=_ts(base, 0.010)))

    # ServerHello — TLS 1.3, TLS_AES_256_GCM_SHA384
    sh = _server_hello(version=0x0304, cipher_suite=0x1302)
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, sh, seq=2000, ack=1000+len(ch), ts=_ts(base, 0.020)))

    # Server Certificate
    cert_msg = _minimal_cert("imap.example.com")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, cert_msg, seq=2000+len(sh), ack=1000+len(ch), ts=_ts(base, 0.021)))

    # ChangeCipherSpec + AppData (encrypted IMAP greeting)
    ccs = _change_cipher_spec()
    app = _app_data(b"* OK IMAP4rev1 Service Ready")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ccs + app, seq=2000+len(sh)+len(cert_msg), ack=1000+len(ch), ts=_ts(base, 0.030)))

    # Client: encrypted IMAP commands
    client_app = _app_data(b"a001 LOGIN user@example.com secret")
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, client_app, seq=1000+len(ch), ack=2000+len(sh)+len(cert_msg)+len(ccs+app), ts=_ts(base, 0.040)))

    out = output_dir / "clean_implicit_tls.pcap"
    wrpcap(str(out), pkts)
    return out


# ---------------------------------------------------------------------------
# Scenario 2: Weak Cipher STARTTLS (SMTP port 587, TLS 1.0, 3DES, SHA1 cert)
# ---------------------------------------------------------------------------

def _gen_weak_cipher_starttls(output_dir: Path) -> Path:
    base = time.time()
    pkts = []
    client_ip = "192.168.1.101"
    server_ip = "10.0.0.2"
    sport, dport = 55001, 587

    # TCP 3-way
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "S",  seq=999, ack=0, ts=_ts(base, 0)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"", "SA", seq=1999, ack=1000, ts=_ts(base, 0.001)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "A",  seq=1000, ack=2000, ts=_ts(base, 0.002)))

    # SMTP greeting
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"220 mail.example.com ESMTP\r\n", seq=2000, ack=1000, ts=_ts(base, 0.010)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"EHLO client.example.com\r\n", seq=1000, ack=2029, ts=_ts(base, 0.020)))

    # EHLO response with STARTTLS
    ehlo_resp = (
        b"250-mail.example.com Hello\r\n"
        b"250-STARTTLS\r\n"
        b"250-AUTH PLAIN LOGIN\r\n"
        b"250 8BITMIME\r\n"
    )
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ehlo_resp, seq=2029, ack=1025, ts=_ts(base, 0.030)))

    # Client requests STARTTLS
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"STARTTLS\r\n", seq=1025, ack=2029+len(ehlo_resp), ts=_ts(base, 0.040)))

    # Server acknowledges
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"220 Ready to start TLS\r\n", seq=2029+len(ehlo_resp), ack=1035, ts=_ts(base, 0.050)))

    # TLS Handshake — TLS 1.0, 3DES cipher (0x000A)
    ch = _client_hello(version=0x0301, cipher_suites=[0x000A, 0x000A], sni="mail.example.com")
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, ch, seq=1035, ack=2029+len(ehlo_resp)+24, ts=_ts(base, 0.060)))

    sh = _server_hello(version=0x0301, cipher_suite=0x000A)
    cert_msg = _minimal_cert("mail.example.com")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, sh + cert_msg, seq=2029+len(ehlo_resp)+24, ack=1035+len(ch), ts=_ts(base, 0.070)))

    ccs = _change_cipher_spec()
    app = _app_data(b"220 mail.example.com ESMTP (TLS)")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ccs + app, seq=2029+len(ehlo_resp)+24+len(sh)+len(cert_msg), ack=1035+len(ch), ts=_ts(base, 0.080)))

    out = output_dir / "weak_cipher_starttls.pcap"
    wrpcap(str(out), pkts)
    return out


# ---------------------------------------------------------------------------
# Scenario 3: Stripped STARTTLS / Plaintext Fallback (SMTP port 25, MITM)
# ---------------------------------------------------------------------------

def _gen_stripped_starttls(output_dir: Path) -> Path:
    base = time.time()
    pkts = []
    client_ip = "192.168.1.102"
    server_ip = "10.0.0.3"
    sport, dport = 55002, 25

    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "S",  seq=999, ack=0, ts=_ts(base, 0)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"", "SA", seq=1999, ack=1000, ts=_ts(base, 0.001)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "A",  seq=1000, ack=2000, ts=_ts(base, 0.002)))

    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"220 mail.victim.com ESMTP\r\n", seq=2000, ack=1000, ts=_ts(base, 0.010)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"EHLO attacker-mitm.com\r\n", seq=1000, ack=2028, ts=_ts(base, 0.020)))

    # MITM-modified EHLO response — STARTTLS capability STRIPPED
    ehlo_resp_stripped = (
        b"250-mail.victim.com Hello\r\n"
        b"250-AUTH PLAIN\r\n"
        b"250 8BITMIME\r\n"
        # NOTE: 250-STARTTLS intentionally missing — simulating MITM strip
    )
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ehlo_resp_stripped, seq=2028, ack=1024, ts=_ts(base, 0.030)))

    # Client sends AUTH in plaintext because it doesn't see STARTTLS
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n", seq=1024, ack=2028+len(ehlo_resp_stripped), ts=_ts(base, 0.040)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"235 Authentication successful\r\n", seq=2028+len(ehlo_resp_stripped), ack=1061, ts=_ts(base, 0.050)))

    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"MAIL FROM:<admin@victim.com>\r\n", seq=1061, ack=2028+len(ehlo_resp_stripped)+31, ts=_ts(base, 0.060)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"250 OK\r\n", seq=2028+len(ehlo_resp_stripped)+31, ack=1092, ts=_ts(base, 0.070)))

    out = output_dir / "stripped_starttls_plaintext.pcap"
    wrpcap(str(out), pkts)
    return out


# ---------------------------------------------------------------------------
# Scenario 4: Expired Certificate (IMAPS port 993, TLS 1.2)
# ---------------------------------------------------------------------------

def _gen_expired_cert(output_dir: Path) -> Path:
    base = time.time()
    pkts = []
    client_ip = "192.168.1.103"
    server_ip = "10.0.0.4"
    sport, dport = 55003, 993

    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "S",  seq=999, ack=0, ts=_ts(base, 0)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"", "SA", seq=1999, ack=1000, ts=_ts(base, 0.001)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "A",  seq=1000, ack=2000, ts=_ts(base, 0.002)))

    # ClientHello — TLS 1.2, ECDHE-RSA-AES128-GCM
    ch = _client_hello(version=0x0303, cipher_suites=[0xC02F, 0xC030], sni="imap.victim.com")
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, ch, seq=1000, ack=2000, ts=_ts(base, 0.010)))

    sh = _server_hello(version=0x0303, cipher_suite=0xC02F)
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, sh, seq=2000, ack=1000+len(ch), ts=_ts(base, 0.020)))

    # Expired certificate!
    cert_msg = _minimal_cert("imap.victim.com", expired=True)
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, cert_msg, seq=2000+len(sh), ack=1000+len(ch), ts=_ts(base, 0.021)))

    ccs = _change_cipher_spec()
    app = _app_data(b"* OK IMAP4rev1")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ccs + app, seq=2000+len(sh)+len(cert_msg), ack=1000+len(ch), ts=_ts(base, 0.030)))

    out = output_dir / "expired_cert_implicit_tls.pcap"
    wrpcap(str(out), pkts)
    return out


# ---------------------------------------------------------------------------
# Scenario 5: Buffer Injection Attack (SMTP STARTTLS + pipelined commands)
# ---------------------------------------------------------------------------

def _gen_buffer_injection(output_dir: Path) -> Path:
    """
    Simulates the Poddebniak et al. (USENIX Security 2021) buffer injection:
    Cleartext SMTP commands are appended to the STARTTLS command in the same
    TCP segment, exploiting improper buffer flushing before TLS handshake.
    """
    base = time.time()
    pkts = []
    client_ip = "192.168.1.104"
    server_ip = "10.0.0.5"
    sport, dport = 55004, 25

    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "S",  seq=999, ack=0, ts=_ts(base, 0)))
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"", "SA", seq=1999, ack=1000, ts=_ts(base, 0.001)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"", "A",  seq=1000, ack=2000, ts=_ts(base, 0.002)))

    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"220 mail.example.com ESMTP\r\n", seq=2000, ack=1000, ts=_ts(base, 0.010)))
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, b"EHLO attacker.example.com\r\n", seq=1000, ack=2029, ts=_ts(base, 0.020)))

    ehlo_resp = (
        b"250-mail.example.com\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH PLAIN\r\n"
    )
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ehlo_resp, seq=2029, ack=1028, ts=_ts(base, 0.030)))

    # BUFFER INJECTION: STARTTLS command WITH injected commands in same TCP segment
    injected_payload = (
        b"STARTTLS\r\n"                              # Legitimate upgrade request
        b"MAIL FROM:<injected@attacker.com>\r\n"     # Injected plaintext command 1
        b"RCPT TO:<victim@example.com>\r\n"          # Injected plaintext command 2
        b"DATA\r\n"                                   # Injected plaintext command 3
    )
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, injected_payload, seq=1028, ack=2029+len(ehlo_resp), ts=_ts(base, 0.040)))

    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, b"220 Ready to start TLS\r\n", seq=2029+len(ehlo_resp), ack=1028+len(injected_payload), ts=_ts(base, 0.050)))

    # TLS handshake follows normally
    ch = _client_hello(version=0x0303, cipher_suites=[0xC02F], sni="mail.example.com")
    pkts.append(_tcp_pkt(client_ip, server_ip, sport, dport, ch, seq=1028+len(injected_payload), ack=2029+len(ehlo_resp)+24, ts=_ts(base, 0.060)))

    sh = _server_hello(version=0x0303, cipher_suite=0xC02F)
    cert_msg = _minimal_cert("mail.example.com")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, sh + cert_msg, seq=2029+len(ehlo_resp)+24, ack=1028+len(injected_payload)+len(ch), ts=_ts(base, 0.070)))

    ccs = _change_cipher_spec()
    app = _app_data(b"220 OK TLS")
    pkts.append(_tcp_pkt(server_ip, client_ip, dport, sport, ccs + app, seq=2029+len(ehlo_resp)+24+len(sh)+len(cert_msg), ack=1028+len(injected_payload)+len(ch), ts=_ts(base, 0.080)))

    out = output_dir / "buffer_injection_attack.pcap"
    wrpcap(str(out), pkts)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

SCENARIO_GENERATORS = {
    "clean_implicit_tls":        _gen_clean_implicit_tls,
    "weak_cipher_starttls":      _gen_weak_cipher_starttls,
    "stripped_starttls_plaintext": _gen_stripped_starttls,
    "expired_cert_implicit_tls": _gen_expired_cert,
    "buffer_injection_attack":   _gen_buffer_injection,
}


def generate_all(output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> dict[str, Path]:
    """
    Generate all 5 synthetic forensic test PCAPs.

    Returns:
        dict mapping scenario name → output Path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, gen_fn in SCENARIO_GENERATORS.items():
        print(f"  Generating {name}.pcap ...", end=" ", flush=True)
        try:
            path = gen_fn(output_dir)
            results[name] = path
            print(f"✓ ({path.stat().st_size:,} bytes)")
        except Exception as e:
            print(f"✗ ERROR: {e}")
            results[name] = None

    return results


_SAMPLE_DESCRIPTIONS = {
    "clean_implicit_tls":          "✅ IMAPS TLS 1.3, ECDHE, AES-256-GCM (Good session — expected LOW risk)",
    "weak_cipher_starttls":        "⚠️ SMTP STARTTLS, TLS 1.0, 3DES cipher (Deprecated — expected HIGH risk)",
    "stripped_starttls_plaintext": "🚨 SMTP STARTTLS stripped by MITM, cleartext AUTH (expected CRITICAL)",
    "expired_cert_implicit_tls":   "⚠️ IMAPS TLS 1.2, expired X.509 certificate (expected MEDIUM–HIGH)",
    "buffer_injection_attack":     "💀 SMTP STARTTLS + Poddebniak buffer injection attack (expected CRITICAL)",
}


if __name__ == "__main__":
    print("Generating synthetic forensic test PCAPs...")
    paths = generate_all()
    print(f"\n✅ Done! {sum(1 for v in paths.values() if v)} / {len(paths)} PCAPs generated.")
    for name, path in paths.items():
        if path:
            print(f"  {name}: {path}")
