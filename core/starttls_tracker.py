"""
core/starttls_tracker.py
STARTTLS finite state machine and buffer injection detector.
Implements Pipeline Stage 3 from the project synopsis.

Order-aware, chronological state machine tracking the plaintext-to-ciphertext
upgrade sequence for SMTP STARTTLS (RFC 3207), IMAP STARTTLS (RFC 3501), and
POP3 STLS (RFC 2595). Detects:
  - Normal negotiation flow
  - Failed/rejected upgrades
  - Proven stripping vs possible stripping (MITM: capability removed / plaintext fallback)
  - Buffer injection attacks across segment boundaries and pipelining (Poddebniak et al., USENIX Security '21)
  - Inconclusive/ambiguous captures (mid-stream, truncated, or incomplete captures)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .models import Protocol, StarttlsStatus, ChannelType
from .reassembly import TCPStream, TCPSegment


# ---------------------------------------------------------------------------
# TLS Record Boundary & Structural Validation
# ---------------------------------------------------------------------------

_VALID_TLS_RECORD_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}

_VALID_TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2/1.3",
    0x0304: "TLS 1.3 Draft",
}

_VALID_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}


def find_tls_record_transition(data: bytes, min_offset: int = 0) -> Optional[Tuple[int, int, int]]:
    """
    Search for the first structurally valid TLS record header starting at min_offset.
    Validates content type, TLS version, length sanity (<= 18432), and handshake
    type when content_type is Handshake (0x16).

    Returns:
        (offset, content_type, version) or None if no valid TLS record layer is found.
    """
    length = len(data)
    if length < 5 or min_offset >= length:
        return None

    for i in range(min_offset, length - 4):
        ctype = data[i]
        if ctype not in _VALID_TLS_RECORD_TYPES:
            continue

        ver = struct.unpack(">H", data[i+1:i+3])[0]
        if ver not in _VALID_TLS_VERSIONS:
            continue

        rec_len = struct.unpack(">H", data[i+3:i+5])[0]
        # Max TLS fragment size is 16384 bytes; with compression/MAC/padding headroom <= 18432
        if rec_len == 0 or rec_len > 18432:
            continue

        # If Handshake, validate first handshake header if available in buffer
        if ctype == 0x16:
            if i + 5 < length:
                hs_type = data[i+5]
                if hs_type not in _VALID_HANDSHAKE_TYPES:
                    continue
                if i + 9 <= length:
                    hs_len = int.from_bytes(data[i+6:i+9], "big")
                    if hs_len > rec_len:
                        continue

        return (i, ctype, ver)

    return None


# ---------------------------------------------------------------------------
# Protocol Patterns & Parsers
# ---------------------------------------------------------------------------

_SMTP_COMMANDS_PATTERN = re.compile(
    rb"^(EHLO|HELO|STARTTLS|AUTH|MAIL FROM|RCPT TO|DATA|QUIT|RSET|NOOP|VRFY)\b",
    re.IGNORECASE | re.MULTILINE,
)

_SMTP_INJECTABLE_COMMANDS = re.compile(
    rb"\b(EHLO|HELO|MAIL FROM|RCPT TO|DATA|AUTH|QUIT|RSET)\b",
    re.IGNORECASE,
)

_IMAP_INJECTABLE_COMMANDS = re.compile(
    rb"\b(LOGIN|AUTHENTICATE|SELECT|EXAMINE|FETCH|STORE|SEARCH)\b",
    re.IGNORECASE,
)

_POP3_INJECTABLE_COMMANDS = re.compile(
    rb"\b(USER|PASS|APOP|LIST|RETR|DELE)\b",
    re.IGNORECASE,
)


def parse_smtp_replies(raw: bytes) -> List[Tuple[int, List[str], bytes]]:
    """
    Parse raw server bytes into discrete SMTP replies.
    Returns list of (status_code, text_lines, raw_bytes).
    Handles both single-line and multi-line (hyphenated) replies.
    """
    replies = []
    lines = [line.strip(b"\r") for line in raw.split(b"\n") if line.strip(b"\r")]
    cur_code = None
    cur_lines = []
    cur_raw = []

    for line in lines:
        if len(line) >= 3 and line[:3].isdigit():
            code = int(line[:3])
            sep = line[3:4]
            text = line[4:].decode("latin1", errors="replace").strip()
            if cur_code is None:
                cur_code = code
            cur_lines.append(text)
            cur_raw.append(line)
            # If separator is space or end of line (not hyphen), reply is complete
            if sep != b"-":
                replies.append((cur_code, cur_lines, b"\r\n".join(cur_raw)))
                cur_code = None
                cur_lines = []
                cur_raw = []
        else:
            if cur_code is not None:
                cur_lines.append(line.decode("latin1", errors="replace").strip())
                cur_raw.append(line)

    if cur_code is not None and cur_lines:
        replies.append((cur_code, cur_lines, b"\r\n".join(cur_raw)))

    return replies


def parse_imap_replies(raw: bytes) -> List[Tuple[str, str, str, bytes]]:
    """
    Parse IMAP server responses.
    Returns list of (tag, status, text, raw_line).
    tag: '*' for untagged, or specific client tag like 'a001'.
    status: 'OK', 'NO', 'BAD', 'BYE', 'CAPABILITY', etc.
    """
    replies = []
    lines = [line.strip(b"\r") for line in raw.split(b"\n") if line.strip(b"\r")]
    for line in lines:
        parts = line.split(None, 2)
        if len(parts) >= 2:
            tag = parts[0].decode("latin1", errors="replace")
            status = parts[1].decode("latin1", errors="replace").upper()
            text = parts[2].decode("latin1", errors="replace") if len(parts) > 2 else ""
            replies.append((tag, status, text, line))
        elif len(parts) == 1:
            tag = parts[0].decode("latin1", errors="replace")
            replies.append((tag, "", "", line))
    return replies


def parse_pop3_replies(raw: bytes) -> List[Tuple[str, List[str], bytes]]:
    """
    Parse POP3 server responses.
    Returns list of (status, text_lines, raw_bytes).
    status: '+OK' or '-ERR'
    """
    replies = []
    lines = [line.strip(b"\r") for line in raw.split(b"\n") if line.strip(b"\r")]
    cur_status = None
    cur_lines = []
    cur_raw = []

    for line in lines:
        line_str = line.decode("latin1", errors="replace").strip()
        if line_str.startswith("+OK") or line_str.startswith("-ERR"):
            if cur_status is not None:
                replies.append((cur_status, cur_lines, b"\r\n".join(cur_raw)))
            cur_status = "+OK" if line_str.startswith("+OK") else "-ERR"
            cur_lines = [line_str[len(cur_status):].strip()]
            cur_raw = [line]
        elif line_str == ".":
            # End of multi-line response (e.g. CAPA)
            if cur_status is not None:
                cur_raw.append(line)
                replies.append((cur_status, cur_lines, b"\r\n".join(cur_raw)))
                cur_status = None
                cur_lines = []
                cur_raw = []
        else:
            if cur_status is not None:
                cur_lines.append(line_str)
                cur_raw.append(line)

    if cur_status is not None:
        replies.append((cur_status, cur_lines, b"\r\n".join(cur_raw)))

    return replies


def parse_client_lines(raw: bytes) -> List[Tuple[str, str, bytes]]:
    """
    Parse client cleartext stream into lines.
    Returns list of (command_verb, argument_str, raw_line).
    Handles SMTP, IMAP (strips tag), and POP3.
    """
    results = []
    lines = [line.strip(b"\r") for line in raw.split(b"\n") if line.strip(b"\r")]
    for line in lines:
        parts = line.split(None, 1)
        if not parts:
            continue
        verb = parts[0].decode("latin1", errors="replace").upper()
        arg = parts[1].decode("latin1", errors="replace") if len(parts) > 1 else ""
        results.append((verb, arg, line))
    return results


def detect_plaintext_credentials(commands: List[Tuple[str, str, bytes]], raw_bytes: bytes) -> bool:
    """
    Detect if the client submitted sensitive credentials in cleartext:
    - SMTP: AUTH PLAIN, AUTH LOGIN, AUTH CRAM-MD5
    - IMAP: LOGIN user pass, AUTHENTICATE PLAIN
    - POP3: USER / PASS, APOP
    """
    for verb, arg, raw in commands:
        if verb == "AUTH" or "AUTH PLAIN" in verb or "AUTH LOGIN" in verb:
            return True
        if verb in ("USER", "PASS", "APOP"):
            return True
        parts = raw.split()
        if len(parts) >= 2 and parts[1].decode("latin1", errors="replace").upper() in ("LOGIN", "AUTHENTICATE"):
            return True

    if re.search(rb"\bAUTH\s+(PLAIN|LOGIN)\b", raw_bytes, re.IGNORECASE):
        return True
    if re.search(rb"\b(USER|PASS)\s+[^\r\n]+", raw_bytes, re.IGNORECASE):
        return True

    return False


# ---------------------------------------------------------------------------
# Result Structure
# ---------------------------------------------------------------------------

@dataclass
class StarttlsAnalysis:
    """Result of STARTTLS state-machine analysis for a single stream."""
    starttls_status:    StarttlsStatus = StarttlsStatus.NONE
    channel_type:       ChannelType    = ChannelType.UNKNOWN
    buffer_injection:   bool           = False
    injected_commands:  List[str]      = None
    bytes_before_tls:   int            = 0   # Plaintext bytes before TLS record layer
    details:            str            = ""  # Forensic reasoning / event summary
    events:             List[str]      = None

    def __post_init__(self):
        if self.injected_commands is None:
            self.injected_commands = []
        if self.events is None:
            self.events = []


# ---------------------------------------------------------------------------
# Order-Aware STARTTLS Tracker
# ---------------------------------------------------------------------------

class StarttlsTracker:
    """
    Runs an order-aware, chronological finite-state machine over a reconstructed TCPStream.

    Negotiation Stages (per RFC 3207 / RFC 3501 / RFC 2595):
      1. Server Greeting Banner
      2. Capability Query & Advertisement (EHLO / CAPABILITY / CAPA)
      3. Client Upgrade Request (STARTTLS / STLS)
      4. Server Acknowledgment or Rejection
      5. TLS Transition (ClientHello record)

    Accurately classifies:
      - NEGOTIATED: Complete valid sequence leading to TLS record layer
      - ADVERTISED: Offered by server, but client never upgraded
      - FAILED: Explicitly rejected by server, or aborted after ACK
      - STRIPPED: Proven on-path downgrade (capability suppressed + cleartext credential fallback)
      - POSSIBLE_STRIPPING: Suspected stripping on untrusted cleartext channel
      - NONE: Unencrypted cleartext or standard non-STARTTLS session
      - INCONCLUSIVE: Incomplete/truncated capture or missing handshake segments
    """

    def analyze(self, stream: TCPStream) -> StarttlsAnalysis:
        result = StarttlsAnalysis()

        client_data = bytes(stream.client_data)
        server_data = bytes(stream.server_data)

        # ---- Case 1: Implicit TLS Port Policy (RFC 8314) ----
        if stream.is_implicit_tls:
            result.channel_type = ChannelType.IMPLICIT_TLS
            result.starttls_status = StarttlsStatus.NONE
            result.bytes_before_tls = 0
            result.details = "Implicit TLS configured by port policy (RFC 8314)."
            return result

        # ---- Case 2: Empty Stream ----
        if not client_data and not server_data:
            result.starttls_status = StarttlsStatus.INCONCLUSIVE
            result.channel_type = ChannelType.UNKNOWN
            result.details = "Empty stream; no application layer data captured."
            return result

        # ---- Case 3: Immediate TLS Transition at byte 0 ----
        c_tls_zero = find_tls_record_transition(client_data, 0)
        if c_tls_zero and c_tls_zero[0] == 0:
            result.channel_type = ChannelType.IMPLICIT_TLS
            result.starttls_status = StarttlsStatus.NONE
            result.bytes_before_tls = 0
            result.details = "Session starts directly with TLS ClientHello at byte 0 (Implicit TLS)."
            return result

        # ---- Case 4: Detect First Valid TLS Record Transition ----
        c_tls = find_tls_record_transition(client_data, 0)
        s_tls = find_tls_record_transition(server_data, 0)

        c_plain_limit = c_tls[0] if c_tls else len(client_data)
        s_plain_limit = s_tls[0] if s_tls else len(server_data)
        result.bytes_before_tls = s_plain_limit

        c_plain = client_data[:c_plain_limit]
        s_plain = server_data[:s_plain_limit]

        # Dispatch protocol-specific chronological analysis
        proto = stream.protocol
        if proto == Protocol.SMTP:
            self._analyze_smtp(stream, c_plain, s_plain, c_tls, s_tls, result)
        elif proto == Protocol.IMAP:
            self._analyze_imap(stream, c_plain, s_plain, c_tls, s_tls, result)
        elif proto == Protocol.POP3:
            self._analyze_pop3(stream, c_plain, s_plain, c_tls, s_tls, result)
        else:
            self._analyze_generic(stream, c_plain, s_plain, c_tls, s_tls, result)

        return result

    # ------------------------------------------------------------------ SMTP

    def _analyze_smtp(
        self, stream: TCPStream, c_plain: bytes, s_plain: bytes,
        c_tls: Optional[Tuple[int, int, int]], s_tls: Optional[Tuple[int, int, int]],
        result: StarttlsAnalysis,
    ):
        client_cmds = parse_client_lines(c_plain)
        server_replies = parse_smtp_replies(s_plain)

        has_tls = bool(c_tls and s_tls)

        # 1. Identify Greeting (first reply, code 220)
        has_greeting = False
        greeting_idx = -1
        if server_replies and server_replies[0][0] == 220:
            has_greeting = True
            greeting_idx = 0
            result.events.append("Server greeting 220 observed")

        # 2. Identify Capability Advertisement in reply to EHLO
        # In SMTP, EHLO responses are 250 with lines containing STARTTLS
        advertised = False
        advert_reply_idx = -1
        for idx, (code, lines, raw) in enumerate(server_replies):
            if idx == greeting_idx:
                continue
            if code == 250:
                for line in lines:
                    if re.search(r"\bSTARTTLS\b", line, re.IGNORECASE):
                        advertised = True
                        advert_reply_idx = idx
                        result.events.append("Server advertised 250-STARTTLS capability")
                        break
                if advertised:
                    break

        # 3. Identify Client STARTTLS Command
        requested = False
        starttls_cmd_idx = -1
        for idx, (verb, arg, raw) in enumerate(client_cmds):
            if verb == "STARTTLS":
                requested = True
                starttls_cmd_idx = idx
                result.events.append("Client issued STARTTLS command")
                break

        # 4. Check Order: Did STARTTLS command occur chronologically AFTER advertisement?
        # If client requested without advertisement or before advertisement:
        unadvertised_request = requested and not advertised

        # 5. Check Server Response to STARTTLS command
        # In SMTP, the reply to STARTTLS is code 220 (Positive ACK) or 454/5xx (Rejection)
        # It must occur AFTER the EHLO reply (and after greeting)
        acked = False
        rejected = False
        reject_code = None

        if requested:
            # Look at server replies after advert_reply_idx (or after greeting)
            start_search = max(greeting_idx, advert_reply_idx) + 1
            for idx in range(start_search, len(server_replies)):
                code, lines, raw = server_replies[idx]
                if code == 220:
                    acked = True
                    result.events.append("Server acknowledged STARTTLS with 220 Ready to start TLS")
                    break
                elif code in (454, 501, 502, 554) or (code >= 400 and code <= 599):
                    rejected = True
                    reject_code = code
                    result.events.append(f"Server rejected STARTTLS with code {code}")
                    break

        # Fallback regex if replies could not be neatly grouped
        if requested and not acked and not rejected:
            if re.search(rb"\b220\s+[^\r\n]*TLS", s_plain, re.IGNORECASE):
                acked = True
                result.events.append("Server acknowledged STARTTLS (heuristic)")
            elif re.search(rb"\b(454|501|502|554)\b", s_plain):
                rejected = True
                result.events.append("Server rejected STARTTLS (heuristic)")

        # 6. Evaluate State
        if requested and acked and has_tls:
            result.starttls_status = StarttlsStatus.NEGOTIATED
            result.channel_type = ChannelType.STARTTLS
            result.details = "Successful STARTTLS negotiation followed by valid TLS handshake."
            # Buffer injection check
            injection, commands = self._check_buffer_injection(stream)
            result.buffer_injection = injection
            result.injected_commands = commands
            if injection:
                result.events.append(f"Buffer injection detected: {commands}")

        elif requested and rejected:
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type = ChannelType.PLAINTEXT
            result.details = f"STARTTLS requested by client was rejected by server (code {reject_code or 'error'})."

        elif requested and acked and not has_tls:
            if len(c_plain) > 0 and len(client_cmds) > starttls_cmd_idx + 1:
                # Cleartext continued after ACK instead of TLS
                result.starttls_status = StarttlsStatus.FAILED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "STARTTLS acknowledged by server, but client resumed in cleartext instead of TLS."
            else:
                result.starttls_status = StarttlsStatus.INCONCLUSIVE
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "STARTTLS acknowledged by server, but capture ended before TLS handshake."

        elif requested and not acked and not rejected:
            result.starttls_status = StarttlsStatus.INCONCLUSIVE
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "Client issued STARTTLS, but capture truncated before server response."

        elif not requested:
            if advertised:
                result.starttls_status = StarttlsStatus.ADVERTISED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Server advertised 250-STARTTLS, but client never initiated upgrade (opportunistic plaintext)."
            else:
                # Neither advertised nor requested
                # Check if client queried capabilities (EHLO)
                ehlo_seen = any(v in ("EHLO", "HELO") for v, _, _ in client_cmds) or bool(re.search(rb"\b(EHLO|HELO)\b", c_plain, re.IGNORECASE))
                credentials_sent = detect_plaintext_credentials(client_cmds, c_plain)

                if ehlo_seen and server_replies and any(code == 250 for code, _, _ in server_replies):
                    # Server replied to EHLO with 250, but STARTTLS was missing!
                    if credentials_sent:
                        result.starttls_status = StarttlsStatus.STRIPPED
                        result.channel_type = ChannelType.PLAINTEXT
                        result.details = "Proven STARTTLS stripping: server capability lacked STARTTLS following EHLO, and client submitted plaintext credentials."
                    elif stream.dst_port in (587, 25):
                        result.starttls_status = StarttlsStatus.STRIPPED if credentials_sent else StarttlsStatus.POSSIBLE_STRIPPING
                        result.channel_type = ChannelType.PLAINTEXT
                        result.details = "Possible STARTTLS stripping: capability omitted on submission port 587/25."
                    else:
                        result.starttls_status = StarttlsStatus.NONE
                        result.channel_type = ChannelType.PLAINTEXT
                        result.details = "Plaintext SMTP session without STARTTLS advertisement."
                elif has_greeting:
                    result.starttls_status = StarttlsStatus.NONE
                    result.channel_type = ChannelType.PLAINTEXT
                    result.details = "Standard cleartext SMTP session; no capability negotiation observed."
                else:
                    result.starttls_status = StarttlsStatus.INCONCLUSIVE
                    result.channel_type = ChannelType.UNKNOWN
                    result.details = "Mid-stream capture; initial SMTP greeting and EHLO negotiation missing."

    # ------------------------------------------------------------------ IMAP

    def _analyze_imap(
        self, stream: TCPStream, c_plain: bytes, s_plain: bytes,
        c_tls: Optional[Tuple[int, int, int]], s_tls: Optional[Tuple[int, int, int]],
        result: StarttlsAnalysis,
    ):
        client_cmds = parse_client_lines(c_plain)
        server_replies = parse_imap_replies(s_plain)
        has_tls = bool(c_tls and s_tls)

        advertised = False
        for tag, status, text, raw in server_replies:
            if re.search(rb"\bSTARTTLS\b", raw, re.IGNORECASE):
                advertised = True
                result.events.append("Server advertised IMAP STARTTLS capability")
                break

        requested = False
        starttls_tag = None
        for verb, arg, raw in client_cmds:
            if "STARTTLS" in raw.decode("latin1", errors="replace").upper():
                requested = True
                parts = raw.split()
                starttls_tag = parts[0].decode("latin1", errors="replace") if len(parts) >= 2 else None
                result.events.append("Client issued IMAP STARTTLS command")
                break

        acked = False
        rejected = False
        for tag, status, text, raw in server_replies:
            if requested:
                if (starttls_tag and tag == starttls_tag and status == "OK") or (status == "OK" and "TLS" in text.upper()):
                    acked = True
                    result.events.append("Server acknowledged IMAP STARTTLS with OK")
                    break
                elif (starttls_tag and tag == starttls_tag and status in ("NO", "BAD")):
                    rejected = True
                    result.events.append(f"Server rejected IMAP STARTTLS with {status}")
                    break

        if requested and acked and has_tls:
            result.starttls_status = StarttlsStatus.NEGOTIATED
            result.channel_type = ChannelType.STARTTLS
            result.details = "IMAP STARTTLS negotiated successfully."
            injection, commands = self._check_buffer_injection(stream)
            result.buffer_injection = injection
            result.injected_commands = commands
        elif requested and rejected:
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "Server rejected IMAP STARTTLS upgrade."
        elif requested and acked and not has_tls:
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "IMAP STARTTLS acknowledged, but TLS handshake failed to materialize."
        elif requested and not acked and not rejected:
            result.starttls_status = StarttlsStatus.INCONCLUSIVE
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "IMAP STARTTLS requested, but capture ended before server response."
        elif not requested:
            credentials_sent = detect_plaintext_credentials(client_cmds, c_plain)
            if advertised:
                result.starttls_status = StarttlsStatus.ADVERTISED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Server advertised IMAP STARTTLS capability, but client never upgraded."
            elif credentials_sent:
                result.starttls_status = StarttlsStatus.STRIPPED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Proven STARTTLS stripping: IMAP credentials transmitted in plaintext without TLS."
            else:
                result.starttls_status = StarttlsStatus.NONE
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Plaintext IMAP session without STARTTLS."

    # ------------------------------------------------------------------ POP3

    def _analyze_pop3(
        self, stream: TCPStream, c_plain: bytes, s_plain: bytes,
        c_tls: Optional[Tuple[int, int, int]], s_tls: Optional[Tuple[int, int, int]],
        result: StarttlsAnalysis,
    ):
        client_cmds = parse_client_lines(c_plain)
        server_replies = parse_pop3_replies(s_plain)
        has_tls = bool(c_tls and s_tls)

        advertised = False
        for status, lines, raw in server_replies:
            for line in lines:
                if re.search(r"\bSTLS\b", line, re.IGNORECASE):
                    advertised = True
                    result.events.append("Server advertised POP3 STLS capability")
                    break

        requested = False
        for verb, arg, raw in client_cmds:
            if verb == "STLS" or b"STLS" in raw.upper():
                requested = True
                result.events.append("Client issued POP3 STLS command")
                break

        acked = False
        rejected = False
        if requested:
            # First reply after STLS command
            for status, lines, raw in server_replies:
                if status == "+OK" and any("TLS" in l.upper() or "BEGIN" in l.upper() for l in lines):
                    acked = True
                    result.events.append("Server acknowledged POP3 STLS with +OK")
                    break
                elif status == "-ERR":
                    rejected = True
                    result.events.append("Server rejected POP3 STLS with -ERR")
                    break

        # Fallback heuristic
        if requested and not acked and not rejected:
            if re.search(rb"^\+OK[^\r\n]*", s_plain, re.MULTILINE):
                acked = True
            elif re.search(rb"^-ERR", s_plain, re.MULTILINE):
                rejected = True

        if requested and acked and has_tls:
            result.starttls_status = StarttlsStatus.NEGOTIATED
            result.channel_type = ChannelType.STARTTLS
            result.details = "POP3 STLS negotiated successfully."
            injection, commands = self._check_buffer_injection(stream)
            result.buffer_injection = injection
            result.injected_commands = commands
        elif requested and rejected:
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "Server rejected POP3 STLS command."
        elif requested and acked and not has_tls:
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "POP3 STLS acknowledged, but TLS handshake failed to materialize."
        elif requested and not acked and not rejected:
            result.starttls_status = StarttlsStatus.INCONCLUSIVE
            result.channel_type = ChannelType.PLAINTEXT
            result.details = "POP3 STLS requested, but capture ended before server response."
        elif not requested:
            credentials_sent = detect_plaintext_credentials(client_cmds, c_plain)
            if advertised:
                result.starttls_status = StarttlsStatus.ADVERTISED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Server advertised POP3 STLS capability, but client never upgraded."
            elif credentials_sent:
                result.starttls_status = StarttlsStatus.STRIPPED
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Proven STARTTLS stripping: POP3 credentials submitted in plaintext without TLS."
            else:
                result.starttls_status = StarttlsStatus.NONE
                result.channel_type = ChannelType.PLAINTEXT
                result.details = "Plaintext POP3 session without STLS."

    # ------------------------------------------------------------------ Generic

    def _analyze_generic(
        self, stream: TCPStream, c_plain: bytes, s_plain: bytes,
        c_tls: Optional[Tuple[int, int, int]], s_tls: Optional[Tuple[int, int, int]],
        result: StarttlsAnalysis,
    ):
        has_tls = bool(c_tls and s_tls)
        if has_tls:
            result.channel_type = ChannelType.STARTTLS if (c_plain or s_plain) else ChannelType.IMPLICIT_TLS
            result.starttls_status = StarttlsStatus.NEGOTIATED if (c_plain or s_plain) else StarttlsStatus.NONE
            result.details = "Generic stream: TLS connection established."
        elif c_plain or s_plain:
            result.channel_type = ChannelType.PLAINTEXT
            result.starttls_status = StarttlsStatus.NONE
            result.details = "Generic stream: Plaintext session."
        else:
            result.channel_type = ChannelType.UNKNOWN
            result.starttls_status = StarttlsStatus.INCONCLUSIVE
            result.details = "Inconclusive stream: insufficient application layer data."

    # ------------------------------------------------------------------ Buffer Injection

    def _check_buffer_injection(
        self, stream: TCPStream
    ) -> Tuple[bool, List[str]]:
        """
        Detect Poddebniak et al. (USENIX Security 2021) buffer injection:
        Cleartext email application commands injected around the STARTTLS transition.

        Checks:
          1. Same segment: Cleartext commands pipelined in the same segment as STARTTLS
          2. Multi-segment: Subsequent client segments sent before the TLS record transition
          3. Pipelining: Commands sent before server ACK or alongside TLS record
        """
        injected = []
        found_starttls_seg = False
        starttls_seg_idx = -1

        for idx, seg in enumerate(stream.client_segments):
            data = seg.payload

            # Check if this segment contains STARTTLS or STLS command
            match = re.search(rb"\b(?:STARTTLS|STLS)\b\r?\n?", data, re.IGNORECASE)
            if match:
                found_starttls_seg = True
                starttls_seg_idx = idx
                trailing = data[match.end():]
                # Check for commands in trailing payload of same segment
                cmds = _SMTP_INJECTABLE_COMMANDS.findall(trailing) + \
                       _IMAP_INJECTABLE_COMMANDS.findall(trailing) + \
                       _POP3_INJECTABLE_COMMANDS.findall(trailing)
                if cmds:
                    injected.extend([c.decode("latin1", errors="replace").upper() for c in cmds])
                continue

            # If STARTTLS segment was already seen, inspect subsequent segments
            # that appear BEFORE the TLS record transition
            if found_starttls_seg and idx > starttls_seg_idx:
                # Check if this segment is already a TLS record (0x16 0x03 0x0...)
                if find_tls_record_transition(data, 0) is not None:
                    # TLS started; any preceding injection was already caught
                    break

                # Segment is still cleartext following STARTTLS command
                cmds = _SMTP_INJECTABLE_COMMANDS.findall(data) + \
                       _IMAP_INJECTABLE_COMMANDS.findall(data) + \
                       _POP3_INJECTABLE_COMMANDS.findall(data)
                if cmds:
                    injected.extend([c.decode("latin1", errors="replace").upper() for c in cmds])

        # Deduplicate while preserving order
        seen = set()
        unique_injected = []
        for cmd in injected:
            if cmd not in seen:
                seen.add(cmd)
                unique_injected.append(cmd)

        return bool(unique_injected), unique_injected


def analyze_starttls(stream: TCPStream) -> StarttlsAnalysis:
    """Convenience wrapper."""
    return StarttlsTracker().analyze(stream)

