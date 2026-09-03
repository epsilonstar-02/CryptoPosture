"""
core/starttls_tracker.py
STARTTLS finite state machine and buffer injection detector.
Implements Pipeline Stage 3 from the project synopsis.

Tracks the plaintext-to-ciphertext upgrade sequence for SMTP STARTTLS
(RFC 3207), IMAP STARTTLS (RFC 3501), and POP3 STLS (RFC 2595), detecting:
  - Normal negotiation flow
  - Failed/rejected upgrades
  - Stripped STARTTLS (MITM: server capability removed before forwarding)
  - Buffer injection attacks (Poddebniak et al., USENIX Security '21)
"""

from __future__ import annotations

import re
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .models import Protocol, StarttlsStatus, ChannelType
from .reassembly import TCPStream


# ---------------------------------------------------------------------------
# STARTTLS capability and command signatures (per protocol)
# ---------------------------------------------------------------------------

# Server capability advertisements (server→client)
_SMTP_STARTTLS_ADVERT  = re.compile(rb"250[- ]STARTTLS", re.IGNORECASE)
_IMAP_STARTTLS_ADVERT  = re.compile(rb"STARTTLS", re.IGNORECASE)
_POP3_STARTTLS_ADVERT  = re.compile(rb"\+OK.*STLS", re.IGNORECASE | re.DOTALL)

# Client upgrade requests (client→server)
_SMTP_STARTTLS_CMD     = re.compile(rb"^STARTTLS\r?\n", re.IGNORECASE | re.MULTILINE)
_IMAP_STARTTLS_CMD     = re.compile(rb"\d+ STARTTLS\r?\n", re.IGNORECASE)
_POP3_STLS_CMD         = re.compile(rb"^STLS\r?\n", re.IGNORECASE | re.MULTILINE)

# Server acknowledgments (server→client)
_SMTP_STARTTLS_ACK     = re.compile(rb"^220 ", re.MULTILINE)
_IMAP_STARTTLS_ACK     = re.compile(rb"\d+ OK Begin TLS", re.IGNORECASE)
_POP3_STLS_ACK         = re.compile(rb"^\+OK", re.MULTILINE)

# Server rejection of upgrade
_STARTTLS_REJECT       = re.compile(rb"^(4\d\d|5\d\d)", re.MULTILINE)

# TLS record magic byte: 0x16 (TLS Handshake), 0x15 (Alert), 0x14 (ChangeCipherSpec)
_TLS_RECORD_MAGIC      = re.compile(rb"[\x14\x15\x16]\x03[\x00-\x04]")

# Cleartext SMTP commands that MUST NOT appear after STARTTLS negotiation
_SMTP_COMMANDS_PATTERN = re.compile(
    rb"^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|AUTH|QUIT)\b",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class StarttlsAnalysis:
    """Result of STARTTLS state-machine analysis for a single stream."""
    starttls_status:    StarttlsStatus = StarttlsStatus.NONE
    channel_type:       ChannelType    = ChannelType.UNKNOWN
    buffer_injection:   bool           = False
    injected_commands:  List[str]      = None
    bytes_before_tls:   int            = 0   # Plaintext bytes before TLS record layer (research paper feature table)

    def __post_init__(self):
        if self.injected_commands is None:
            self.injected_commands = []



# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class StarttlsTracker:
    """
    Runs the STARTTLS finite-state machine over a reconstructed TCPStream.

    States (in order of negotiation):
      NONE → ADVERTISED → REQUESTED → NEGOTIATED (success)
                                    → FAILED      (server rejected)
      NONE → STRIPPED   (server never advertised despite expected capability)
    """

    def analyze(self, stream: TCPStream) -> StarttlsAnalysis:
        result = StarttlsAnalysis()

        client_data = bytes(stream.client_data)
        server_data = bytes(stream.server_data)

        # ---- Case 1: Implicit TLS port — no STARTTLS negotiation expected ----
        if stream.is_implicit_tls:
            result.channel_type  = ChannelType.IMPLICIT_TLS
            result.starttls_status = StarttlsStatus.NONE
            return result

        # ---- Case 2: Detect if TLS records appear at all ----
        has_tls_records_client = bool(_TLS_RECORD_MAGIC.search(client_data))
        has_tls_records_server = bool(_TLS_RECORD_MAGIC.search(server_data))
        any_tls = has_tls_records_client or has_tls_records_server

        # ---- Case 3: State machine by protocol ----
        proto = stream.protocol

        # Capability advertised by server?
        advert_found = self._check_advert(server_data, proto)

        # Upgrade command sent by client?
        cmd_found = self._check_command(client_data, proto)

        # Server acknowledged the upgrade?
        ack_found = self._check_ack(server_data, proto)

        # Server rejected the upgrade?
        reject_found = self._check_reject(server_data, proto)

        # ---- Build state ----
        if not advert_found and not cmd_found and not any_tls:
            # Pure plaintext session
            result.channel_type    = ChannelType.PLAINTEXT
            result.starttls_status = StarttlsStatus.NONE

        elif advert_found and not cmd_found:
            # Server offered STARTTLS but client never asked — opportunistic
            result.starttls_status = StarttlsStatus.ADVERTISED
            result.channel_type    = ChannelType.PLAINTEXT

        elif advert_found and cmd_found and not ack_found and reject_found:
            # Server rejected the upgrade request
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type    = ChannelType.PLAINTEXT

        elif advert_found and cmd_found and ack_found and any_tls:
            # Full successful STARTTLS negotiation
            result.starttls_status = StarttlsStatus.NEGOTIATED
            result.channel_type    = ChannelType.STARTTLS

            # ---- Poddebniak Buffer Injection Check ----
            injection, commands = self._check_buffer_injection(stream)
            result.buffer_injection = injection
            result.injected_commands = commands

        elif not advert_found and cmd_found:
            # Client asked but server never offered — possible STRIPPING by MITM
            result.starttls_status = StarttlsStatus.STRIPPED
            result.channel_type    = ChannelType.PLAINTEXT

        elif advert_found and cmd_found and not any_tls:
            # Negotiation started but TLS handshake never materialized
            result.starttls_status = StarttlsStatus.FAILED
            result.channel_type    = ChannelType.PLAINTEXT

        else:
            # Fallback heuristic
            if any_tls:
                result.channel_type    = ChannelType.STARTTLS
                result.starttls_status = StarttlsStatus.NEGOTIATED
            else:
                result.channel_type    = ChannelType.PLAINTEXT
                result.starttls_status = StarttlsStatus.NONE

        # ---- Compute bytes_before_tls ----
        # Counts server bytes that appear before the first TLS record (0x16 0x03 xx)
        tls_match = _TLS_RECORD_MAGIC.search(server_data)
        result.bytes_before_tls = tls_match.start() if tls_match else len(server_data)

        return result

    # ------------------------------------------------------------------ helpers

    def _check_advert(self, server_data: bytes, proto: Protocol) -> bool:
        if proto == Protocol.SMTP:
            return bool(_SMTP_STARTTLS_ADVERT.search(server_data))
        elif proto == Protocol.IMAP:
            return bool(_IMAP_STARTTLS_ADVERT.search(server_data))
        elif proto == Protocol.POP3:
            return bool(_POP3_STARTTLS_ADVERT.search(server_data))
        return False

    def _check_command(self, client_data: bytes, proto: Protocol) -> bool:
        if proto == Protocol.SMTP:
            return bool(_SMTP_STARTTLS_CMD.search(client_data))
        elif proto == Protocol.IMAP:
            return bool(_IMAP_STARTTLS_CMD.search(client_data))
        elif proto == Protocol.POP3:
            return bool(_POP3_STLS_CMD.search(client_data))
        return False

    def _check_ack(self, server_data: bytes, proto: Protocol) -> bool:
        if proto == Protocol.SMTP:
            # After STARTTLS: server sends "220 Ready to start TLS"
            return bool(re.search(rb"220 [^\r\n]*TLS", server_data, re.IGNORECASE))
        elif proto == Protocol.IMAP:
            return bool(_IMAP_STARTTLS_ACK.search(server_data))
        elif proto == Protocol.POP3:
            return bool(_POP3_STLS_ACK.search(server_data))
        return False

    def _check_reject(self, server_data: bytes, proto: Protocol) -> bool:
        return bool(_STARTTLS_REJECT.search(server_data))

    def _check_buffer_injection(
        self, stream: TCPStream
    ) -> Tuple[bool, List[str]]:
        """
        Detect Poddebniak et al. buffer injection:
        Cleartext SMTP application commands pipelined in the SAME TCP segment
        as the STARTTLS response or immediately before the TLS record start.

        We look for client-side segments that contain both a STARTTLS command
        AND additional SMTP application commands in the same payload.
        """
        injected = []
        for seg in stream.client_segments:
            data = seg.payload
            if not _SMTP_STARTTLS_CMD.search(data):
                continue
            # Found a STARTTLS command segment — check for additional commands
            # in the same buffer (after the STARTTLS\r\n)
            starttls_match = _SMTP_STARTTLS_CMD.search(data)
            after_starttls = data[starttls_match.end():]
            cmds = _SMTP_COMMANDS_PATTERN.findall(after_starttls)
            if cmds:
                injected.extend([c.decode(errors="replace") for c in cmds])

        return bool(injected), injected


def analyze_starttls(stream: TCPStream) -> StarttlsAnalysis:
    """Convenience wrapper."""
    return StarttlsTracker().analyze(stream)
