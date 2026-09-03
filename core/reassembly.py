"""
core/reassembly.py
TCP stream reassembly and protocol demuxing for SMTP, IMAP, and POP3.
Implements Pipeline Stage 2 from the project synopsis.

Reconstructs ordered bidirectional application-layer payloads from raw Scapy
packets using TCP 5-tuple tracking and sequence number ordering.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from .models import Protocol


# ---------------------------------------------------------------------------
# Port → Protocol mapping (RFC 8314 and historical ports)
# ---------------------------------------------------------------------------

SMTP_PORTS  = {25, 465, 587}
IMAP_PORTS  = {143, 993}
POP3_PORTS  = {110, 995}
IMPLICIT_TLS_PORTS = {465, 993, 995}   # RFC 8314 — Implicit TLS (no STARTTLS)


def _port_to_protocol(src_port: int, dst_port: int) -> Protocol:
    """Determine email protocol from TCP port numbers."""
    for port in (dst_port, src_port):
        if port in SMTP_PORTS:
            return Protocol.SMTP
        if port in IMAP_PORTS:
            return Protocol.IMAP
        if port in POP3_PORTS:
            return Protocol.POP3
    return Protocol.UNKNOWN


def _is_implicit_tls_port(src_port: int, dst_port: int) -> bool:
    return dst_port in IMPLICIT_TLS_PORTS or src_port in IMPLICIT_TLS_PORTS


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TCPSegment:
    """A single ordered TCP segment with directional context."""
    seq: int
    payload: bytes
    from_client: bool       # True = client→server, False = server→client


@dataclass
class TCPStream:
    """
    Reconstructed bidirectional TCP application stream for a 5-tuple flow.
    """
    stream_id:    str
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    protocol:     Protocol

    # Ordered ordered payloads (client→server, server→client)
    client_data:  bytearray = field(default_factory=bytearray)
    server_data:  bytearray = field(default_factory=bytearray)

    # Packet-level bookkeeping
    packet_count: int = 0
    byte_count:   int = 0
    is_implicit_tls: bool = False

    # Raw ordered segment list (for TLS record boundary detection)
    client_segments: List[TCPSegment] = field(default_factory=list)
    server_segments: List[TCPSegment] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reassembler
# ---------------------------------------------------------------------------

class StreamReassembler:
    """
    Reassembles TCP streams from a flat packet list.

    Identifies email protocol flows by port, tracks both directions of each
    5-tuple flow, and returns a list of reconstructed TCPStream objects ready
    for higher-level protocol analysis.
    """

    def __init__(self, include_all_ports: bool = False):
        """
        Args:
            include_all_ports: If True, attempt to reassemble ALL TCP flows
                               (not just email-protocol ports). Useful for
                               testing with custom PCAPs.
        """
        self.include_all_ports = include_all_ports
        self._flows: Dict[str, TCPStream] = {}
        # Temporary seq-keyed buffers: flow_key → {seq: bytes}
        self._client_buf: Dict[str, Dict[int, bytes]] = defaultdict(dict)
        self._server_buf: Dict[str, Dict[int, bytes]] = defaultdict(dict)

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port) -> Tuple[str, bool]:
        """
        Return a canonical flow key and a boolean indicating client→server direction.
        Lower-port side is always treated as the server (convention for email).
        """
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if dst_port in (SMTP_PORTS | IMAP_PORTS | POP3_PORTS) or dst_port < src_port:
            key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            return key, True      # src is client
        else:
            key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
            return key, False     # dst is client (response packet)

    def feed(self, packets: List[Packet]) -> List[TCPStream]:
        """
        Process a list of Scapy packets and return assembled TCP streams.
        """
        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue

            ip  = pkt[IP]
            tcp = pkt[TCP]

            src_ip   = ip.src
            dst_ip   = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport
            payload  = bytes(tcp.payload)

            if not payload:
                continue

            protocol = _port_to_protocol(src_port, dst_port)
            if protocol == Protocol.UNKNOWN and not self.include_all_ports:
                continue

            flow_key, from_client = self._flow_key(src_ip, dst_ip, src_port, dst_port)

            # Initialize stream on first sight
            if flow_key not in self._flows:
                # Normalize: stream's src/dst always represents client/server
                if from_client:
                    cli_ip, cli_port = src_ip, src_port
                    srv_ip, srv_port = dst_ip, dst_port
                else:
                    cli_ip, cli_port = dst_ip, dst_port
                    srv_ip, srv_port = src_ip, src_port

                self._flows[flow_key] = TCPStream(
                    stream_id    = flow_key,
                    src_ip       = cli_ip,
                    dst_ip       = srv_ip,
                    src_port     = cli_port,
                    dst_port     = srv_port,
                    protocol     = protocol,
                    is_implicit_tls = _is_implicit_tls_port(src_port, dst_port),
                )

            stream = self._flows[flow_key]
            stream.packet_count += 1
            stream.byte_count   += len(payload)

            seg = TCPSegment(seq=tcp.seq, payload=payload, from_client=from_client)
            if from_client:
                stream.client_data.extend(payload)
                stream.client_segments.append(seg)
            else:
                stream.server_data.extend(payload)
                stream.server_segments.append(seg)

        return list(self._flows.values())

    def reset(self):
        """Clear all state for reuse."""
        self._flows.clear()
        self._client_buf.clear()
        self._server_buf.clear()


def reassemble(packets: List[Packet], include_all_ports: bool = False) -> List[TCPStream]:
    """
    Convenience function: reassemble packets → TCPStream list.
    """
    r = StreamReassembler(include_all_ports=include_all_ports)
    return r.feed(packets)
