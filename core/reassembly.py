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


def seq_diff(b: int, a: int) -> int:
    """
    Compute signed distance (b - a) in 32-bit TCP sequence number space [-2^31, 2^31 - 1].
    Correctly accounts for sequence wrap-around across 2^32 - 1 per RFC 1323 / RFC 7323.
    """
    diff = (b - a) & 0xFFFFFFFF
    if diff >= 0x80000000:
        diff -= 0x100000000
    return diff


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TCPSegment:
    """A single ordered TCP segment with directional context."""
    seq: int
    payload: bytes
    from_client: bool       # True = client→server, False = server→client
    timestamp: float = 0.0


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

    # Ordered payloads (client→server, server→client)
    client_data:  bytearray = field(default_factory=bytearray)
    server_data:  bytearray = field(default_factory=bytearray)

    # Packet-level bookkeeping
    packet_count: int = 0
    byte_count:   int = 0
    is_implicit_tls: bool = False

    # Raw ordered segment list (for TLS record boundary detection)
    client_segments: List[TCPSegment] = field(default_factory=list)
    server_segments: List[TCPSegment] = field(default_factory=list)

    @property
    def all_segments(self) -> List[TCPSegment]:
        """All segments across both directions sorted chronologically by arrival timestamp."""
        segs = list(self.client_segments) + list(self.server_segments)
        segs.sort(key=lambda s: s.timestamp)
        return segs


# ---------------------------------------------------------------------------
# Directional TCP Stream Reassembler
# ---------------------------------------------------------------------------

class _TCPDirectionReassembler:
    """
    Reassembles a single unidirectional TCP stream from unordered, overlapping,
    or duplicate TCP segments.
    """

    def __init__(self, from_client: bool):
        self.from_client = from_client
        self.ref_seq: Optional[int] = None
        self.syn_seen: bool = False
        self.expected_start_seq: Optional[int] = None
        self.raw_segments: List[Tuple[int, bytes, int, float]] = []  # (seq, payload, arrival_idx, timestamp)
        self.arrival_counter: int = 0

    def record_syn(self, syn_seq: int):
        """Record a SYN packet sequence number to anchor the stream sequence space."""
        self.syn_seen = True
        # Application data starts after SYN flag: (ISN + 1)
        self.expected_start_seq = (syn_seq + 1) & 0xFFFFFFFF
        if self.ref_seq is None:
            self.ref_seq = self.expected_start_seq

    def add_segment(self, seq: int, payload: bytes, is_syn: bool = False, timestamp: float = 0.0):
        """Buffer a payload segment for reassembly."""
        if not payload:
            return
        if is_syn:
            seq = (seq + 1) & 0xFFFFFFFF
        if self.ref_seq is None:
            self.ref_seq = seq

        self.raw_segments.append((seq, payload, self.arrival_counter, timestamp))
        self.arrival_counter += 1

    def reassemble(self) -> Tuple[bytearray, List[TCPSegment]]:
        """
        Reorder, deduplicate, and merge segments into a contiguous byte stream
        and an ordered list of distinct non-overlapping TCP segments.
        """
        if not self.raw_segments:
            return bytearray(), []

        ref_seq = self.ref_seq if self.ref_seq is not None else self.raw_segments[0][0]

        # Convert sequence numbers to linear signed offsets relative to ref_seq
        items: List[Tuple[int, int, int, bytes, int, float]] = []
        for seq, payload, arrival_idx, timestamp in self.raw_segments:
            start_offset = seq_diff(seq, ref_seq)
            end_offset = start_offset + len(payload)
            items.append((start_offset, end_offset, seq, payload, arrival_idx, timestamp))

        # Sort segments:
        # 1. start_offset ascending (earliest sequence number first)
        # 2. length descending (prefer larger chunks first if start is identical)
        # 3. arrival_idx ascending (preserve FIFO for equal spans)
        items.sort(key=lambda x: (x[0], -len(x[3]), x[4]))

        # If SYN was observed, trim any pre-SYN noise or partial handshake data
        if self.syn_seen and self.expected_start_seq is not None:
            syn_offset = seq_diff(self.expected_start_seq, ref_seq)
            filtered = []
            for start_offset, end_offset, seq, payload, arrival_idx, timestamp in items:
                if end_offset <= syn_offset:
                    continue
                if start_offset < syn_offset:
                    trim = syn_offset - start_offset
                    payload = payload[trim:]
                    seq = (seq + trim) & 0xFFFFFFFF
                    start_offset = syn_offset
                filtered.append((start_offset, end_offset, seq, payload, arrival_idx, timestamp))
            items = filtered

        result_segments: List[TCPSegment] = []
        current_offset: Optional[int] = None

        for start_offset, end_offset, seq, payload, _, timestamp in items:
            if current_offset is None:
                result_segments.append(TCPSegment(seq=seq, payload=payload, from_client=self.from_client, timestamp=timestamp))
                current_offset = end_offset
                continue

            # Case 1: Fully contained within already processed sequence range (duplicate/retransmission)
            if end_offset <= current_offset:
                continue

            # Case 2: Partial overlap on the left with already processed data
            if start_offset < current_offset:
                trim_len = current_offset - start_offset
                trimmed_payload = payload[trim_len:]
                trimmed_seq = (seq + trim_len) & 0xFFFFFFFF
                result_segments.append(TCPSegment(seq=trimmed_seq, payload=trimmed_payload, from_client=self.from_client, timestamp=timestamp))
                current_offset = end_offset
                continue

            # Case 3: Contiguous (start_offset == current_offset) or Gap (start_offset > current_offset)
            result_segments.append(TCPSegment(seq=seq, payload=payload, from_client=self.from_client, timestamp=timestamp))
            current_offset = end_offset

        data = bytearray(b"".join(seg.payload for seg in result_segments))
        return data, result_segments


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
        self._client_reassemblers: Dict[str, _TCPDirectionReassembler] = {}
        self._server_reassemblers: Dict[str, _TCPDirectionReassembler] = {}
        # Temporary seq-keyed buffers for compatibility: flow_key → {seq: bytes}
        self._client_buf: Dict[str, Dict[int, bytes]] = defaultdict(dict)
        self._server_buf: Dict[str, Dict[int, bytes]] = defaultdict(dict)

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port) -> Tuple[str, bool]:
        """
        Return a canonical flow key and a boolean indicating client→server direction.
        Lower-port side is always treated as the server (convention for email).
        """
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
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ip = pkt[IP]
                src_ip, dst_ip = ip.src, ip.dst
            elif pkt.haslayer("IPv6") and pkt.haslayer(TCP):
                ip = pkt["IPv6"]
                src_ip, dst_ip = ip.src, ip.dst
            else:
                continue

            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            payload  = bytes(tcp.payload) if tcp.payload else b""

            protocol = _port_to_protocol(src_port, dst_port)
            if protocol == Protocol.UNKNOWN and not self.include_all_ports:
                continue

            flow_key, from_client = self._flow_key(src_ip, dst_ip, src_port, dst_port)

            # Initialize stream and reassemblers on first sight
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
                self._client_reassemblers[flow_key] = _TCPDirectionReassembler(from_client=True)
                self._server_reassemblers[flow_key] = _TCPDirectionReassembler(from_client=False)

            stream = self._flows[flow_key]
            stream.packet_count += 1

            is_syn = bool(tcp.flags & 0x02)
            c_reassembler = self._client_reassemblers[flow_key]
            s_reassembler = self._server_reassemblers[flow_key]

            target_reassembler = c_reassembler if from_client else s_reassembler

            pkt_time = float(pkt.time) if hasattr(pkt, "time") and pkt.time is not None else 0.0

            if is_syn:
                target_reassembler.record_syn(tcp.seq)

            if payload:
                target_reassembler.add_segment(tcp.seq, payload, is_syn=is_syn, timestamp=pkt_time)

        # Reassemble and finalize each flow's bidirectional streams
        for flow_key, stream in self._flows.items():
            c_data, c_segs = self._client_reassemblers[flow_key].reassemble()
            s_data, s_segs = self._server_reassemblers[flow_key].reassemble()

            stream.client_data = c_data
            stream.server_data = s_data
            stream.client_segments = c_segs
            stream.server_segments = s_segs
            stream.byte_count = len(c_data) + len(s_data)

            self._client_buf[flow_key] = {seg.seq: seg.payload for seg in c_segs}
            self._server_buf[flow_key] = {seg.seq: seg.payload for seg in s_segs}

        return list(self._flows.values())

    def reset(self):
        """Clear all state for reuse."""
        self._flows.clear()
        self._client_reassemblers.clear()
        self._server_reassemblers.clear()
        self._client_buf.clear()
        self._server_buf.clear()


def reassemble(packets: List[Packet], include_all_ports: bool = False) -> List[TCPStream]:
    """
    Convenience function: reassemble packets → TCPStream list.
    """
    r = StreamReassembler(include_all_ports=include_all_ports)
    return r.feed(packets)
