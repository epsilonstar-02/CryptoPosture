"""
tests/test_reassembly.py
Comprehensive unit tests for TCP stream reordering and reassembly.
Tests out-of-order packets, duplicates, partial overlaps, 32-bit sequence
wrap-around, SYN anchoring, and fragmented TLS record reassembly.
"""

import random
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.all import Raw

from core.reassembly import StreamReassembler, reassemble, seq_diff
from core.crypto_parser import parse_combined
from generator.pcap_generator import _client_hello


def _make_pkt(
    src_ip: str, dst_ip: str, sport: int, dport: int,
    seq: int, payload: bytes, flags: str = "PA",
) -> Packet:
    return (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=1) /
        Raw(load=payload)
    )


class TestTCPReassembly(unittest.TestCase):
    """Unit tests for TCP stream reassembly and reordering."""

    def setUp(self):
        self.cli_ip = "192.168.1.10"
        self.srv_ip = "10.0.0.1"
        self.cli_port = 54321
        self.srv_port = 587  # SMTP

    def test_seq_diff_basic_and_wrap(self):
        """Test 32-bit TCP modular sequence arithmetic."""
        # Simple positive diff
        self.assertEqual(seq_diff(1500, 1000), 500)
        # Simple negative diff
        self.assertEqual(seq_diff(1000, 1500), -500)
        # Identical
        self.assertEqual(seq_diff(1000, 1000), 0)
        # Wrap-around across 0: 10 after 0xFFFFFFFF
        self.assertEqual(seq_diff(10, 0xFFFFFFFF), 11)
        self.assertEqual(seq_diff(0xFFFFFFFF, 10), -11)
        # Large jump wrap
        self.assertEqual(seq_diff(0x00000020, 0xFFFFFFF0), 48)
        self.assertEqual(seq_diff(0xFFFFFFF0, 0x00000020), -48)

    def test_in_order_reassembly(self):
        """Verify normal in-order packet delivery."""
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"EHLO client.com\r\n")
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000 + len(p1[Raw].load), payload=b"STARTTLS\r\n")

        streams = reassemble([p1, p2])
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(bytes(stream.client_data), b"EHLO client.com\r\nSTARTTLS\r\n")
        self.assertEqual(len(stream.client_segments), 2)
        self.assertEqual(stream.client_segments[0].seq, 1000)

    def test_out_of_order_reverse(self):
        """Verify reverse-order packet delivery is reassembled correctly."""
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"EHLO client.com\r\n")
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000 + len(p1[Raw].load), payload=b"STARTTLS\r\n")

        # Feed in reverse order: p2 before p1
        streams = reassemble([p2, p1])
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(bytes(stream.client_data), b"EHLO client.com\r\nSTARTTLS\r\n")
        self.assertEqual(len(stream.client_segments), 2)
        self.assertEqual(stream.client_segments[0].seq, 1000)
        self.assertEqual(stream.client_segments[1].seq, 1000 + len(p1[Raw].load))

    def test_out_of_order_shuffled(self):
        """Verify randomly shuffled segments are properly ordered."""
        base_seq = 50000
        chunks = [f"CHUNK_{i:02d};".encode("ascii") for i in range(20)]
        expected = b"".join(chunks)

        pkts = []
        cur_seq = base_seq
        for chunk in chunks:
            pkts.append(_make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=cur_seq, payload=chunk))
            cur_seq += len(chunk)

        # Shuffle packets
        rng = random.Random(42)
        shuffled = list(pkts)
        rng.shuffle(shuffled)

        streams = reassemble(shuffled)
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].client_data), expected)

    def test_retransmission_deduplication(self):
        """Verify retransmitted identical packets do not duplicate data."""
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"STARTTLS\r\n")
        p1_dup = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"STARTTLS\r\n")
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1010, payload=b"MAIL FROM:<a@b.com>\r\n")

        streams = reassemble([p1, p1_dup, p2])
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(bytes(stream.client_data), b"STARTTLS\r\nMAIL FROM:<a@b.com>\r\n")
        self.assertEqual(len(stream.client_segments), 2)

    def test_subset_segment_deduplication(self):
        """Verify a segment completely contained within an earlier segment is ignored."""
        # Large segment covering 1000..1060
        p_large = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"A" * 60)
        # Small segment covering 1020..1040 (completely inside p_large)
        p_sub = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1020, payload=b"A" * 20)
        # Next segment 1060..1080
        p_next = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1060, payload=b"B" * 20)

        streams = reassemble([p_large, p_sub, p_next])
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].client_data), b"A" * 60 + b"B" * 20)
        self.assertEqual(len(streams[0].client_segments), 2)

    def test_partial_overlap_tail(self):
        """Verify partially overlapping segments are trimmed so overlap is not duplicated."""
        # p1 covers 1000..1050
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"A" * 50)
        # p2 covers 1030..1080 (overlap of 20 bytes 1030..1050, new bytes 1050..1080)
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1030, payload=b"A" * 20 + b"B" * 30)

        streams = reassemble([p1, p2])
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].client_data), b"A" * 50 + b"B" * 30)
        self.assertEqual(len(streams[0].client_data), 80)

    def test_partial_overlap_out_of_order(self):
        """Verify partially overlapping segments arriving out of order are reordered and trimmed."""
        # p1 covers 1000..1050
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"A" * 50)
        # p2 covers 1030..1080
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1030, payload=b"A" * 20 + b"B" * 30)

        # Feed p2 first, then p1
        streams = reassemble([p2, p1])
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].client_data), b"A" * 50 + b"B" * 30)
        self.assertEqual(len(streams[0].client_data), 80)

    def test_32bit_sequence_wraparound(self):
        """Verify 32-bit TCP sequence wrap-around across 0xFFFFFFFF -> 0."""
        seq_start = 0xFFFFFFE0  # 32 bytes before 2^32
        data1 = b"BEFORE_WRAP_32_BYTES_OF_DATA_!!"  # exactly 32 bytes
        seq_after = 0  # wrapped to 0
        data2 = b"AFTER_WRAP_DATA_HERE"

        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=seq_start, payload=data1)
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=seq_after, payload=data2)

        # Test in-order
        s_in_order = reassemble([p1, p2])
        self.assertEqual(bytes(s_in_order[0].client_data), data1 + data2)

        # Test out-of-order (wrapped packet arrives first)
        s_out_of_order = reassemble([p2, p1])
        self.assertEqual(bytes(s_out_of_order[0].client_data), data1 + data2)

    def test_syn_anchoring_and_pre_syn_filtering(self):
        """Verify SYN sequence number anchors expected data start and trims pre-SYN noise."""
        syn_pkt = (
            IP(src=self.cli_ip, dst=self.srv_ip) /
            TCP(sport=self.cli_port, dport=self.srv_port, flags="S", seq=999, ack=0)
        )
        # Legitimate data packet starting at ISN + 1 = 1000
        data_pkt = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"EHLO mail.com\r\n")

        # Pre-SYN noise probe (seq 900)
        noise_pkt = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=900, payload=b"NOISE")

        streams = reassemble([noise_pkt, syn_pkt, data_pkt])
        self.assertEqual(len(streams), 1)
        self.assertEqual(bytes(streams[0].client_data), b"EHLO mail.com\r\n")

    def test_bidirectional_interleaved_out_of_order(self):
        """Verify client and server directions are each independently reordered."""
        # Client: c1 (seq 1000), c2 (seq 1020)
        c1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000, payload=b"CLIENT_1_")
        c2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=1000 + len(b"CLIENT_1_"), payload=b"CLIENT_2_")

        # Server: s1 (seq 5000), s2 (seq 5020)
        s1 = _make_pkt(self.srv_ip, self.cli_ip, self.srv_port, self.cli_port, seq=5000, payload=b"SERVER_1_")
        s2 = _make_pkt(self.srv_ip, self.cli_ip, self.srv_port, self.cli_port, seq=5000 + len(b"SERVER_1_"), payload=b"SERVER_2_")

        # Interleave out of order: s2, c2, s1, c1
        streams = reassemble([s2, c2, s1, c1])
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(bytes(stream.client_data), b"CLIENT_1_CLIENT_2_")
        self.assertEqual(bytes(stream.server_data), b"SERVER_1_SERVER_2_")

    def test_out_of_order_tls_fragment_reassembly(self):
        """
        Verify that a TLS ClientHello fragmented across multiple TCP packets
        arriving out of order is correctly reassembled and parsed by the crypto parser.
        """
        ch_bytes = _client_hello(version=0x0303, cipher_suites=[0xC02F, 0xC030], sni="mail.secure-corp.com")
        self.assertGreater(len(ch_bytes), 60)

        # Split into 3 fragments
        f1 = ch_bytes[:30]
        f2 = ch_bytes[30:70]
        f3 = ch_bytes[70:]

        seq = 10000
        p1 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=seq, payload=f1)
        p2 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=seq + len(f1), payload=f2)
        p3 = _make_pkt(self.cli_ip, self.srv_ip, self.cli_port, self.srv_port, seq=seq + len(f1) + len(f2), payload=f3)

        # Reassemble packets arriving out-of-order: p3, p1, p2
        streams = reassemble([p3, p1, p2])
        self.assertEqual(len(streams), 1)
        client_bytes = bytes(streams[0].client_data)
        self.assertEqual(client_bytes, ch_bytes)

        # Parse with crypto parser
        parsed = parse_combined(client_bytes, b"")
        self.assertIsNotNone(parsed.tls_version)
        self.assertEqual(parsed.sni, "mail.secure-corp.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
