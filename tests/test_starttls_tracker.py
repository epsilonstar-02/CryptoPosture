"""
tests/test_starttls_tracker.py
Comprehensive unit tests for the order-aware STARTTLS tracker.
Validates state machine transitions, proven vs possible stripping,
inconclusive capture handling, multi-segment buffer injection,
IMAP/POP3 protocol parsing, and structural TLS record transitions.
"""

import unittest
from core.models import Protocol, StarttlsStatus, ChannelType
from core.reassembly import TCPStream, TCPSegment
from core.starttls_tracker import StarttlsTracker, analyze_starttls, find_tls_record_transition
from generator.pcap_generator import _client_hello, _server_hello


def _make_stream(
    protocol: Protocol,
    client_payloads: list[bytes],
    server_payloads: list[bytes],
    dst_port: int = 25,
    is_implicit_tls: bool = False,
) -> TCPStream:
    """Helper to construct a mock TCPStream with TCPSegments."""
    stream = TCPStream(
        stream_id="192.168.1.10:50000->10.0.0.1:" + str(dst_port),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        is_implicit_tls=is_implicit_tls,
    )

    c_seq = 1000
    for idx, p in enumerate(client_payloads):
        seg = TCPSegment(seq=c_seq, payload=p, from_client=True, timestamp=float(idx * 0.010))
        stream.client_data.extend(p)
        stream.client_segments.append(seg)
        c_seq += len(p)

    s_seq = 5000
    for idx, p in enumerate(server_payloads):
        seg = TCPSegment(seq=s_seq, payload=p, from_client=False, timestamp=float(idx * 0.010))
        stream.server_data.extend(p)
        stream.server_segments.append(seg)
        s_seq += len(p)

    stream.byte_count = len(stream.client_data) + len(stream.server_data)
    stream.packet_count = len(client_payloads) + len(server_payloads)
    return stream


class TestStarttlsTracker(unittest.TestCase):
    """Unit tests for StarttlsTracker state machine and detector."""

    def test_structural_tls_record_validator(self):
        """Verify structural TLS validator rejects invalid magic bytes and accepts genuine records."""
        # Genuine ClientHello
        ch = _client_hello(version=0x0303, sni="mail.test.com")
        res = find_tls_record_transition(ch, 0)
        self.assertIsNotNone(res)
        offset, ctype, ver = res
        self.assertEqual(offset, 0)
        self.assertEqual(ctype, 0x16)
        self.assertEqual(ver, 0x0301)  # outer record version

        # False positive: 0x16 0x03 0x01 but invalid length or not handshake
        fake = b"RANDOM_PREFIX\x16\x03\x01\x00\x00REST_OF_DATA"
        self.assertIsNone(find_tls_record_transition(fake, 0))

        # Embedded genuine record
        embedded = b"SOME_PREAMBLE_DATA\r\n" + ch
        res2 = find_tls_record_transition(embedded, 0)
        self.assertIsNotNone(res2)
        self.assertEqual(res2[0], len(b"SOME_PREAMBLE_DATA\r\n"))

    def test_normal_smtp_starttls(self):
        """Verify standard successful SMTP STARTTLS negotiation."""
        ch = _client_hello(version=0x0303)
        sh = _server_hello(version=0x0303)

        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"STARTTLS\r\n",
            ch,
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP Postfix\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"220 2.0.0 Ready to start TLS\r\n",
            sh,
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(analysis.channel_type, ChannelType.STARTTLS)
        self.assertFalse(analysis.buffer_injection)
        self.assertGreater(analysis.bytes_before_tls, 0)

    def test_server_advertises_client_ignores(self):
        """Verify opportunistic plaintext when server advertises but client does not upgrade."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"MAIL FROM:<sender@test.com>\r\n",
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"250 2.1.0 Ok\r\n",
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=25)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.ADVERTISED)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_proven_stripping_with_auth_fallback(self):
        """Verify proven STRIPPED when STARTTLS omitted from EHLO reply and client transmits cleartext credentials."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"AUTH PLAIN dXNlcgBwYXNz\r\n",
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n",  # STARTTLS stripped!
            b"235 2.7.0 Authentication successful\r\n",
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=25)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.STRIPPED)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_possible_stripping_on_submission_port(self):
        """Verify POSSIBLE_STRIPPING when capability omitted on port 587 but no credentials transmitted."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"QUIT\r\n",
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250 8BITMIME\r\n",  # No STARTTLS on port 587!
            b"221 Bye\r\n",
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.POSSIBLE_STRIPPING)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_server_rejects_starttls(self):
        """Verify FAILED status when server rejects STARTTLS request."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"STARTTLS\r\n",
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"454 4.7.0 TLS not available due to temporary reason\r\n",
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.FAILED)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_starttls_acked_but_cleartext_resumed(self):
        """Verify FAILED status when server ACKs upgrade but client resumes in cleartext."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"STARTTLS\r\n",
            b"RSET\r\n",  # Cleartext resumed instead of TLS ClientHello
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"220 2.0.0 Ready to start TLS\r\n",
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.FAILED)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_truncated_capture_inconclusive(self):
        """Verify INCONCLUSIVE when capture ends abruptly right after client sends STARTTLS."""
        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"STARTTLS\r\n",
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            # No response captured!
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.INCONCLUSIVE)
        self.assertEqual(analysis.channel_type, ChannelType.PLAINTEXT)

    def test_mid_stream_capture_inconclusive(self):
        """Verify INCONCLUSIVE when capture begins mid-stream with no greeting or handshake."""
        client_pkts = [b"NOOP\r\n"]
        server_pkts = [b"250 OK\r\n"]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=25)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.INCONCLUSIVE)

    def test_same_segment_buffer_injection(self):
        """Verify detection of Poddebniak buffer injection in the same TCP segment."""
        ch = _client_hello(version=0x0303)
        sh = _server_hello(version=0x0303)

        injected_seg = (
            b"STARTTLS\r\n"
            b"MAIL FROM:<attacker@evil.com>\r\n"
            b"RCPT TO:<victim@target.com>\r\n"
            b"DATA\r\n"
        )

        client_pkts = [
            b"EHLO client.test.com\r\n",
            injected_seg,
            ch,
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"220 Ready to start TLS\r\n",
            sh,
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertTrue(analysis.buffer_injection)
        self.assertIn("MAIL FROM", analysis.injected_commands)
        self.assertIn("RCPT TO", analysis.injected_commands)
        self.assertIn("DATA", analysis.injected_commands)

    def test_multi_segment_buffer_injection(self):
        """Verify detection of injected commands arriving in separate subsequent segment before TLS."""
        ch = _client_hello(version=0x0303)
        sh = _server_hello(version=0x0303)

        client_pkts = [
            b"EHLO client.test.com\r\n",
            b"STARTTLS\r\n",
            b"MAIL FROM:<injected@separate.com>\r\nRCPT TO:<v@separate.com>\r\n",  # injected segment before TLS!
            ch,
        ]
        server_pkts = [
            b"220 mail.test.com ESMTP\r\n",
            b"250-mail.test.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            b"220 Ready to start TLS\r\n",
            sh,
        ]

        stream = _make_stream(Protocol.SMTP, client_pkts, server_pkts, dst_port=587)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertTrue(analysis.buffer_injection)
        self.assertIn("MAIL FROM", analysis.injected_commands)
        self.assertIn("RCPT TO", analysis.injected_commands)

    def test_imap_starttls_negotiation(self):
        """Verify IMAP STARTTLS negotiation parsing."""
        ch = _client_hello(version=0x0303)
        sh = _server_hello(version=0x0303)

        client_pkts = [
            b"a001 CAPABILITY\r\n",
            b"a002 STARTTLS\r\n",
            ch,
        ]
        server_pkts = [
            b"* OK IMAP4rev1 Server Ready\r\n",
            b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK CAPABILITY completed\r\n",
            b"a002 OK Begin TLS negotiation now\r\n",
            sh,
        ]

        stream = _make_stream(Protocol.IMAP, client_pkts, server_pkts, dst_port=143)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(analysis.channel_type, ChannelType.STARTTLS)
        self.assertFalse(analysis.buffer_injection)

    def test_pop3_stls_negotiation(self):
        """Verify POP3 STLS negotiation parsing."""
        ch = _client_hello(version=0x0303)
        sh = _server_hello(version=0x0303)

        client_pkts = [
            b"CAPA\r\n",
            b"STLS\r\n",
            ch,
        ]
        server_pkts = [
            b"+OK POP3 server ready\r\n",
            b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n",
            b"+OK Begin TLS negotiation\r\n",
            sh,
        ]

        stream = _make_stream(Protocol.POP3, client_pkts, server_pkts, dst_port=110)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.starttls_status, StarttlsStatus.NEGOTIATED)
        self.assertEqual(analysis.channel_type, ChannelType.STARTTLS)
        self.assertFalse(analysis.buffer_injection)

    def test_implicit_tls_policy(self):
        """Verify implicit TLS port produces IMPLICIT_TLS and NONE status."""
        ch = _client_hello(version=0x0304)
        sh = _server_hello(version=0x0304)

        stream = _make_stream(Protocol.IMAP, [ch], [sh], dst_port=993, is_implicit_tls=True)
        analysis = analyze_starttls(stream)

        self.assertEqual(analysis.channel_type, ChannelType.IMPLICIT_TLS)
        self.assertEqual(analysis.starttls_status, StarttlsStatus.NONE)
        self.assertEqual(analysis.bytes_before_tls, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
