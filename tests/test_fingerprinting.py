"""
tests/test_fingerprinting.py
Unit and integration tests for official FoxIO JA4+ fingerprinting.
"""

import unittest
from pathlib import Path

from core.fingerprinting import (
    FoxIOFingerprintIndex,
    _find_tshark,
    build_fingerprints,
    format_alpn,
    is_grease,
    oid_to_hex,
)
from core.models import JA4Fingerprints


class TestFoxIOIntegration(unittest.TestCase):
    def test_find_tshark_locates_executable(self):
        tshark = _find_tshark()
        self.assertIsNotNone(tshark, "tshark executable should be discovered")
        self.assertTrue(Path(tshark).exists(), f"Path must exist: {tshark}")

    def test_foxio_runs_and_extracts_fingerprints(self):
        pcap = Path("sample_pcaps/clean_implicit_tls.pcap")
        if not pcap.exists():
            self.skipTest("clean_implicit_tls.pcap not present")

        idx = FoxIOFingerprintIndex.from_environment(pcap)
        idx.load()

        self.assertTrue(idx.loaded, "FoxIO index should report loaded")
        self.assertIsNone(idx.load_error, "FoxIO should complete without error")
        self.assertGreater(len(idx._observations), 0, "Should have indexed at least 1 stream")

        obs = idx.lookup("192.168.1.100", "10.0.0.1", 54321, 993)
        self.assertIsNotNone(obs, "Should find stream for clean_implicit_tls 4-tuple")
        self.assertIsNotNone(obs.ja4, "Should have extracted a JA4 client fingerprint")
        self.assertTrue(obs.ja4.startswith("t13"), f"Expected t13 JA4, got {obs.ja4}")
        self.assertIsNotNone(obs.ja4s, "Should have extracted a JA4S server fingerprint")

    def test_build_fingerprints_pipeline_mode(self):
        pcap = Path("sample_pcaps/clean_implicit_tls.pcap")
        if not pcap.exists():
            self.skipTest("clean_implicit_tls.pcap not present")

        idx = FoxIOFingerprintIndex.from_environment(pcap)

        class MockStream:
            src_ip = "192.168.1.100"
            dst_ip = "10.0.0.1"
            src_port = 54321
            dst_port = 993

        fps, meta = build_fingerprints(stream=MockStream(), foxio=idx)
        self.assertIsInstance(fps, JA4Fingerprints)
        self.assertEqual(meta.get("status"), "MATCHED")
        self.assertTrue(meta.get("pcap_stream_match"))
        self.assertIsNotNone(fps.ja4)
        self.assertTrue(fps.ja4.startswith("t13"))

    def test_build_fingerprints_no_match(self):
        pcap = Path("sample_pcaps/clean_implicit_tls.pcap")
        if not pcap.exists():
            self.skipTest("clean_implicit_tls.pcap not present")

        idx = FoxIOFingerprintIndex.from_environment(pcap)

        class UnmatchedStream:
            src_ip = "1.2.3.4"
            dst_ip = "5.6.7.8"
            src_port = 12345
            dst_port = 443

        fps, meta = build_fingerprints(stream=UnmatchedStream(), foxio=idx)
        self.assertEqual(meta.get("status"), "NO_MATCHING_FOXIO_STREAM")
        self.assertFalse(meta.get("pcap_stream_match"))
        self.assertIsNone(fps.ja4)

    def test_iter_json_records_concatenated_multiline(self):
        multiline_foxio_output = """
        {
            "stream": 2,
            "src": "10.10.1.88",
            "dst": "10.0.0.3",
            "srcport": "52114",
            "dstport": "993",
            "JA4.1": "t12d020300_04659ec43a24_355e4ef2c0d9"
        }
        {
            "stream": 5,
            "src": "198.51.100.20",
            "dst": "10.0.0.4",
            "srcport": "50123",
            "dstport": "25",
            "JA4.1": "t12d010300_f06271c2b022_355e4ef2c0d9"
        }
        """
        records = list(FoxIOFingerprintIndex._iter_json_records(multiline_foxio_output))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["stream"], 2)
        self.assertEqual(records[1]["stream"], 5)
        self.assertEqual(records[0]["JA4.1"], "t12d020300_04659ec43a24_355e4ef2c0d9")

    def test_foxio_non_tls_pcap_loads_cleanly(self):
        pcap = Path("sample_pcaps/stripped_starttls_plaintext.pcap")
        if not pcap.exists():
            self.skipTest("stripped_starttls_plaintext.pcap not present")

        idx = FoxIOFingerprintIndex.from_environment(pcap)
        idx.load()
        self.assertTrue(idx.loaded)
        self.assertIsNone(idx.load_error)
        self.assertEqual(len(idx._observations), 0)

    def test_enterprise_network_simulation_loads_multiple_streams(self):
        pcap = Path("sample_pcaps/enterprise_network_simulation.pcap")
        if not pcap.exists():
            self.skipTest("enterprise_network_simulation.pcap not present")

        idx = FoxIOFingerprintIndex.from_environment(pcap)
        idx.load()
        self.assertTrue(idx.loaded)
        self.assertIsNone(idx.load_error)
        self.assertGreaterEqual(len(idx._observations), 5)


class TestALPNFormatting(unittest.TestCase):
    def test_spec_alpn_examples(self):
        self.assertEqual(format_alpn("h2"), "h2")
        self.assertEqual(format_alpn("http/1.1"), "h1")
        self.assertEqual(format_alpn("h"), "hh")
        self.assertEqual(format_alpn(""), "00")
        self.assertEqual(format_alpn(None), "00")

    def test_non_ascii_hex_fallback(self):
        self.assertEqual(format_alpn(b"\xab"), "ab")
        self.assertEqual(format_alpn(b"\x20"), "20")
        self.assertEqual(format_alpn(b"\xab\xcd"), "ad")
        self.assertEqual(format_alpn(b"\x20\x61"), "21")
        self.assertEqual(format_alpn(b"\x30\xab"), "3b")
        self.assertEqual(format_alpn(b"\x61\x20"), "60")
        self.assertEqual(format_alpn(b"\x30\x31\xab\xcd"), "3d")
        self.assertEqual(format_alpn(b"\x30\xab\xcd\x31"), "01")


class TestOIDEncoding(unittest.TestCase):
    def test_oid_to_hex(self):
        self.assertEqual(oid_to_hex("2.5.4.3"), "550403")
        self.assertEqual(oid_to_hex("2.5.4.6"), "550406")
        self.assertEqual(oid_to_hex("2.5.4.10"), "55040a")
        self.assertEqual(oid_to_hex("2.5.29.17"), "551d11")

    def test_empty_or_short_oid(self):
        self.assertEqual(oid_to_hex(""), "")
        self.assertEqual(oid_to_hex("2"), "")


class TestGREASEFiltering(unittest.TestCase):
    def test_grease_values(self):
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0x1A1A))
        self.assertTrue(is_grease(0xFAFA))
        self.assertFalse(is_grease(0x1301))
        self.assertFalse(is_grease(0x0000))


if __name__ == "__main__":
    unittest.main()
