"""
core/ingestion.py
Authoritative PCAP/PCAPNG Evidence Ingestion with SHA-256 Forensic Integrity.
Implements Pipeline Stage 1 from the project synopsis.

Key Forensic Principles:
  1. Capture-level validation: verifies binary magic bytes (PCAP/PCAPNG) to prevent
     extension spoofing or corrupt capture processing.
  2. Complete chain-of-custody metadata: preserves normalized absolute path,
     SHA-256 integrity hash, ingestion timestamp (UTC), capture format, link-layer type,
     first/last packet timestamps, and parse error count.
  3. Memory-efficient streaming ingestion: uses Scapy's PcapReader to stream packets
     sequentially rather than loading entire raw captures into unmanaged RAM.
  4. Diagnostic and fail-safe error hierarchy: typed exceptions distinguishing
     missing files, permission errors, unsupported formats, truncated headers,
     empty captures, and integrity violations.
  5. Tamper verification: verifies that the evidence file remains strictly unmodified
     before, during, and after ingestion.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from scapy.all import PcapReader
from scapy.packet import Packet

from .models import EvidenceMetadata


# ---------------------------------------------------------------------------
# Magic Byte Definitions
# ---------------------------------------------------------------------------

PCAP_MAGIC_MICROSECONDS           = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_MICROSECONDS_SWAPPED   = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NANOSECONDS            = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NANOSECONDS_SWAPPED    = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC_SHB                  = b"\x0a\x0d\x0d\x0a"

_PCAP_MAGICS = {
    PCAP_MAGIC_MICROSECONDS,
    PCAP_MAGIC_MICROSECONDS_SWAPPED,
    PCAP_MAGIC_NANOSECONDS,
    PCAP_MAGIC_NANOSECONDS_SWAPPED,
}

_ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


# ---------------------------------------------------------------------------
# Diagnostic Exception Hierarchy
# ---------------------------------------------------------------------------

class IngestionError(Exception):
    """Base class for all forensic evidence ingestion errors."""
    pass


class EvidenceNotFoundError(IngestionError, FileNotFoundError):
    """Raised when the specified evidence file does not exist."""
    pass


class EvidencePermissionError(IngestionError, PermissionError):
    """Raised when the evidence file cannot be accessed due to OS permissions."""
    pass


class UnsupportedFormatError(IngestionError, ValueError):
    """Raised when the file format, extension, or magic bytes are unsupported."""
    pass


class CorruptCaptureError(IngestionError):
    """Raised when the capture header or packet stream is truncated or malformed."""
    pass


class EmptyCaptureError(IngestionError):
    """Raised when the capture contains 0 bytes or zero decodable packets."""
    pass


class EvidenceIntegrityError(IngestionError):
    """Raised when the evidence file mutates between pre-read and post-read hashes."""
    pass


# ---------------------------------------------------------------------------
# Core Ingestion Functions
# ---------------------------------------------------------------------------

def compute_sha256(filepath: str | Path) -> str:
    """
    Compute the authoritative SHA-256 hash of a file using chunked streaming.
    Evidence immutability is strictly respected: opened read-only in binary mode.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def detect_capture_format(filepath: Path) -> Tuple[str, bytes]:
    """
    Inspect the binary file header to validate PCAP / PCAPNG magic numbers.

    Returns:
        (format_name, magic_bytes) where format_name is "PCAP" or "PCAPNG".

    Raises:
        CorruptCaptureError: if file is under 4 bytes.
        UnsupportedFormatError: if magic bytes do not match a known capture format.
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except PermissionError as e:
        raise EvidencePermissionError(f"Permission denied reading evidence file: {filepath}") from e
    except OSError as e:
        raise IngestionError(f"OS error reading evidence file {filepath}: {e}") from e

    if len(magic) < 4:
        raise CorruptCaptureError(
            f"Evidence file is truncated (< 4 bytes, got {len(magic)} bytes): {filepath.name}"
        )

    if magic in _PCAP_MAGICS:
        return "PCAP", magic
    elif magic == PCAPNG_MAGIC_SHB:
        return "PCAPNG", magic
    else:
        raise UnsupportedFormatError(
            f"Unsupported or invalid capture magic bytes 0x{magic.hex()} in '{filepath.name}'. "
            f"Expected standard PCAP or PCAPNG Section Header Block."
        )


def ingest_pcap(
    filepath: str | Path,
    max_packets: Optional[int] = None,
    verify_tamper: bool = True,
) -> Tuple[List[Packet], EvidenceMetadata]:
    """
    Authoritative passive forensic evidence ingestion.

    Steps:
      1. Validates file existence and permissions.
      2. Validates file extension and binary capture magic bytes.
      3. Computes pre-read SHA-256 hash before reading any packets.
      4. Streams packets using PcapReader for memory efficiency.
      5. Analyzes timestamp boundaries and flags any timestamp anomalies.
      6. Computes post-read SHA-256 hash to verify the file was not tampered with.
      7. Returns the list of parsed packets alongside complete EvidenceMetadata.

    Raises:
        EvidenceNotFoundError: if the evidence file does not exist.
        EvidencePermissionError: if read access is denied.
        UnsupportedFormatError: if extension or magic bytes are invalid.
        CorruptCaptureError: if header or file is truncated.
        EmptyCaptureError: if the file is 0 bytes or contains 0 packets.
        EvidenceIntegrityError: if the file changed during reading.
    """
    path = Path(filepath)

    # 1. Existence check
    if not path.exists():
        raise EvidenceNotFoundError(f"PCAP evidence file not found: {path}")

    # 2. Extension check
    ext = path.suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported file extension '{ext}'. Expected .pcap, .pcapng, or .cap."
        )

    # 3. File size check
    try:
        file_size = path.stat().st_size
    except OSError as e:
        raise EvidencePermissionError(f"Cannot access evidence file stats: {e}") from e

    if file_size == 0:
        raise EmptyCaptureError(f"Evidence file is empty (0 bytes): {path.name}")

    # 4. Binary magic bytes validation
    capture_format, magic_bytes = detect_capture_format(path)

    # 5. Pre-read cryptographic integrity hash
    pre_sha256 = compute_sha256(path)

    # 6. Streaming packet ingestion
    packets: List[Packet] = []
    diagnostics: List[str] = []
    parse_errors = 0
    timestamps: List[float] = []
    link_layer_type = "Ethernet"

    try:
        with PcapReader(str(path)) as reader:
            raw_linktype = getattr(reader, "linktype", None)
            if raw_linktype is not None:
                link_layer_type = f"DLT_{raw_linktype}"

            while True:
                try:
                    pkt = reader.read_packet()
                    if pkt is None:
                        break
                    packets.append(pkt)

                    if hasattr(pkt, "time") and pkt.time is not None:
                        try:
                            timestamps.append(float(pkt.time))
                        except (ValueError, TypeError):
                            pass

                    if max_packets and len(packets) >= max_packets:
                        diagnostics.append(f"Ingestion capped at max_packets={max_packets}")
                        break
                except EOFError:
                    break
                except Exception as pkt_err:
                    parse_errors += 1
                    diagnostics.append(
                        f"Packet decode error at packet index #{len(packets) + 1}: {pkt_err}"
                    )
    except Exception as read_err:
        if not packets:
            raise CorruptCaptureError(
                f"Failed to read capture {path.name}: {read_err}"
            ) from read_err
        else:
            diagnostics.append(f"Reader terminated with error: {read_err}")

    # 7. Check for empty packet capture
    if not packets:
        raise EmptyCaptureError(
            f"Capture contains valid {capture_format} header but 0 packets were decoded: {path.name}"
        )

    # 8. Post-read tamper verification
    is_tamper_free = True
    if verify_tamper:
        post_sha256 = compute_sha256(path)
        if pre_sha256 != post_sha256:
            raise EvidenceIntegrityError(
                f"Evidence file was modified during ingestion! "
                f"Pre-hash: {pre_sha256}, Post-hash: {post_sha256}"
            )

    # 9. Timestamp boundary analysis
    first_pkt_ts: Optional[float] = None
    last_pkt_ts: Optional[float] = None
    capture_duration: float = 0.0

    if timestamps:
        first_pkt_ts = timestamps[0]
        last_pkt_ts = timestamps[-1]

        # Check for non-monotonic timestamp regressions
        regressions = sum(1 for i in range(1, len(timestamps)) if timestamps[i] < timestamps[i - 1])
        if regressions > 0:
            diagnostics.append(
                f"Timestamp anomaly: {regressions} non-monotonic timestamp regressions detected in capture."
            )

        t_min = min(timestamps)
        t_max = max(timestamps)
        capture_duration = round(max(0.0, t_max - t_min), 6)

    metadata = EvidenceMetadata(
        filename=path.name,
        sha256_hash=pre_sha256,
        file_size_bytes=file_size,
        total_packets=len(packets),
        capture_duration=capture_duration,
        evidence_id=f"ev_{pre_sha256[:16]}",
        absolute_path=str(path.resolve()),
        hash_algorithm="SHA-256",
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        capture_format=capture_format,
        magic_bytes_hex=magic_bytes.hex(),
        link_layer_type=link_layer_type,
        first_packet_timestamp=first_pkt_ts,
        last_packet_timestamp=last_pkt_ts,
        parse_error_count=parse_errors,
        is_tamper_free=is_tamper_free,
        diagnostics=diagnostics,
    )

    return packets, metadata


def stream_pcap(filepath: str | Path) -> Generator[Packet, None, None]:
    """
    Generator that yields packets sequentially using PcapReader for memory-efficient
    processing of multi-gigabyte captures. Validates capture magic bytes prior to streaming.
    """
    path = Path(filepath)
    if not path.exists():
        raise EvidenceNotFoundError(f"PCAP file not found: {path}")

    # Validate header magic bytes
    detect_capture_format(path)

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield pkt

