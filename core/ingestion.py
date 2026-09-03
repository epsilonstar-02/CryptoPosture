"""
core/ingestion.py
PCAP/PCAPNG evidence ingestion with SHA-256 forensic integrity hashing.
Implements Pipeline Stage 1 from the project synopsis.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from scapy.all import PcapReader, rdpcap
from scapy.layers.inet import IP

from .models import EvidenceMetadata


def compute_sha256(filepath: str | Path) -> str:
    """
    Compute the SHA-256 hash of a file in streaming chunks.
    The original file is never modified — evidence immutability is maintained.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def ingest_pcap(filepath: str | Path) -> tuple[list, EvidenceMetadata]:
    """
    Load a PCAP/PCAPNG file, compute evidence integrity hash, and return:
      - list of raw Scapy packets
      - EvidenceMetadata with SHA-256, file size, packet count, and capture duration

    Raises:
        FileNotFoundError: if the file does not exist.
        ValueError: if the file extension is not .pcap or .pcapng.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    ext = filepath.suffix.lower()
    if ext not in {".pcap", ".pcapng"}:
        raise ValueError(f"Unsupported file type '{ext}'. Expected .pcap or .pcapng.")

    # Compute evidence integrity hash BEFORE reading packets
    sha256_hash = compute_sha256(filepath)
    file_size   = filepath.stat().st_size

    # Read packets
    packets = rdpcap(str(filepath))

    # Calculate capture duration
    capture_duration = 0.0
    if len(packets) >= 2:
        try:
            t_start = float(packets[0].time)
            t_end   = float(packets[-1].time)
            capture_duration = round(t_end - t_start, 6)
        except Exception:
            pass

    metadata = EvidenceMetadata(
        filename=filepath.name,
        sha256_hash=sha256_hash,
        file_size_bytes=file_size,
        total_packets=len(packets),
        capture_duration=capture_duration,
    )

    return list(packets), metadata


def stream_pcap(filepath: str | Path):
    """
    Generator that yields packets one at a time using PcapReader (memory-efficient
    for large captures). Does NOT compute SHA-256 — use ingest_pcap() for
    forensic-integrity-verified loading.
    """
    filepath = Path(filepath)
    with PcapReader(str(filepath)) as reader:
        for pkt in reader:
            yield pkt
