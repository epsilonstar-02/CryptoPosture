"""
core/pipeline.py
Main forensic analysis pipeline orchestrator.
Wires together all stages: ingestion → reassembly → STARTTLS tracking →
TLS/X.509 parsing → fingerprinting → rule engine → scoring → ML anomaly detection.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import List, Optional

from .ingestion import ingest_pcap
from .reassembly import reassemble, TCPStream, IMPLICIT_TLS_PORTS
from .starttls_tracker import analyze_starttls
from .crypto_parser import parse_combined
from .fingerprinting import build_fingerprints
from .rule_engine import run_rules
from .scorer import score_session, compute_enterprise_index
from .ml_anomaly import run_anomaly_detection
from .models import (
    CertHealth,
    ChannelType,
    EnterpriseSummary,
    EvidenceMetadata,
    KeyExchange,
    Protocol,
    SessionAnalysis,
    TLSVersion,
)


def analyze_pcap(
    filepath: str | Path,
    run_ml: bool = True,
    include_all_ports: bool = False,
) -> EnterpriseSummary:
    """
    End-to-end forensic analysis pipeline for a PCAP/PCAPNG file.

    Args:
        filepath: Path to the PCAP/PCAPNG evidence file.
        run_ml: Whether to run Isolation Forest anomaly detection (default True).
        include_all_ports: If True, reassemble all TCP flows regardless of port.

    Returns:
        EnterpriseSummary with all sessions analyzed and enterprise posture index.
    """
    # Stage 1: Evidence ingestion + SHA-256 integrity
    packets, evidence = ingest_pcap(filepath)

    # Stage 2: TCP stream reassembly + protocol demux
    streams = reassemble(packets, include_all_ports=include_all_ports)

    # Stages 3–9: Per-session analysis
    sessions: List[SessionAnalysis] = []
    for stream in streams:
        session = _analyze_stream(stream)
        sessions.append(session)

    # Stage 9 (ML): Isolation Forest anomaly detection across all sessions
    if run_ml and len(sessions) >= 2:
        sessions = run_anomaly_detection(sessions)

    # Stage 10: Enterprise aggregation
    summary = EnterpriseSummary(
        evidence=evidence,
        sessions=sessions,
    )
    summary = compute_enterprise_index(summary)

    return summary


def _analyze_stream(stream: TCPStream) -> SessionAnalysis:
    """
    Run the full analysis pipeline on a single reassembled TCP stream.
    """
    session = SessionAnalysis(
        session_id  = str(uuid.uuid4())[:8],
        src_ip      = stream.src_ip,
        dst_ip      = stream.dst_ip,
        src_port    = stream.src_port,
        dst_port    = stream.dst_port,
        protocol    = stream.protocol,
        packet_count = stream.packet_count,
        byte_count   = stream.byte_count,
    )

    # Stage 3: STARTTLS state machine
    starttls_result = analyze_starttls(stream)
    session.starttls_status        = starttls_result.starttls_status
    session.channel_type           = starttls_result.channel_type
    session.buffer_injection_detected = starttls_result.buffer_injection
    session.cmd_inject_flag        = starttls_result.buffer_injection
    session.bytes_pre_tls          = starttls_result.bytes_before_tls

    # Stage 4 & 5: TLS handshake + X.509 certificate parsing
    client_bytes = bytes(stream.client_data)
    server_bytes = bytes(stream.server_data)

    hs = parse_combined(client_bytes, server_bytes)

    if hs.tls_version:
        session.tls_version = hs.tls_version
    if hs.cipher_suite_name:
        session.cipher_suite = hs.cipher_suite_name
    if hs.key_exchange:
        session.key_exchange = hs.key_exchange
    session.sni = hs.sni
    session.sni_present = bool(hs.sni)

    if hs.cert:
        session.cert = hs.cert

    # Correct channel type for implicit TLS if TLS records found but no STARTTLS
    if stream.is_implicit_tls and hs.tls_version:
        session.channel_type = ChannelType.IMPLICIT_TLS

    # Stage 6: JA4 fingerprinting
    session.fingerprints = build_fingerprints(hs)

    # Stage 8 (simplified): Note PQC readiness
    if hs.has_pqc:
        session.pqc_state = 2   # Hybrid PQC Negotiated
        session.anomaly_features["pqc_ready"] = 1.0
    else:
        session.pqc_state = 0   # Classical only

    # Stage 9 (rules): Deterministic compliance checking
    session.violations = run_rules(session)

    # Stage 9 (scoring): Posture score + risk tier
    session = score_session(session)

    return session
