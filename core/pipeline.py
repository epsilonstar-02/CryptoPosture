"""
core/pipeline.py
Production-grade Passive Network Cryptographic Forensic Pipeline Orchestrator.

Formal Pipeline Contract:
  Stage 1:  Evidence Ingestion & Cryptographic Integrity Verification
  Stage 2:  TCP Flow Reassembly & Directional Demuxing
  Stage 3:  Application Protocol & STARTTLS State Machine Tracking
  Stage 4:  TLS Record Layer & Handshake Parsing
  Stage 5:  X.509 Certificate Chain Validation & Security Bit Profiling
  Stage 6:  Multi-layer JA4+ Cryptographic Fingerprinting
  Stage 7:  Cross-Stage Pipeline Semantic & Boundary Validation
  Stage 8:  Forensic Fact & Evidence Lineage Construction
  Stage 9:  Deterministic Compliance & Rule Engine Evaluation
  Stage 10: Cryptographic Posture Scoring & Risk Tiering
  Stage 11: Machine Learning Anomaly Detection (Optional & Isolated)
  Stage 12: Enterprise Posture Aggregation & Forensic Reporting
"""

from __future__ import annotations

import hashlib
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ingestion import (
    ingest_pcap,
    IngestionError,
    EvidenceNotFoundError,
    EvidencePermissionError,
    UnsupportedFormatError,
    CorruptCaptureError,
    EmptyCaptureError,
    EvidenceIntegrityError,
)
from .reassembly import reassemble, TCPStream, IMPLICIT_TLS_PORTS
from .starttls_tracker import analyze_starttls, StarttlsAnalysis
from .crypto_parser import parse_combined, HandshakeResult
from .fingerprinting import build_fingerprints, FoxIOFingerprintIndex
from .rule_engine import run_rules, DEFAULT_POLICY_CATALOG
from .scorer import score_session, compute_enterprise_index, DEFAULT_POLICY
from .ml_anomaly import run_anomaly_detection
from .models import (
    AnalysisConfig,
    CertHealth,
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    EnterpriseSummary,
    EvidenceMetadata,
    FactOrigin,
    FindingStatus,
    ForensicFact,
    KeyExchange,
    MLSettings,
    PacketProvenance,
    ParserOptions,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StageResult,
    StageStatus,
    StarttlsStatus,
    TLSVersion,
    Violation,
)


# ---------------------------------------------------------------------------
# Public Orchestrator Entrypoint
# ---------------------------------------------------------------------------

def analyze_pcap(
    filepath: str | Path,
    run_ml: bool = True,
    include_all_ports: bool = False,
    config: Optional[AnalysisConfig] = None,
) -> EnterpriseSummary:
    """
    End-to-end passive forensic analysis pipeline for a PCAP/PCAPNG evidence file.

    Guarantees:
      1. Stage-level error isolation: a malformed stream or handshake failure will
         isolate to that session (marked INCONCLUSIVE) and never abort the entire capture.
      2. Deterministic execution: reproducible session IDs and rule evaluations.
      3. Provenance tracking: every finding links back to raw packet / record boundaries.
      4. Isolated ML: machine learning never mutates deterministic compliance scores.

    Args:
        filepath: Path to the PCAP/PCAPNG evidence file.
        run_ml: Toggle Isolation Forest anomaly detection (used if config is None).
        include_all_ports: Reassemble all TCP flows regardless of standard email ports.
        config: Explicit AnalysisConfig policy object. Overrides boolean flags if provided.

    Returns:
        EnterpriseSummary with all sessions analyzed, evidence hash, and enterprise posture index.
    """
    if config is None:
        config = AnalysisConfig.from_args(
            run_ml=run_ml,
            include_all_ports=include_all_ports,
        )

    # 🔴 Fix 5: Attach actual policy objects if not already set.
    # This wires the real PolicyCatalog and ScoringPolicy (not just their string IDs)
    # so that stage9, stage10, and stage12 all use the same, correctly-configured objects.
    import hashlib as _hl, json as _json
    if config.policy_catalog is None:
        config.policy_catalog = DEFAULT_POLICY_CATALOG
    if config.scoring_policy is None:
        config.scoring_policy = DEFAULT_POLICY
    # Compute reproducibility hashes
    if config.policy_catalog_hash is None:
        try:
            config.policy_catalog_hash = _hl.sha256(
                config.policy_catalog.to_json().encode()
            ).hexdigest()[:16]
        except Exception:
            config.policy_catalog_hash = "unavailable"
    if config.scoring_policy_hash is None:
        try:
            _sp = config.scoring_policy
            _sp_str = _json.dumps({
                "policy_id": _sp.policy_id,
                "policy_version": _sp.policy_version,
                "weights": _sp.weights,
            }, sort_keys=True)
            config.scoring_policy_hash = _hl.sha256(_sp_str.encode()).hexdigest()[:16]
        except Exception:
            config.scoring_policy_hash = "unavailable"

    # -----------------------------------------------------------------------
    # Stage 1: Evidence Ingestion & Cryptographic Integrity Verification
    # -----------------------------------------------------------------------
    packets, evidence, s1_result = stage1_ingest(filepath)

    # -----------------------------------------------------------------------
    # Stage 2: TCP Flow Reassembly & Directional Demuxing
    # -----------------------------------------------------------------------
    streams, s2_result = stage2_reassemble(packets, config.parser_options)

    # -----------------------------------------------------------------------
    # Stage 6 dependency: run FoxIO once per capture, then correlate by 4-tuple.
    # This avoids re-running the external fingerprint engine for every session.
    # -----------------------------------------------------------------------
    foxio = FoxIOFingerprintIndex.from_environment(filepath)

    # -----------------------------------------------------------------------
    # Stages 3–10: Per-Session Analysis with Stage-Level Error Isolation
    # -----------------------------------------------------------------------
    sessions: List[SessionAnalysis] = []
    for stream in streams:
        try:
            session = _analyze_stream(stream, config, evidence=evidence, foxio=foxio)
            session.stage_results["stage1_ingestion"] = s1_result
            session.stage_results["stage2_reassembly"] = s2_result
            sessions.append(session)
        except Exception as exc:
            # Absolute fallback isolation: malformed stream never halts pipeline
            fallback_session = _build_fallback_session(stream, exc, evidence=evidence)
            fallback_session.stage_results["stage1_ingestion"] = s1_result
            fallback_session.stage_results["stage2_reassembly"] = s2_result
            sessions.append(fallback_session)

    # -----------------------------------------------------------------------
    # Stage 11: Machine Learning Anomaly Detection (Optional & Isolated)
    # -----------------------------------------------------------------------
    sessions, s11_result = stage11_ml_anomaly(sessions, config)

    # -----------------------------------------------------------------------
    # Stage 12: Enterprise Posture Aggregation & Forensic Reporting
    # -----------------------------------------------------------------------
    summary, s12_result = stage12_aggregate_enterprise(evidence, sessions, config)

    return summary


# ---------------------------------------------------------------------------
# Individual Stage Implementations
# ---------------------------------------------------------------------------

def stage1_ingest(filepath: str | Path) -> Tuple[List[Any], EvidenceMetadata, StageResult]:
    """
    Stage 1: Evidence Ingestion & Cryptographic Integrity Verification.
    Reads PCAP/PCAPNG evidence, verifies binary magic bytes, validates chain-of-custody,
    computes authoritative SHA-256 integrity hash, and streams packets with tamper verification.
    """
    diagnostics: List[str] = []
    try:
        packets, evidence = ingest_pcap(filepath)
        status = StageStatus.SUCCESS if packets else StageStatus.INCONCLUSIVE
        if not packets:
            diagnostics.append(f"No packets ingested from {filepath}")
        stage_res = StageResult(
            stage_id="stage1_ingestion",
            stage_name="Evidence Ingestion & Integrity",
            status=status,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostics=list(evidence.diagnostics) + diagnostics,
            metadata={
                "evidence_id": evidence.evidence_id,
                "sha256": evidence.sha256_hash,
                "capture_format": evidence.capture_format,
                "is_tamper_free": evidence.is_tamper_free,
                "link_layer_type": evidence.link_layer_type,
                "packet_count": len(packets),
                "file_size": evidence.file_size_bytes,
                "capture_duration": evidence.capture_duration,
            },
        )
        return packets, evidence, stage_res
    except IngestionError as exc:
        err_msg = f"Forensic ingestion error on {filepath}: {exc}"
        diagnostics.append(err_msg)
        stage_res = StageResult(
            stage_id="stage1_ingestion",
            stage_name="Evidence Ingestion & Integrity",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
            metadata={
                "error_type": exc.__class__.__name__,
                "filepath": str(filepath),
            },
        )
        path_obj = Path(filepath) if isinstance(filepath, (str, Path)) else None
        abs_path = str(path_obj.resolve()) if path_obj and path_obj.exists() else str(filepath)
        fallback_ev = EvidenceMetadata(
            filename=path_obj.name if path_obj else "unknown",
            absolute_path=abs_path,
            diagnostics=diagnostics,
        )
        return [], fallback_ev, stage_res
    except Exception as exc:
        err_msg = f"Unexpected ingestion error on {filepath}: {exc}"
        diagnostics.append(err_msg)
        stage_res = StageResult(
            stage_id="stage1_ingestion",
            stage_name="Evidence Ingestion & Integrity",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
            metadata={
                "error_type": exc.__class__.__name__,
                "filepath": str(filepath),
            },
        )
        path_obj = Path(filepath) if isinstance(filepath, (str, Path)) else None
        fallback_ev = EvidenceMetadata(
            filename=path_obj.name if path_obj else "unknown",
            diagnostics=diagnostics,
        )
        return [], fallback_ev, stage_res


def stage2_reassemble(
    packets: List[Any],
    options: ParserOptions,
) -> Tuple[List[TCPStream], StageResult]:
    """
    Stage 2: TCP Flow Reassembly & Directional Demuxing.
    Reconstructs bidirectional application-layer payloads from TCP 5-tuples.

    🔴 Fix 1: Streams with sequence gaps are now marked PARTIAL. Gap metadata
    is attached to each TCPStream and surfaced in StageResult.metadata.
    """
    diagnostics: List[str] = []
    try:
        streams = reassemble(packets, include_all_ports=options.include_all_ports)
        gapped_streams = [s for s in streams if s.has_gaps]
        total_gaps = sum(len(s.sequence_gaps) for s in streams)

        if not streams:
            status = StageStatus.INCONCLUSIVE
            diagnostics.append("No TCP streams matching monitored protocols were identified.")
        elif gapped_streams:
            # 🔴 Fix 1: PARTIAL — streams are present but forensically incomplete
            status = StageStatus.PARTIAL
            for s in gapped_streams:
                gap_sum = sum(g.missing_bytes for g in s.sequence_gaps)
                diagnostics.append(
                    f"Stream {s.stream_id}: {len(s.sequence_gaps)} sequence gap(s), "
                    f"{gap_sum} missing bytes. Downstream parsers must not make "
                    f"high-confidence inferences across these gaps."
                )
        else:
            status = StageStatus.SUCCESS

        stage_res = StageResult(
            stage_id="stage2_reassembly",
            stage_name="TCP Reassembly & Demuxing",
            status=status,
            confidence=ConfidenceLevel.CONFIRMED if not gapped_streams else ConfidenceLevel.MEDIUM,
            diagnostics=diagnostics,
            metadata={
                "stream_count": len(streams),
                "include_all_ports": options.include_all_ports,
                "gapped_stream_count": len(gapped_streams),
                "total_gap_count": total_gaps,
            },
        )
        return streams, stage_res
    except Exception as exc:
        diagnostics.append(f"TCP stream reassembly error: {exc}")
        stage_res = StageResult(
            stage_id="stage2_reassembly",
            stage_name="TCP Reassembly & Demuxing",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return [], stage_res


def stage3_track_starttls(stream: TCPStream) -> Tuple[StarttlsAnalysis, StageResult]:
    """
    Stage 3: Application Protocol & STARTTLS State Machine Tracking.
    Runs order-aware state machine to detect cleartext upgrade or stripping.
    """
    diagnostics: List[str] = []
    try:
        res = analyze_starttls(stream)
        status = (
            StageStatus.INCONCLUSIVE
            if res.starttls_status == StarttlsStatus.INCONCLUSIVE
            else StageStatus.SUCCESS
        )
        stage_res = StageResult(
            stage_id="stage3_starttls",
            stage_name="STARTTLS State Tracking",
            status=status,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostics=[res.details] if res.details else [],
            metadata={
                "status": res.starttls_status.value,
                "channel_type": res.channel_type.value,
                "buffer_injection": res.buffer_injection,
                "bytes_before_tls": res.bytes_before_tls,
            },
        )
        return res, stage_res
    except Exception as exc:
        diagnostics.append(f"STARTTLS tracking error: {exc}")
        fallback = StarttlsAnalysis(
            starttls_status=StarttlsStatus.INCONCLUSIVE,
            channel_type=ChannelType.UNKNOWN,
            details=f"Exception during STARTTLS analysis: {exc}",
        )
        stage_res = StageResult(
            stage_id="stage3_starttls",
            stage_name="STARTTLS State Tracking",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return fallback, stage_res


def stage4_parse_handshake(stream: TCPStream) -> Tuple[HandshakeResult, StageResult]:
    """
    Stage 4: TLS Record Layer & Handshake Parsing.
    Parses ClientHello and ServerHello, extracting cryptographic negotiation parameters.
    """
    diagnostics: List[str] = []
    client_bytes = bytes(stream.client_data)
    server_bytes = bytes(stream.server_data)

    try:
        hs = parse_combined(client_bytes, server_bytes)
        if hs.diagnostics:
            diagnostics.extend(hs.diagnostics)

        # 🔴 Fix 1: Gap warning for TLS framing
        if stream.has_gaps:
            diagnostics.append(
                f"TCP sequence gaps detected ({len(stream.sequence_gaps)} gap(s), "
                f"{sum(g.missing_bytes for g in stream.sequence_gaps)} missing bytes); "
                f"TLS record framing and handshake completeness may be compromised."
            )

        status = StageStatus.SUCCESS
        if hs.handshake_status.startswith("INCONCLUSIVE"):
            status = StageStatus.INCONCLUSIVE
        elif hs.handshake_status == "ALERT_TERMINATED":
            status = StageStatus.PARTIAL
        elif stream.has_gaps:
            status = StageStatus.PARTIAL

        conf = ConfidenceLevel.CONFIRMED if hs.tls_version and not stream.has_gaps else ConfidenceLevel.MEDIUM
        stage_res = StageResult(
            stage_id="stage4_tls_handshake",
            stage_name="TLS Record & Handshake Parsing",
            status=status,
            confidence=conf,
            diagnostics=diagnostics,
            metadata={
                "handshake_status": hs.handshake_status,
                "tls_version": hs.tls_version.value if hs.tls_version else None,
                "cipher_suite": hs.cipher_suite_name,
                "cert_visibility": hs.cert_visibility,
                "pqc_offered": hs.pqc_offered,
                "pqc_negotiated": hs.pqc_negotiated,
                "record_count": len(hs.record_provenance),
                "stream_has_gaps": stream.has_gaps,
            },
        )
        return hs, stage_res
    except Exception as exc:
        diagnostics.append(f"TLS parsing error: {exc}")
        fallback_hs = HandshakeResult(
            handshake_status="INCONCLUSIVE_PARSER_ERROR",
            diagnostics=diagnostics,
        )
        stage_res = StageResult(
            stage_id="stage4_tls_handshake",
            stage_name="TLS Record & Handshake Parsing",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return fallback_hs, stage_res


def stage5_validate_certs(
    hs: HandshakeResult,
) -> Tuple[Optional[CertHealth], List[CertHealth], StageResult]:
    """
    Stage 5: X.509 Certificate Chain Validation & Security Bit Profiling.
    Inspects leaf certificate and certificate chain for cryptographic health.

    🔴 Fix 2: When TLS 1.3 is negotiated but no cert is present (encrypted handshake),
    this stage returns PARTIAL with an explicit note — not SKIPPED.
    🔴 Fix 3: Checks against HANDSHAKE_MESSAGES_COMPLETE (was: COMPLETED).
    """
    diagnostics: List[str] = []
    try:
        leaf_cert = hs.cert
        chain = hs.cert_chain

        if not leaf_cert and not chain:
            # 🔴 Fix 2: Distinguish TLS 1.3 encrypted cert from genuinely missing cert
            if hs.cert_visibility == "ENCRYPTED_TLS13":
                stage_res = StageResult(
                    stage_id="stage5_cert_validation",
                    stage_name="X.509 Certificate Validation",
                    status=StageStatus.PARTIAL,
                    confidence=ConfidenceLevel.LOW,
                    diagnostics=[
                        "TLS 1.3 LIMITATION: Certificate record is encrypted after ServerHello "
                        "and cannot be accessed via passive inspection without session keys "
                        "(SSLKEYLOGFILE / NSS Key Log). Certificate-based compliance findings "
                        "are INCONCLUSIVE for this session. To obtain cert data, provide a "
                        "session key log via the FOXIO_SSLKEYLOG environment variable."
                    ],
                    metadata={"cert_visibility": "ENCRYPTED_TLS13"},
                )
                return None, [], stage_res

            # 🔴 Fix 3: Use HANDSHAKE_MESSAGES_COMPLETE (was: COMPLETED)
            status = (
                StageStatus.SKIPPED
                if hs.handshake_status != "HANDSHAKE_MESSAGES_COMPLETE"
                else StageStatus.INCONCLUSIVE
            )
            stage_res = StageResult(
                stage_id="stage5_cert_validation",
                stage_name="X.509 Certificate Validation",
                status=status,
                confidence=ConfidenceLevel.CONFIRMED,
                diagnostics=["No X.509 certificates presented in this session."],
            )
            return None, [], stage_res

        if leaf_cert and leaf_cert.diagnostics:
            diagnostics.extend(leaf_cert.diagnostics)

        status = StageStatus.SUCCESS
        stage_res = StageResult(
            stage_id="stage5_cert_validation",
            stage_name="X.509 Certificate Validation",
            status=status,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostics=diagnostics,
            metadata={
                "leaf_subject_cn": leaf_cert.subject_cn if leaf_cert else None,
                "validity": leaf_cert.validity.value if leaf_cert else None,
                "key_length_bits": leaf_cert.key_length_bits if leaf_cert else None,
                "chain_length": len(chain),
                "cert_visibility": hs.cert_visibility,
            },
        )
        return leaf_cert, chain, stage_res
    except Exception as exc:
        diagnostics.append(f"Certificate analysis error: {exc}")
        stage_res = StageResult(
            stage_id="stage5_cert_validation",
            stage_name="X.509 Certificate Validation",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return None, [], stage_res


def stage6_fingerprint(
    stream: TCPStream,
    foxio: FoxIOFingerprintIndex,
    hs: Optional[HandshakeResult] = None,
) -> Tuple[Any, StageResult]:
    """
    Stage 6: JA4+ Fingerprinting via FoxIO's official implementation,
    with native Python fallback when FoxIO external runner is unavailable.
    """
    from .models import JA4Fingerprints
    try:
        fingerprints, metadata = build_fingerprints(stream=stream, foxio=foxio)
        status = (
            StageStatus.SUCCESS
            if metadata.get("status") == "MATCHED" or metadata.get("status") == "NO_MATCHING_FOXIO_STREAM"
            else StageStatus.INCONCLUSIVE
        )
        confidence = (
            ConfidenceLevel.CONFIRMED
            if metadata.get("status") == "MATCHED"
            else ConfidenceLevel.LOW
        )
        diagnostics = []
        if metadata.get("status") == "NO_MATCHING_FOXIO_STREAM":
            diagnostics.append("FoxIO completed, but emitted no record matching this normalized session 4-tuple.")
        stage_res = StageResult(
            stage_id="stage6_fingerprinting",
            stage_name="JA4+ Fingerprinting (FoxIO)",
            status=status,
            confidence=confidence,
            diagnostics=diagnostics,
            metadata={
                "ja4": fingerprints.ja4,
                "ja4s": fingerprints.ja4s,
                "ja4x": fingerprints.ja4x,
                **metadata,
            },
        )
        return fingerprints, stage_res
    except Exception as exc:
        stage_res = StageResult(
            stage_id="stage6_fingerprinting",
            stage_name="JA4+ Fingerprinting (FoxIO)",
            status=StageStatus.INCONCLUSIVE,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[f"FoxIO fingerprinting unavailable: {exc}"],
            metadata={"implementation": "FoxIO official JA4+", "status": "UNAVAILABLE"},
        )
        return JA4Fingerprints(), stage_res


def stage7_cross_validate(
    stream: TCPStream,
    st_res: StarttlsAnalysis,
    hs: HandshakeResult,
) -> Tuple[str, List[str], StageResult]:
    """
    Stage 7: Cross-Stage Pipeline Semantic & Boundary Validation.
    Enforces integrity invariants between STARTTLS state, TLS records, and ports:
      - Validates that a session marked PLAINTEXT/STRIPPED does not falsely claim TLS negotiation.
      - Flags STARTTLS command acknowledged without subsequent TLS handshake.
      - Prevents missing evidence from silently defaulting to a secure-looking state.
    """
    warnings: List[str] = []
    status_code = "VALID"

    # Check 1: STARTTLS Cleartext/Stripped vs TLS Handshake presence
    is_cleartext_state = (
        st_res.channel_type == ChannelType.PLAINTEXT
        or st_res.starttls_status in (
            StarttlsStatus.STRIPPED,
            StarttlsStatus.POSSIBLE_STRIPPING,
            StarttlsStatus.FAILED,
            StarttlsStatus.NONE,
        )
    )
    if is_cleartext_state and not stream.is_implicit_tls:
        if hs.tls_version is not None or hs.cipher_suite_name is not None:
            warnings.append(
                "Cross-stage anomaly: STARTTLS tracker classified session as cleartext/stripped, "
                "yet TLS handshake records were extracted. Possible smuggling, protocol desynchronization, "
                "or cleartext command injection."
            )
            status_code = "AMBIGUOUS_CONFLICT"

    # Check 2: STARTTLS Negotiated but TLS Handshake missing
    if st_res.channel_type == ChannelType.STARTTLS and st_res.starttls_status == StarttlsStatus.NEGOTIATED:
        if hs.handshake_status in ("INCONCLUSIVE_NO_HANDSHAKE", "UNKNOWN", "INCONCLUSIVE_CLIENT_HELLO_ONLY"):
            warnings.append(
                "Cross-stage anomaly: STARTTLS upgrade was negotiated, but the subsequent TLS handshake "
                "did not complete or records are missing from capture."
            )
            if status_code == "VALID":
                status_code = "INCONCLUSIVE_HANDSHAKE_MISSING"

    # Check 3: Implicit TLS Port Policy check
    if stream.is_implicit_tls and st_res.channel_type == ChannelType.PLAINTEXT:
        warnings.append(
            f"Port policy violation: Port {stream.dst_port} is reserved for Implicit TLS (RFC 8314) "
            f"but observed traffic consists entirely of cleartext commands."
        )

    # Check 4: Missing Payload / Zero Byte Safeguard
    if stream.packet_count > 0 and stream.byte_count == 0:
        warnings.append("Flow contains TCP control packets but zero application payload bytes.")
        if status_code == "VALID":
            status_code = "INCONCLUSIVE_EMPTY"

    # Check 5: ClientHello only (No Server response)
    if hs.handshake_status == "INCONCLUSIVE_CLIENT_HELLO_ONLY":
        warnings.append(
            "ClientHello was observed offering cryptographic parameters, but no ServerHello response "
            "was captured. Cipher and version cannot be considered negotiated."
        )
        if status_code == "VALID":
            status_code = "INCONCLUSIVE_CLIENT_HELLO_ONLY"

    # 🔴 Fix 1: Check 6 — TCP sequence gaps
    if stream.has_gaps:
        gap_bytes = sum(g.missing_bytes for g in stream.sequence_gaps)
        warnings.append(
            f"TCP sequence gap: {len(stream.sequence_gaps)} gap(s) detected with {gap_bytes} missing byte(s). "
            f"Stream data is incomplete; forensic findings are PARTIAL."
        )
        if status_code == "VALID":
            status_code = "PARTIAL_STREAM_GAPS"

    stage_status = StageStatus.SUCCESS if status_code == "VALID" else StageStatus.PARTIAL
    conf = ConfidenceLevel.CONFIRMED if status_code == "VALID" and not stream.has_gaps else ConfidenceLevel.MEDIUM
    stage_res = StageResult(
        stage_id="stage7_cross_validation",
        stage_name="Cross-Stage Semantic Validation",
        status=stage_status,
        confidence=conf,
        diagnostics=list(warnings),
        metadata={
            "validation_status": status_code,
            "anomaly_count": len(warnings),
            "stream_has_gaps": stream.has_gaps,
            "gap_count": len(stream.sequence_gaps),
        },
    )
    return status_code, warnings, stage_res


def stage8_build_lineage(
    stream: TCPStream,
    st_res: StarttlsAnalysis,
    hs: HandshakeResult,
    leaf_cert: Optional[CertHealth],
    validation_status: str,
    validation_warnings: List[str],
    evidence: Optional[EvidenceMetadata] = None,
) -> Tuple[Dict[str, ForensicFact], StageResult]:
    """
    Stage 8: Forensic Fact & Evidence Lineage Construction.
    Builds explicit ForensicFact instances with complete provenance (stream 5-tuple,
    packet sequence ranges, record offsets, certificate serials, and parser diagnostics).
    """
    facts: Dict[str, ForensicFact] = {}

    # Sequence range calculation across all segments
    all_segs = stream.all_segments
    seq_range: Optional[Tuple[int, int]] = None
    if all_segs:
        min_seq = min(s.seq for s in all_segs)
        max_seq = max(s.seq + len(s.payload) for s in all_segs)
        seq_range = (min_seq, max_seq)

    base_prov = PacketProvenance(
        stream_id=stream.stream_id,
        frame_length=stream.byte_count,
        seq_range=seq_range,
        direction="bidirectional",
    )

    # Fact: Flow 5-tuple
    facts["flow"] = ForensicFact(
        name="flow",
        value=stream.stream_id,
        origin=FactOrigin.OBSERVED,
        provenance=base_prov,
        confidence=ConfidenceLevel.CONFIRMED,
        diagnostic=f"Packets: {stream.packet_count}, Bytes: {stream.byte_count}",
    )

    # Fact: STARTTLS Status
    st_prov = PacketProvenance(
        stream_id=stream.stream_id,
        record_offset=st_res.bytes_before_tls,
        seq_range=seq_range,
        direction="client<->server",
        diagnostic=f"Channel: {st_res.channel_type.value}, STARTTLS: {st_res.starttls_status.value}",
    )
    facts["starttls_status"] = ForensicFact(
        name="starttls_status",
        value=st_res.starttls_status,
        origin=FactOrigin.OBSERVED if st_res.starttls_status != StarttlsStatus.UNKNOWN else FactOrigin.UNKNOWN,
        provenance=st_prov,
        confidence=ConfidenceLevel.CONFIRMED,
        diagnostic=f"Buffer injection: {st_res.buffer_injection}; Pre-TLS bytes: {st_res.bytes_before_tls}",
    )

    # Fact: TLS Version
    rec_offset = hs.record_provenance[0].offset if hs.record_provenance else None
    rec_type = hs.record_provenance[0].content_type if hs.record_provenance else None
    tls_prov = PacketProvenance(
        stream_id=stream.stream_id,
        record_offset=rec_offset,
        tls_record_offset=rec_offset,
        tls_record_type=rec_type,
        seq_range=seq_range,
        diagnostic=f"Handshake status: {hs.handshake_status}",
    )
    facts["tls_version"] = ForensicFact(
        name="tls_version",
        value=hs.tls_version,
        origin=FactOrigin.OBSERVED if hs.tls_version else FactOrigin.UNKNOWN,
        provenance=tls_prov,
        confidence=ConfidenceLevel.CONFIRMED if hs.tls_version else ConfidenceLevel.LOW,
        diagnostic=f"Negotiated version: {hs.tls_version.value if hs.tls_version else 'None'} ({hs.handshake_status})",
    )

    # Fact: Cipher Suite
    facts["cipher_suite"] = ForensicFact(
        name="cipher_suite",
        value=hs.cipher_suite_name,
        origin=FactOrigin.OBSERVED if hs.cipher_suite_name else FactOrigin.UNKNOWN,
        provenance=tls_prov,
        confidence=ConfidenceLevel.CONFIRMED if hs.cipher_suite_name else ConfidenceLevel.LOW,
        diagnostic=f"ID: {hex(hs.cipher_suite_id) if hs.cipher_suite_id else 'None'}; Forward secret: {hs.is_forward_secret}",
    )

    # Fact: Key Exchange
    facts["key_exchange"] = ForensicFact(
        name="key_exchange",
        value=hs.key_exchange,
        origin=FactOrigin.OBSERVED if hs.key_exchange else (
            FactOrigin.INFERRED if hs.cipher_suite_name else FactOrigin.UNKNOWN
        ),
        provenance=tls_prov,
        confidence=ConfidenceLevel.HIGH if hs.key_exchange else ConfidenceLevel.LOW,
        diagnostic=f"Selected group: {hs.selected_group_name or 'None'}",
    )

    # Fact: SNI
    facts["sni"] = ForensicFact(
        name="sni",
        value=hs.sni,
        origin=FactOrigin.OBSERVED if hs.sni else FactOrigin.UNKNOWN,
        provenance=tls_prov,
        confidence=ConfidenceLevel.CONFIRMED if hs.sni else ConfidenceLevel.LOW,
        diagnostic="SNI present in ClientHello" if hs.sni else "SNI missing",
    )

    # Fact: Certificate Health
    has_cert = bool(leaf_cert and (leaf_cert.key_length_bits is not None or leaf_cert.subject_cn))
    cert_prov = PacketProvenance(
        stream_id=stream.stream_id,
        record_offset=rec_offset,
        cert_serial=leaf_cert.serial_number if leaf_cert else None,
        cert_fingerprint=leaf_cert.fingerprint_sha256 if leaf_cert else None,
        diagnostic="; ".join(leaf_cert.diagnostics) if (leaf_cert and leaf_cert.diagnostics) else "",
    )
    facts["cert"] = ForensicFact(
        name="cert",
        value=leaf_cert,
        origin=FactOrigin.OBSERVED if has_cert else FactOrigin.UNKNOWN,
        provenance=cert_prov,
        confidence=ConfidenceLevel.CONFIRMED if has_cert else ConfidenceLevel.LOW,
        diagnostic=f"Validity: {leaf_cert.validity.value if leaf_cert else 'None'}; Key: {leaf_cert.key_length_bits if leaf_cert else 'None'} bits",
    )

    # Fact: PQC Posture (Offered vs Negotiated distinction)
    pqc_desc = (
        "Hybrid PQC Negotiated"
        if hs.pqc_negotiated
        else ("PQC Offered in ClientHello" if hs.pqc_offered else "Classical Only")
    )
    pqc_prov = PacketProvenance(
        stream_id=stream.stream_id,
        diagnostic=f"Offered: {hs.pqc_offered}, Negotiated: {hs.pqc_negotiated}",
    )
    facts["pqc_posture"] = ForensicFact(
        name="pqc_posture",
        value=pqc_desc,
        origin=FactOrigin.OBSERVED if (hs.pqc_offered or hs.pqc_negotiated) else FactOrigin.INFERRED,
        provenance=pqc_prov,
        confidence=ConfidenceLevel.CONFIRMED,
        diagnostic=f"Group: {hs.selected_group_name or 'None'}, Offered count: {len(hs.client_supported_groups)}",
    )

    # Fact: Validation State
    val_prov = PacketProvenance(
        stream_id=stream.stream_id,
        diagnostic="; ".join(validation_warnings) if validation_warnings else "Passed cross-stage validation",
    )
    facts["validation"] = ForensicFact(
        name="validation",
        value=validation_status,
        origin=FactOrigin.INFERRED,
        provenance=val_prov,
        confidence=ConfidenceLevel.HIGH,
        diagnostic="; ".join(validation_warnings) if validation_warnings else "OK",
    )

    # Fact: Ingested Evidence Chain of Custody
    if evidence and evidence.evidence_id:
        ev_prov = PacketProvenance(
            stream_id=stream.stream_id,
            diagnostic=f"Evidence ID: {evidence.evidence_id}",
        )
        facts["evidence"] = ForensicFact(
            name="evidence",
            value=evidence.evidence_id,
            origin=FactOrigin.OBSERVED,
            provenance=ev_prov,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostic=(
                f"SHA-256: {evidence.sha256_hash}; "
                f"Format: {evidence.capture_format}; "
                f"Tamper-free: {evidence.is_tamper_free}"
            ),
        )

    stage_res = StageResult(
        stage_id="stage8_provenance",
        stage_name="Evidence Lineage & Provenance",
        status=StageStatus.SUCCESS,
        confidence=ConfidenceLevel.CONFIRMED,
        metadata={"fact_count": len(facts)},
    )
    return facts, stage_res


def stage9_evaluate_rules(
    session: SessionAnalysis,
    config: AnalysisConfig,
) -> Tuple[List[Violation], StageResult]:
    """
    Stage 9: Deterministic Compliance & Rule Engine Evaluation.
    Evaluates session against NIST SP 800-52r2, RFC 9325, and RFC 8314 policies.
    Enriches finding evidence with provenance pointers back to raw stream and offsets.
    """
    diagnostics: List[str] = []
    try:
        # 🔴 Fix 5: Pass the actual configured PolicyCatalog (not DEFAULT_POLICY_CATALOG implicitly)
        violations = run_rules(session, policy=config.policy_catalog)

        # Enrich violations with provenance lineage
        for v in violations:
            if hasattr(v, "evidence") and isinstance(v.evidence, dict):
                v.evidence["stream_id"] = session.flow_id
                v.evidence["session_id"] = session.session_id
                v.evidence["packet_count"] = session.packet_count
                v.evidence["byte_count"] = session.byte_count
                if session.bytes_pre_tls > 0:
                    v.evidence["bytes_pre_tls"] = session.bytes_pre_tls
                if session.cert and session.cert.serial_number:
                    v.evidence["cert_serial"] = session.cert.serial_number
                if session.tls_diagnostics:
                    v.evidence["tls_diagnostics"] = list(session.tls_diagnostics)

        stage_res = StageResult(
            stage_id="stage9_rules",
            stage_name="Deterministic Compliance Engine",
            status=StageStatus.SUCCESS,
            confidence=ConfidenceLevel.CONFIRMED,
            metadata={
                "policy_id": config.rule_policy_id,
                "policy_version": config.rule_policy_version,
                "policy_catalog_hash": config.policy_catalog_hash,
                "violation_count": len(violations),
            },
        )
        return violations, stage_res
    except Exception as exc:
        diagnostics.append(f"Rule evaluation error: {exc}")
        stage_res = StageResult(
            stage_id="stage9_rules",
            stage_name="Deterministic Compliance Engine",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return [], stage_res


def stage10_score_session(
    session: SessionAnalysis,
    config: AnalysisConfig,
) -> Tuple[SessionAnalysis, StageResult]:
    """
    Stage 10: Cryptographic Posture Scoring & Risk Tiering.
    Calculates weighted domain scores and critical caps, attaching structured explanations.
    """
    diagnostics: List[str] = []
    try:
        # If cross-validation detected a fatal mismatch or empty capture, enforce inconclusive posture
        if session.validation_status == "AMBIGUOUS_CONFLICT":
            session.tls_diagnostics.append(
                "Cross-stage conflict detected: plaintext state conflicting with TLS records."
            )
        elif session.validation_status in ("INCONCLUSIVE_EMPTY", "INCONCLUSIVE_HANDSHAKE_MISSING"):
            session.tls_diagnostics.append(
                f"Missing evidence detected: {session.validation_status}"
            )

        session = score_session(session, policy=config.scoring_policy)

        # Enrich scoring explanation with evidence lineage
        if session.scoring_explanation and isinstance(session.scoring_explanation, dict):
            session.scoring_explanation["flow_id"] = session.flow_id
            session.scoring_explanation["session_id"] = session.session_id
            session.scoring_explanation["validation_status"] = session.validation_status
            session.scoring_explanation["evidence_lineage"] = {
                k: v.to_dict() if hasattr(v, "to_dict") else v
                for k, v in session.facts.items()
            }

        stage_res = StageResult(
            stage_id="stage10_scoring",
            stage_name="Posture Scoring & Risk Tiering",
            status=StageStatus.SUCCESS,
            confidence=ConfidenceLevel.CONFIRMED,
            metadata={
                "posture_score": session.posture_score,
                "risk_tier": session.risk_tier.value,
                "scoring_policy_id": session.scoring_policy_id,
                "scoring_policy_version": session.scoring_policy_version,
            },
        )
        return session, stage_res
    except Exception as exc:
        diagnostics.append(f"Scoring error: {exc}")
        session.posture_score = 0.0
        session.risk_tier = RiskTier.CRITICAL
        session.confidence = "LOW"
        stage_res = StageResult(
            stage_id="stage10_scoring",
            stage_name="Posture Scoring & Risk Tiering",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return session, stage_res


def stage11_ml_anomaly(
    sessions: List[SessionAnalysis],
    config: AnalysisConfig,
) -> Tuple[List[SessionAnalysis], StageResult]:
    """
    Stage 11: Machine Learning Anomaly Detection (Optional & Strictly Isolated).
    Unsupervised Isolation Forest flags statistical outlier sessions.
    Crucially, ML findings NEVER alter the authoritative deterministic compliance
    or posture score results.
    """
    diagnostics: List[str] = []

    if not config.ml_settings.enabled:
        for s in sessions:
            s.anomaly_status = "SKIPPED"
        stage_res = StageResult(
            stage_id="stage11_ml_anomaly",
            stage_name="Isolation Forest Anomaly Detection",
            status=StageStatus.SKIPPED,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostics=["ML anomaly detection disabled in AnalysisConfig."],
        )
        return sessions, stage_res

    min_baseline = config.ml_settings.min_baseline_sessions
    if len(sessions) < min_baseline:
        for s in sessions:
            s.is_anomalous = False
            s.anomaly_score = None
            s.anomaly_status = "INSUFFICIENT_BASELINE"
            s.anomaly_features = {}
        stage_res = StageResult(
            stage_id="stage11_ml_anomaly",
            stage_name="Isolation Forest Anomaly Detection",
            status=StageStatus.INCONCLUSIVE,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[
                f"Insufficient baseline: capture contains {len(sessions)} session(s), below the minimum "
                f"required baseline threshold ({min_baseline}) for capture-relative statistical clustering."
            ],
            metadata={
                "sessions_evaluated": len(sessions),
                "min_baseline_sessions": min_baseline,
                "anomalies_detected": 0,
                "status": "INSUFFICIENT_BASELINE",
            },
        )
        return sessions, stage_res

    try:
        updated_sessions = run_anomaly_detection(sessions, settings=config.ml_settings)
        anomalous_count = sum(1 for s in updated_sessions if s.is_anomalous)
        stage_res = StageResult(
            stage_id="stage11_ml_anomaly",
            stage_name="Isolation Forest Anomaly Detection",
            status=StageStatus.SUCCESS,
            confidence=ConfidenceLevel.CONFIRMED,
            diagnostics=[
                "Secondary unsupervised outlier detection evaluated relative to current capture population. "
                "Deterministic compliance rules remain authoritative."
            ],
            metadata={
                "model_family": "IsolationForest",
                "scoring_formula": "Liu et al. (ICDM 2008) s(x, n) = 2^(-E(h(x))/c(n))",
                "feature_version": config.ml_settings.feature_version,
                "n_estimators": config.ml_settings.n_estimators,
                "contamination": config.ml_settings.contamination,
                "anomaly_threshold": config.ml_settings.anomaly_threshold,
                "min_baseline_sessions": min_baseline,
                "baseline_mode": "capture_relative",
                "sessions_evaluated": len(sessions),
                "anomalies_detected": anomalous_count,
                "random_state": config.ml_settings.random_state,
            },
        )
        return updated_sessions, stage_res
    except Exception as exc:
        diagnostics.append(f"ML anomaly detection isolated failure: {exc}")
        for s in sessions:
            s.anomaly_status = "ERROR"
        # Return untouched sessions so deterministic results remain pristine
        stage_res = StageResult(
            stage_id="stage11_ml_anomaly",
            stage_name="Isolation Forest Anomaly Detection",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return sessions, stage_res


def stage12_aggregate_enterprise(
    evidence: EvidenceMetadata,
    sessions: List[SessionAnalysis],
    config: AnalysisConfig,
) -> Tuple[EnterpriseSummary, StageResult]:
    """
    Stage 12: Enterprise Posture Aggregation & Forensic Reporting.
    Aggregates session risk tiers, computes enterprise posture index, and binds AnalysisConfig.
    """
    diagnostics: List[str] = []
    try:
        summary = EnterpriseSummary(
            evidence=evidence,
            sessions=sessions,
            analysis_config=config.to_dict(),
        )
        # 🔴 Fix 5: Pass the configured scoring policy
        summary = compute_enterprise_index(summary, policy=config.scoring_policy)

        stage_res = StageResult(
            stage_id="stage12_enterprise",
            stage_name="Enterprise Posture Aggregation",
            status=StageStatus.SUCCESS,
            confidence=ConfidenceLevel.CONFIRMED,
            metadata={
                "enterprise_posture_index": summary.enterprise_posture_index,
                "overall_risk_tier": summary.overall_risk_tier.value,
                "session_count": len(sessions),
                "scoring_policy_id": summary.scoring_policy_id,
                "scoring_policy_version": summary.scoring_policy_version,
                "scoring_policy_hash": config.scoring_policy_hash,
            },
        )
        return summary, stage_res
    except Exception as exc:
        diagnostics.append(f"Enterprise aggregation error: {exc}")
        fallback_summary = EnterpriseSummary(
            evidence=evidence,
            sessions=sessions,
            enterprise_posture_index=0.0,
            overall_risk_tier=RiskTier.CRITICAL,
            analysis_config=config.to_dict(),
        )
        stage_res = StageResult(
            stage_id="stage12_enterprise",
            stage_name="Enterprise Posture Aggregation",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=diagnostics,
        )
        return fallback_summary, stage_res


# ---------------------------------------------------------------------------
# Per-Session Analysis Coordinator
# ---------------------------------------------------------------------------

def _analyze_stream(
    stream: TCPStream,
    config: AnalysisConfig,
    evidence: Optional[EvidenceMetadata] = None,
    foxio: Optional[FoxIOFingerprintIndex] = None,
) -> SessionAnalysis:
    """
    Executes stages 3 through 10 on a single reassembled TCP stream.
    Builds the SessionAnalysis immutably from stage results rather than
    random ad-hoc mutations.
    """
    # 1. Deterministic session identifier from canonical flow 5-tuple and content length
    flow_hash = hashlib.sha256(
        f"{stream.stream_id}:{stream.packet_count}:{stream.byte_count}".encode()
    ).hexdigest()[:12]
    session_id = f"sess_{flow_hash}"

    stage_results: Dict[str, StageResult] = {}

    # Stage 3: STARTTLS State Tracking
    try:
        st_res, s3_result = stage3_track_starttls(stream)
    except Exception as exc:
        st_res = StarttlsAnalysis(
            starttls_status=StarttlsStatus.INCONCLUSIVE,
            channel_type=ChannelType.UNKNOWN,
            details=f"Stage 3 error: {exc}",
        )
        s3_result = StageResult(
            stage_id="stage3_starttls",
            stage_name="STARTTLS State Tracking",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage3_starttls"] = s3_result

    # Stage 4: TLS Record Layer & Handshake Parsing
    try:
        hs, s4_result = stage4_parse_handshake(stream)
    except Exception as exc:
        hs = HandshakeResult(
            handshake_status="INCONCLUSIVE_PARSER_ERROR",
            diagnostics=[str(exc)],
        )
        s4_result = StageResult(
            stage_id="stage4_tls_handshake",
            stage_name="TLS Record & Handshake Parsing",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage4_tls_handshake"] = s4_result

    # Stage 5: Certificate Validation
    try:
        leaf_cert, cert_chain, s5_result = stage5_validate_certs(hs)
    except Exception as exc:
        leaf_cert, cert_chain = None, []
        s5_result = StageResult(
            stage_id="stage5_cert_validation",
            stage_name="X.509 Certificate Validation",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage5_cert_validation"] = s5_result

    # Stage 6: JA4+ Fingerprints via FoxIO
    try:
        if foxio is None:
            foxio = FoxIOFingerprintIndex.from_environment(evidence.absolute_path if evidence else "")
        fingerprints, s6_result = stage6_fingerprint(stream, foxio, hs=hs)
    except Exception as exc:
        from .models import JA4Fingerprints
        fingerprints = JA4Fingerprints()
        s6_result = StageResult(
            stage_id="stage6_fingerprinting",
            stage_name="JA4+ Fingerprinting",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage6_fingerprinting"] = s6_result

    # Determine channel type
    channel_type = st_res.channel_type
    if stream.is_implicit_tls and hs.tls_version:
        channel_type = ChannelType.IMPLICIT_TLS

    # Stage 7: Cross-Stage Pipeline Semantic Validation
    try:
        val_status, val_warnings, s7_result = stage7_cross_validate(stream, st_res, hs)
    except Exception as exc:
        val_status, val_warnings = "INCONCLUSIVE_VALIDATION_ERROR", [str(exc)]
        s7_result = StageResult(
            stage_id="stage7_cross_validation",
            stage_name="Cross-Stage Semantic Validation",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage7_cross_validation"] = s7_result

    # Stage 8: Forensic Fact & Evidence Lineage Construction
    try:
        facts, s8_result = stage8_build_lineage(
            stream=stream,
            st_res=st_res,
            hs=hs,
            leaf_cert=leaf_cert,
            validation_status=val_status,
            validation_warnings=val_warnings,
            evidence=evidence,
        )
    except Exception as exc:
        facts = {}
        s8_result = StageResult(
            stage_id="stage8_provenance",
            stage_name="Evidence Lineage & Provenance",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    stage_results["stage8_provenance"] = s8_result

    # Accurate PQC state assignment: 0=Classical, 1=Offered, 2=Negotiated
    if hs.pqc_negotiated:
        pqc_state = 2
        pqc_ready_feat = 1.0
    elif hs.pqc_offered:
        pqc_state = 1
        pqc_ready_feat = 0.5
    else:
        pqc_state = 0
        pqc_ready_feat = 0.0

    anomaly_features = {}
    if pqc_ready_feat > 0.0:
        anomaly_features["pqc_ready"] = pqc_ready_feat

    # Construct the SessionAnalysis structured object
    session = SessionAnalysis(
        session_id                  = session_id,
        evidence_id                 = evidence.evidence_id if evidence else "",
        evidence_hash               = evidence.sha256_hash if evidence else "",
        flow_id                     = stream.stream_id,
        src_ip                      = stream.src_ip,
        dst_ip                      = stream.dst_ip,
        src_port                    = stream.src_port,
        dst_port                    = stream.dst_port,
        protocol                    = stream.protocol,
        channel_type                = channel_type,
        starttls_status             = st_res.starttls_status,
        tls_version                 = hs.tls_version,
        cipher_suite                = hs.cipher_suite_name,
        key_exchange                = hs.key_exchange,
        sni                         = hs.sni,
        sni_present                 = bool(hs.sni),
        cert                        = leaf_cert or CertHealth(),
        cert_chain                  = cert_chain,
        tls_diagnostics             = list(hs.diagnostics),
        handshake_status            = hs.handshake_status,
        fingerprints                = fingerprints,
        buffer_injection_detected   = st_res.buffer_injection,
        cmd_inject_flag             = st_res.buffer_injection,
        bytes_pre_tls               = st_res.bytes_before_tls,
        pqc_state                   = pqc_state,
        pqc_offered                 = hs.pqc_offered,
        pqc_negotiated              = hs.pqc_negotiated,
        packet_count                = stream.packet_count,
        byte_count                  = stream.byte_count,
        stream_has_gaps             = stream.has_gaps,
        stream_gap_count            = len(stream.sequence_gaps),
        stream_gap_details          = [g.to_dict() for g in stream.sequence_gaps],
        cert_visibility             = hs.cert_visibility,
        validation_status           = val_status,
        validation_warnings         = list(val_warnings),
        facts                       = facts,
        anomaly_features            = anomaly_features,
        stage_results               = stage_results,
    )

    # Stage 9: Deterministic Compliance & Rule Engine Evaluation
    try:
        violations, s9_result = stage9_evaluate_rules(session, config)
    except Exception as exc:
        violations = []
        s9_result = StageResult(
            stage_id="stage9_rules",
            stage_name="Deterministic Compliance Engine",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    session.violations = violations
    session.stage_results["stage9_rules"] = s9_result

    # Stage 10: Cryptographic Posture Scoring & Risk Tiering
    try:
        session, s10_result = stage10_score_session(session, config)
    except Exception as exc:
        session.posture_score = 0.0
        session.risk_tier = RiskTier.CRITICAL
        session.confidence = "LOW"
        s10_result = StageResult(
            stage_id="stage10_scoring",
            stage_name="Posture Scoring & Risk Tiering",
            status=StageStatus.ERROR,
            confidence=ConfidenceLevel.LOW,
            diagnostics=[str(exc)],
        )
    session.stage_results["stage10_scoring"] = s10_result

    return session


def _build_fallback_session(
    stream: TCPStream,
    exc: Exception,
    evidence: Optional[EvidenceMetadata] = None,
) -> SessionAnalysis:
    """Fallback generator when unexpected error occurs during stream analysis."""
    flow_hash = hashlib.sha256(stream.stream_id.encode()).hexdigest()[:12]
    fallback = SessionAnalysis(
        session_id=f"sess_{flow_hash}",
        evidence_id=evidence.evidence_id if evidence else "",
        evidence_hash=evidence.sha256_hash if evidence else "",
        flow_id=stream.stream_id,
        src_ip=stream.src_ip,
        dst_ip=stream.dst_ip,
        src_port=stream.src_port,
        dst_port=stream.dst_port,
        protocol=stream.protocol,
        packet_count=stream.packet_count,
        byte_count=stream.byte_count,
        validation_status="ERROR",
        validation_warnings=[f"Orchestration failure on stream {stream.stream_id}: {exc}"],
        tls_diagnostics=[traceback.format_exc()],
        posture_score=0.0,
        risk_tier=RiskTier.CRITICAL,
        confidence="LOW",
    )
    fallback.stage_results["orchestration_error"] = StageResult(
        stage_id="orchestration_error",
        stage_name="Orchestrator Fallback",
        status=StageStatus.ERROR,
        confidence=ConfidenceLevel.LOW,
        diagnostics=[str(exc)],
    )
    return fallback

