"""
core/models.py
Data structures and schemas for the AI-Assisted Passive Network Forensic Framework.
Implements the session feature schema from §10 of the PRD.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar

# ---------------------------------------------------------------------------
# Versioning & Forensic Constants
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "1.1.0"
FORENSIC_ENGINE_VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FactOrigin(str, Enum):
    OBSERVED = "OBSERVED"   # Directly parsed from packet or payload bytes
    INFERRED = "INFERRED"   # Derived from heuristics, port context, or partial indicators
    UNKNOWN  = "UNKNOWN"    # Unmeasured, unobserved, or missing from capture


class KeyAlgorithm(str, Enum):
    RSA     = "RSA"
    ECDSA   = "ECDSA"
    ED25519 = "Ed25519"
    ED448   = "Ed448"
    DSA     = "DSA"
    UNKNOWN = "Unknown"


class Protocol(str, Enum):
    SMTP  = "SMTP"
    IMAP  = "IMAP"
    POP3  = "POP3"
    UNKNOWN = "UNKNOWN"


class ChannelType(str, Enum):
    IMPLICIT_TLS = "Implicit TLS"
    STARTTLS     = "STARTTLS"
    PLAINTEXT    = "Plaintext"
    UNKNOWN      = "Unknown"


class StarttlsStatus(str, Enum):
    NONE               = "None"
    ADVERTISED         = "Advertised"
    REQUESTED          = "Requested"
    NEGOTIATED         = "Negotiated"
    FAILED             = "Failed"
    STRIPPED           = "Stripped"
    POSSIBLE_STRIPPING = "Possible Stripping"
    INCONCLUSIVE       = "Inconclusive"
    UNKNOWN            = "Unknown"


class TLSVersion(str, Enum):
    SSLv2   = "SSLv2"
    SSLv3   = "SSLv3"
    TLS10   = "TLS1.0"
    TLS11   = "TLS1.1"
    TLS12   = "TLS1.2"
    TLS13   = "TLS1.3"
    UNKNOWN = "Unknown"


class KeyExchange(str, Enum):
    RSA    = "RSA"
    DHE    = "DHE"
    ECDHE  = "ECDHE"
    UNKNOWN = "Unknown"


class CertValidity(str, Enum):
    VALID         = "Valid"
    EXPIRED       = "Expired"
    NOT_YET_VALID = "NotYetValid"
    SELF_SIGNED   = "SelfSigned"
    UNKNOWN       = "Unknown"


class RiskTier(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    VIOLATION      = "VIOLATION"
    PASS           = "PASS"
    NOT_EVALUATED  = "NOT_EVALUATED"
    INCONCLUSIVE   = "INCONCLUSIVE"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"


class AssessmentStatus(str, Enum):
    PASS           = "PASS"
    DEGRADED       = "DEGRADED"
    VIOLATION      = "VIOLATION"
    INCONCLUSIVE   = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StageStatus(str, Enum):
    SUCCESS      = "SUCCESS"
    PARTIAL      = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR        = "ERROR"
    SKIPPED      = "SKIPPED"


T = TypeVar("T")


@dataclass
class PacketProvenance:
    """Forensic evidence location and packet/record boundary reference."""
    packet_index: Optional[int] = None
    stream_id: Optional[str] = None
    record_offset: Optional[int] = None
    timestamp: Optional[float] = None
    frame_length: Optional[int] = None
    diagnostic: str = ""
    seq_range: Optional[tuple[int, int]] = None
    direction: Optional[str] = None
    tls_record_offset: Optional[int] = None
    tls_record_type: Optional[int] = None
    cert_serial: Optional[str] = None
    cert_fingerprint: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "packet_index": self.packet_index,
            "stream_id": self.stream_id,
            "record_offset": self.record_offset,
            "timestamp": self.timestamp,
            "frame_length": self.frame_length,
            "diagnostic": self.diagnostic,
            "seq_range": list(self.seq_range) if self.seq_range else None,
            "direction": self.direction,
            "tls_record_offset": self.tls_record_offset,
            "tls_record_type": self.tls_record_type,
            "cert_serial": self.cert_serial,
            "cert_fingerprint": self.cert_fingerprint,
        }


@dataclass
class ForensicFact(Generic[T]):
    """
    Forensic observation wrapper with explicit origin, confidence, and provenance.
    Distinguishes observed values from inferred heuristics, and unknown (missing)
    from 0 or negative measurements.
    """
    name: str
    value: Optional[T] = None
    origin: FactOrigin = FactOrigin.UNKNOWN
    provenance: Optional[PacketProvenance] = None
    confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED
    diagnostic: str = ""

    def to_dict(self) -> dict:
        val = self.value
        if hasattr(val, "to_dict"):
            val_serialized = val.to_dict()
        elif hasattr(val, "value"):
            val_serialized = val.value
        else:
            val_serialized = val

        return {
            "name": self.name,
            "value": val_serialized,
            "origin": self.origin.value if isinstance(self.origin, FactOrigin) else str(self.origin),
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "diagnostic": self.diagnostic,
        }


@dataclass
class PublicKeyProfile:
    """
    Key-type-aware public key representation with NIST SP 800-57 security bit mapping.
    Prevents false equivalences (e.g. EC 256 bits vs RSA 2048 bits).
    """
    algorithm: KeyAlgorithm = KeyAlgorithm.UNKNOWN
    raw_key_length: Optional[int] = None
    curve_name: Optional[str] = None
    effective_security_bits: Optional[int] = None
    nist_compliant: bool = False
    assessment: AssessmentStatus = AssessmentStatus.INCONCLUSIVE
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm.value if isinstance(self.algorithm, KeyAlgorithm) else str(self.algorithm),
            "raw_key_length": self.raw_key_length,
            "curve_name": self.curve_name,
            "effective_security_bits": self.effective_security_bits,
            "nist_compliant": self.nist_compliant,
            "assessment": self.assessment.value if isinstance(self.assessment, AssessmentStatus) else str(self.assessment),
            "notes": self.notes,
        }

    @classmethod
    def compute(
        cls,
        key_type: Optional[str],
        key_length: Optional[int],
        curve_name: Optional[str] = None,
    ) -> PublicKeyProfile:
        """
        Derive effective cryptographic security bits under NIST SP 800-57 Part 1 Rev. 5 Table 2.
        """
        k_type = (key_type or "").upper().strip()
        curve = (curve_name or "").lower().strip()

        # Handle Ed25519 / Ed448
        if "ED25519" in k_type or curve in ("ed25519", "curve25519"):
            return cls(
                algorithm=KeyAlgorithm.ED25519,
                raw_key_length=256,
                curve_name=curve_name or "Ed25519",
                effective_security_bits=128,
                nist_compliant=True,
                assessment=AssessmentStatus.PASS,
                notes="Ed25519 Edwards-curve provides 128-bit security strength (RFC 8032 / NIST SP 800-186).",
            )
        if "ED448" in k_type or curve in ("ed448", "curve448"):
            return cls(
                algorithm=KeyAlgorithm.ED448,
                raw_key_length=448,
                curve_name=curve_name or "Ed448",
                effective_security_bits=224,
                nist_compliant=True,
                assessment=AssessmentStatus.PASS,
                notes="Ed448 Edwards-curve provides 224-bit security strength (RFC 8032 / NIST SP 800-186).",
            )

        # Handle EC / ECDSA
        if "EC" in k_type or "ECDSA" in k_type:
            raw_len = key_length
            if raw_len is None:
                if "521" in curve:
                    raw_len = 521
                elif "384" in curve:
                    raw_len = 384
                elif "256" in curve:
                    raw_len = 256
                elif "224" in curve:
                    raw_len = 224

            if raw_len is not None:
                if raw_len >= 512:
                    sec_bits = 256
                elif raw_len >= 384:
                    sec_bits = 192
                elif raw_len >= 256:
                    sec_bits = 128
                elif raw_len >= 224:
                    sec_bits = 112
                else:
                    sec_bits = 80

                is_compliant = sec_bits >= 112
                if sec_bits >= 128:
                    assessment = AssessmentStatus.PASS
                    notes = f"ECDSA {curve_name or raw_len} provides {sec_bits}-bit security strength (NIST SP 800-57 compliant)."
                elif sec_bits >= 112:
                    assessment = AssessmentStatus.DEGRADED
                    notes = f"ECDSA {curve_name or raw_len} provides 112-bit security strength (legacy acceptable through 2030)."
                else:
                    assessment = AssessmentStatus.VIOLATION
                    notes = f"ECDSA {curve_name or raw_len} provides only {sec_bits}-bit security strength (< 112 bits; disallowed by NIST SP 800-57)."

                return cls(
                    algorithm=KeyAlgorithm.ECDSA,
                    raw_key_length=raw_len,
                    curve_name=curve_name,
                    effective_security_bits=sec_bits,
                    nist_compliant=is_compliant,
                    assessment=assessment,
                    notes=notes,
                )

        # Handle DSA
        if "DSA" in k_type:
            raw_len = key_length or 1024
            if raw_len >= 2048:
                sec_bits = 112
                is_compliant = True
                assessment = AssessmentStatus.DEGRADED
                notes = f"DSA {raw_len} provides 112-bit security strength (legacy acceptable)."
            else:
                sec_bits = 80
                is_compliant = False
                assessment = AssessmentStatus.VIOLATION
                notes = f"DSA {raw_len} provides only 80-bit security strength (< 112 bits; disallowed by NIST SP 800-57)."

            return cls(
                algorithm=KeyAlgorithm.DSA,
                raw_key_length=raw_len,
                effective_security_bits=sec_bits,
                nist_compliant=is_compliant,
                assessment=assessment,
                notes=notes,
            )

        # Handle RSA (default asymmetric key type if raw key length > 512, or if explicitly RSA)
        if "RSA" in k_type or (key_length is not None and key_length > 512):
            raw_len = key_length or 2048
            if raw_len >= 15360:
                sec_bits = 256
            elif raw_len >= 7680:
                sec_bits = 192
            elif raw_len >= 4096:
                sec_bits = 152
            elif raw_len >= 3072:
                sec_bits = 128
            elif raw_len >= 2048:
                sec_bits = 112
            elif raw_len >= 1024:
                sec_bits = 80
            else:
                sec_bits = 64

            is_compliant = sec_bits >= 112
            if sec_bits >= 128:
                assessment = AssessmentStatus.PASS
                notes = f"RSA {raw_len} provides {sec_bits}-bit security strength (NIST SP 800-57 compliant)."
            elif sec_bits >= 112:
                assessment = AssessmentStatus.DEGRADED
                notes = f"RSA {raw_len} provides 112-bit security strength (acceptable through 2030 under NIST SP 800-57)."
            else:
                assessment = AssessmentStatus.VIOLATION
                notes = f"RSA {raw_len} provides only {sec_bits}-bit security strength (< 112 bits; disallowed by NIST SP 800-57)."

            return cls(
                algorithm=KeyAlgorithm.RSA,
                raw_key_length=raw_len,
                effective_security_bits=sec_bits,
                nist_compliant=is_compliant,
                assessment=assessment,
                notes=notes,
            )

        # Default fallback for unobserved / unknown key parameters
        return cls(
            algorithm=KeyAlgorithm.UNKNOWN,
            raw_key_length=key_length,
            curve_name=curve_name,
            effective_security_bits=None,
            nist_compliant=False,
            assessment=AssessmentStatus.INCONCLUSIVE,
            notes="Key parameters not observed or unknown.",
        )


@dataclass
class ComponentExplanation:
    """Detailed evidence-aware assessment and score explanation for a single dimension."""
    component: str
    observed: str
    assessment: AssessmentStatus
    component_score: float
    weight: float
    contribution: float
    reason: str
    references: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    effective_weight: Optional[float] = None
    effective_contribution: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "observed": self.observed,
            "assessment": self.assessment.value if isinstance(self.assessment, AssessmentStatus) else str(self.assessment),
            "component_score": round(self.component_score, 2),
            "weight": round(self.weight, 4),
            "effective_weight": round(self.effective_weight, 4) if self.effective_weight is not None else round(self.weight, 4),
            "contribution": round(self.contribution, 2),
            "effective_contribution": round(self.effective_contribution, 2) if self.effective_contribution is not None else round(self.contribution, 2),
            "reason": self.reason,
            "references": list(self.references),
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
        }


@dataclass
class CriticalCapApplied:
    """Record of a critical security finding imposing a ceiling on posture score."""
    finding: str
    cap_value: float
    reason: str
    reference: str = ""
    observed: str = ""

    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "cap_value": round(self.cap_value, 2),
            "reason": self.reason,
            "reference": self.reference,
            "observed": self.observed,
        }


@dataclass
class ScoreExplanation:
    """Comprehensive structured explanation for the session posture score."""
    policy_id: str = "crypto-posture-v1"
    policy_version: str = "1.0"
    quality_score: float = 0.0          # Raw weighted sum (may include INCONCLUSIVE zero contributions)
    final_score: float = 0.0            # After critical caps
    risk_tier: str = "CRITICAL"
    overall_confidence: str = "HIGH"
    components: list[ComponentExplanation] = field(default_factory=list)
    critical_caps_applied: list[CriticalCapApplied] = field(default_factory=list)
    summary: str = ""

    # 🔴 Fix 4: Evidence-aware renormalization fields
    renormalized_quality_score: float = 0.0    # Score over assessed dimensions only (PASS/DEGRADED/VIOLATION)
    evidence_completeness_ratio: float = 1.0   # Fraction of weight that was actually assessed
    assessed_component_count: int = 6          # How many components had definitive assessments
    evidence_note: str = ""                    # Human-readable note on evidence gaps

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "quality_score": round(self.quality_score, 2),
            "renormalized_quality_score": round(self.renormalized_quality_score, 2),
            "evidence_completeness_ratio": round(self.evidence_completeness_ratio, 4),
            "assessed_component_count": self.assessed_component_count,
            "evidence_note": self.evidence_note,
            "final_score": round(self.final_score, 2),
            "risk_tier": self.risk_tier,
            "overall_confidence": self.overall_confidence,
            "components": [c.to_dict() for c in self.components],
            "critical_caps_applied": [cap.to_dict() for cap in self.critical_caps_applied],
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Stage Execution & Orchestration Results
# ---------------------------------------------------------------------------

@dataclass
class StageResult:
    """Structured intermediate result for an individual pipeline execution stage."""
    stage_id: str
    stage_name: str
    status: StageStatus = StageStatus.SUCCESS
    confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED
    diagnostics: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "status": self.status.value if isinstance(self.status, StageStatus) else str(self.status),
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "diagnostics": list(self.diagnostics),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Forensic Analysis Policy & Configuration
# ---------------------------------------------------------------------------

@dataclass
class ParserOptions:
    """Configurable options for PCAP ingestion and stream reassembly."""
    include_all_ports: bool = False
    max_stream_bytes: int = 50_000_000
    extract_certificates: bool = True
    validate_sni: bool = True

    def to_dict(self) -> dict:
        return {
            "include_all_ports": self.include_all_ports,
            "max_stream_bytes": self.max_stream_bytes,
            "extract_certificates": self.extract_certificates,
            "validate_sni": self.validate_sni,
        }


@dataclass
class MLSettings:
    """Isolation Forest and anomaly detection options."""
    enabled: bool = True
    anomaly_threshold: float = 0.65
    contamination: float = 0.05
    n_estimators: int = 100
    random_state: int = 42
    min_baseline_sessions: int = 5
    feature_version: str = "v2-raw-observable"

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "anomaly_threshold": self.anomaly_threshold,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "min_baseline_sessions": self.min_baseline_sessions,
            "feature_version": self.feature_version,
        }


@dataclass
class AnalysisConfig:
    """Forensic analysis configuration and policy specification."""
    config_id: str = "default-forensic-v1"
    scoring_policy_id: str = "crypto-posture-v1"
    scoring_policy_version: str = "1.0"
    rule_policy_id: str = "nist-bcp-forensic-v1"
    rule_policy_version: str = "1.2.0"
    parser_options: ParserOptions = field(default_factory=ParserOptions)
    ml_settings: MLSettings = field(default_factory=MLSettings)
    engine_version: str = FORENSIC_ENGINE_VERSION
    schema_version: str = SCHEMA_VERSION

    # 🔴 Fix 5: Actual policy objects — wire these through all stage calls
    # Typed as Optional[Any] to avoid circular imports (rule_engine / scorer
    # import from models, so we cannot import them here).
    # Populated by pipeline.py after importing those modules.
    policy_catalog: Optional[Any] = field(default=None, repr=False)
    scoring_policy: Optional[Any] = field(default=None, repr=False)

    # Reproducibility hashes — SHA-256 of serialized policy JSON
    policy_catalog_hash: Optional[str] = None
    scoring_policy_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "config_id": self.config_id,
            "scoring_policy_id": self.scoring_policy_id,
            "scoring_policy_version": self.scoring_policy_version,
            "scoring_policy_hash": self.scoring_policy_hash,
            "rule_policy_id": self.rule_policy_id,
            "rule_policy_version": self.rule_policy_version,
            "policy_catalog_hash": self.policy_catalog_hash,
            "parser_options": self.parser_options.to_dict(),
            "ml_settings": self.ml_settings.to_dict(),
            "engine_version": self.engine_version,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_args(
        cls,
        run_ml: bool = True,
        include_all_ports: bool = False,
        scoring_policy_id: str = "crypto-posture-v1",
        scoring_policy_version: str = "1.0",
        rule_policy_id: str = "nist-bcp-forensic-v1",
        rule_policy_version: str = "1.2.0",
    ) -> AnalysisConfig:
        return cls(
            scoring_policy_id=scoring_policy_id,
            scoring_policy_version=scoring_policy_version,
            rule_policy_id=rule_policy_id,
            rule_policy_version=rule_policy_version,
            parser_options=ParserOptions(include_all_ports=include_all_ports),
            ml_settings=MLSettings(enabled=run_ml),
        )



# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

@dataclass
class CertHealth:
    """Parsed X.509 certificate metadata."""
    validity: CertValidity = CertValidity.UNKNOWN
    key_length_bits: Optional[int] = None
    signature_algorithm: Optional[str] = None
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_self_signed: bool = False

    # Forensic extensions
    san_list: list[str] = field(default_factory=list)
    key_type: Optional[str] = None
    curve_name: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_dn: Optional[str] = None
    is_ca: bool = False
    signature_valid: Optional[bool] = None
    san_matches_sni: Optional[bool] = None
    diagnostics: list[str] = field(default_factory=list)

    # Ordered OIDs for JA4X certificate fingerprinting
    issuer_rdn_oids: list[str] = field(default_factory=list)
    subject_rdn_oids: list[str] = field(default_factory=list)
    extension_oids: list[str] = field(default_factory=list)

    # Key-type-aware public key security profile (NIST SP 800-57)
    public_key: Optional[PublicKeyProfile] = None

    def __post_init__(self):
        if self.public_key is None and (self.key_type or self.key_length_bits is not None):
            self.public_key = PublicKeyProfile.compute(
                key_type=self.key_type,
                key_length=self.key_length_bits,
                curve_name=self.curve_name,
            )

    def to_dict(self) -> dict:
        return {
            "validity":            self.validity.value,
            "key_length_bits":     self.key_length_bits,
            "signature_algorithm": self.signature_algorithm,
            "subject_cn":          self.subject_cn,
            "issuer_cn":           self.issuer_cn,
            "not_before":          self.not_before,
            "not_after":           self.not_after,
            "is_self_signed":      self.is_self_signed,
            "san_list":            self.san_list,
            "key_type":            self.key_type,
            "curve_name":          self.curve_name,
            "serial_number":       self.serial_number,
            "fingerprint_sha256":  self.fingerprint_sha256,
            "subject_dn":          self.subject_dn,
            "issuer_dn":           self.issuer_dn,
            "is_ca":               self.is_ca,
            "signature_valid":     self.signature_valid,
            "san_matches_sni":     self.san_matches_sni,
            "diagnostics":         self.diagnostics,
            "issuer_rdn_oids":     list(self.issuer_rdn_oids),
            "subject_rdn_oids":    list(self.subject_rdn_oids),
            "extension_oids":      list(self.extension_oids),
            "public_key":          self.public_key.to_dict() if self.public_key else None,
        }


@dataclass
class ComponentScores:
    """Per-domain sub-scores feeding into the posture formula."""
    tls_version:       float = 0.0   # w = 0.25
    cipher_suite:      float = 0.0   # w = 0.20
    cert_health:       float = 0.0   # w = 0.20
    starttls_transition: float = 0.0 # w = 0.15
    forward_secrecy:   float = 0.0   # w = 0.10
    protocol_context:  float = 0.0   # w = 0.10


@dataclass
class Violation:
    """A single detected compliance violation or policy finding."""
    code: str
    description: str
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    reference: str = ""  # RFC or NIST reference

    # Forensic policy extensions (backward-compatible defaults)
    rule_id: str = ""
    title: str = ""
    status: FindingStatus = FindingStatus.VIOLATION
    confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    source_fields: list[str] = field(default_factory=list)
    mandate_level: str = "MUST"    # "MUST" vs "SHOULD"
    is_primary: bool = True
    category: str = ""

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = self.code

    def to_dict(self) -> dict:
        return {
            "code":          self.code,
            "rule_id":       self.rule_id or self.code,
            "title":         self.title,
            "description":   self.description,
            "severity":      self.severity,
            "reference":     self.reference,
            "status":        self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "confidence":    self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "evidence":      self.evidence,
            "remediation":   self.remediation,
            "source_fields": self.source_fields,
            "mandate_level": self.mandate_level,
            "is_primary":    self.is_primary,
            "category":      self.category,
        }


@dataclass
class JA4Fingerprints:
    """Multi-layer JA4+ fingerprints emitted by the FoxIO integration."""
    ja4:  Optional[str] = None   # Client TLS fingerprint
    ja4s: Optional[str] = None   # Server TLS fingerprint
    ja4x: Optional[str] = None   # Leaf/first X.509 certificate fingerprint
    ja4x_chain: List[str] = field(default_factory=list)  # One JA4X per observed certificate


# ---------------------------------------------------------------------------
# Primary session analysis model
# ---------------------------------------------------------------------------

@dataclass
class SessionAnalysis:
    """
    Full forensic analysis result for a single reconstructed email session.
    Matches the PRD §10 JSON feature schema.
    """
    session_id:      str = ""
    src_ip:          str = ""
    dst_ip:          str = ""
    src_port:        int = 0
    dst_port:        int = 0

    protocol:        Protocol    = Protocol.UNKNOWN
    channel_type:    ChannelType = ChannelType.UNKNOWN
    starttls_status: StarttlsStatus = StarttlsStatus.NONE

    tls_version:  Optional[TLSVersion]  = None
    cipher_suite: Optional[str]         = None
    key_exchange: Optional[KeyExchange] = None
    sni:          Optional[str]         = None

    cert: CertHealth = field(default_factory=CertHealth)
    cert_chain: list[CertHealth] = field(default_factory=list)
    tls_diagnostics: list[str] = field(default_factory=list)
    handshake_status: str = "UNKNOWN"
    fingerprints: JA4Fingerprints = field(default_factory=JA4Fingerprints)

    violations:        list[Violation]   = field(default_factory=list)
    policy_findings:   list[Violation]   = field(default_factory=list)
    component_scores:  ComponentScores   = field(default_factory=ComponentScores)
    posture_score:     float             = 0.0
    risk_tier:         RiskTier          = RiskTier.CRITICAL
    scoring_policy_id: str               = "crypto-posture-v1"
    scoring_policy_version: str          = "1.0"
    confidence:        str               = "HIGH"
    scoring_explanation: Optional[dict]  = None

    # ML anomaly detection
    is_anomalous:     bool               = False
    anomaly_score:    Optional[float]    = None
    anomaly_status:   str                = "NORMAL"
    anomaly_features: dict               = field(default_factory=dict)

    # Buffer injection flag (Poddebniak et al.)
    buffer_injection_detected: bool = False

    # Research paper feature table fields
    sni_present:    bool  = False   # SNI extension presence (evaluates server targeting)
    bytes_pre_tls:  int   = 0       # Cleartext bytes observed before TLS record layer
    pqc_state:      int   = 0       # 0=Classical, 1=PQC Offered, 2=Hybrid PQC Negotiated
    pqc_offered:    bool  = False   # PQC group offered in ClientHello
    pqc_negotiated: bool  = False   # PQC group selected/negotiated in ServerHello
    cmd_inject_flag: bool = False   # Alias for buffer_injection_detected (feature table name)

    # Forensic flow identity & stage tracking
    flow_id:             str               = ""
    evidence_id:         str               = ""
    evidence_hash:       str               = ""
    validation_status:   str               = "VALID"
    validation_warnings: list[str]         = field(default_factory=list)
    stage_results:       dict[str, Any]    = field(default_factory=dict)

    # Packet-level metadata
    packet_count: int = 0
    byte_count:   int = 0

    # 🔴 Fix 1: TCP stream gap metadata
    stream_has_gaps: bool = False          # True if any sequence gaps were detected
    stream_gap_count: int = 0             # Total number of gaps across both directions
    stream_gap_details: list[dict] = field(default_factory=list)  # Per-gap forensic records

    # TLS 1.3 certificate visibility (Fix 2)
    cert_visibility: str = "UNKNOWN"      # VISIBLE | ENCRYPTED_TLS13 | UNKNOWN

    # Forensic schema versioning & provenance facts
    schema_version: str = SCHEMA_VERSION
    forensic_engine_version: str = FORENSIC_ENGINE_VERSION
    facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to PRD-compliant JSON-safe dictionary."""
        return {
            "session_id":     self.session_id,
            "flow_id":        self.flow_id,
            "evidence_id":    self.evidence_id,
            "evidence_hash":  self.evidence_hash,
            "src_ip":         self.src_ip,
            "dst_ip":         self.dst_ip,
            "src_port":       self.src_port,
            "dst_port":       self.dst_port,
            "protocol":       self.protocol.value,
            "channel_type":   self.channel_type.value,
            "starttls_status": self.starttls_status.value,
            "tls_version":    self.tls_version.value if self.tls_version else None,
            "cipher_suite":   self.cipher_suite,
            "key_exchange":   self.key_exchange.value if self.key_exchange else None,
            "sni":            self.sni,
            "handshake_status": self.handshake_status,
            "tls_diagnostics": self.tls_diagnostics,
            "cert":           self.cert.to_dict(),
            "cert_chain":      [c.to_dict() for c in self.cert_chain],
            "fingerprints": {
                "ja4":  self.fingerprints.ja4,
                "ja4s": self.fingerprints.ja4s,
                "ja4x": self.fingerprints.ja4x,
                "ja4x_chain": list(self.fingerprints.ja4x_chain),
            },
            "violations": [
                v.to_dict() if hasattr(v, "to_dict") else {
                    "code":        v.code,
                    "description": v.description,
                    "severity":    v.severity,
                    "reference":   v.reference,
                }
                for v in self.violations
            ],
            "policy_findings": [
                f.to_dict() if hasattr(f, "to_dict") else {
                    "code":        f.code,
                    "description": f.description,
                    "severity":    f.severity,
                    "reference":   f.reference,
                }
                for f in self.policy_findings
            ],
            "component_scores": {
                "tls_version":        self.component_scores.tls_version,
                "cipher_suite":       self.component_scores.cipher_suite,
                "cert_health":        self.component_scores.cert_health,
                "starttls_transition": self.component_scores.starttls_transition,
                "forward_secrecy":    self.component_scores.forward_secrecy,
                "protocol_context":   self.component_scores.protocol_context,
            },
            "posture_score":   round(self.posture_score, 2),
            "risk_tier":       self.risk_tier.value,
            "scoring_policy": {
                "id":      self.scoring_policy_id,
                "version": self.scoring_policy_version,
            },
            "confidence":          self.confidence,
            "scoring_explanation": self.scoring_explanation,
            "ml_anomaly": {
                "status":                  self.anomaly_status,
                "is_anomalous":            self.is_anomalous,
                "anomaly_score":           self.anomaly_score,
                "evaluation_mode":         "capture_relative",
                "unusual_characteristics": self.anomaly_features,
                "top_features":            self.anomaly_features,
            },
            # Research paper feature table fields
            "sni_present":              bool(self.sni),
            "cmd_inject_flag":          self.buffer_injection_detected,
            "buffer_injection_detected": self.buffer_injection_detected,
            "bytes_pre_tls":            self.bytes_pre_tls,
            "pqc_state":               self.pqc_state,
            "pqc_offered":             self.pqc_offered,
            "pqc_negotiated":          self.pqc_negotiated,
            "validation_status":        self.validation_status,
            "validation_warnings":      list(self.validation_warnings),
            "stream_has_gaps":          self.stream_has_gaps,
            "stream_gap_count":         self.stream_gap_count,
            "stream_gap_details":       list(self.stream_gap_details),
            "cert_visibility":          self.cert_visibility,
            "stage_results": {
                k: v.to_dict() if hasattr(v, "to_dict") else v
                for k, v in self.stage_results.items()
            },
            "packet_count": self.packet_count,
            "byte_count":   self.byte_count,
            "schema_version":          self.schema_version,
            "forensic_engine_version": self.forensic_engine_version,
            "facts": {
                k: v.to_dict() if hasattr(v, "to_dict") else v
                for k, v in self.facts.items()
            },
        }


# ---------------------------------------------------------------------------
# Enterprise-level aggregate (whole PCAP)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceMetadata:
    """Forensic evidence integrity and chain-of-custody record."""
    filename:                str = ""
    sha256_hash:             str = ""
    file_size_bytes:         int = 0
    total_packets:           int = 0
    capture_duration:        float = 0.0

    # Extended chain-of-custody & capture verification metadata
    evidence_id:             str = ""
    absolute_path:           str = ""
    hash_algorithm:          str = "SHA-256"
    ingestion_timestamp:     str = ""
    capture_format:          str = "UNKNOWN"
    magic_bytes_hex:         str = ""
    link_layer_type:         str = "Ethernet"
    first_packet_timestamp:  Optional[float] = None
    last_packet_timestamp:   Optional[float] = None
    parse_error_count:       int = 0
    is_tamper_free:          bool = True
    diagnostics:             list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "filename":                self.filename,
            "sha256_hash":             self.sha256_hash,
            "file_size_bytes":         self.file_size_bytes,
            "total_packets":           self.total_packets,
            "capture_duration":        self.capture_duration,
            "evidence_id":             self.evidence_id,
            "absolute_path":           self.absolute_path,
            "hash_algorithm":          self.hash_algorithm,
            "ingestion_timestamp":     self.ingestion_timestamp,
            "capture_format":          self.capture_format,
            "magic_bytes_hex":         self.magic_bytes_hex,
            "link_layer_type":         self.link_layer_type,
            "first_packet_timestamp":  self.first_packet_timestamp,
            "last_packet_timestamp":   self.last_packet_timestamp,
            "parse_error_count":       self.parse_error_count,
            "is_tamper_free":          self.is_tamper_free,
            "diagnostics":             list(self.diagnostics),
        }


@dataclass
class EnterpriseSummary:
    """Aggregate forensic result for a complete PCAP capture."""
    evidence:              EvidenceMetadata    = field(default_factory=EvidenceMetadata)
    sessions:              list[SessionAnalysis] = field(default_factory=list)
    enterprise_posture_index: float             = 0.0
    overall_risk_tier:     RiskTier            = RiskTier.CRITICAL
    scoring_policy_id:     str                 = "crypto-posture-v1"
    scoring_policy_version: str                = "1.0"
    enterprise_explanation: dict               = field(default_factory=dict)
    analysis_config:       Optional[dict]      = None

    # Forensic schema versioning
    schema_version: str = SCHEMA_VERSION
    forensic_engine_version: str = FORENSIC_ENGINE_VERSION

    total_violations:      int                 = 0
    critical_sessions:     int                 = 0
    high_sessions:         int                 = 0
    medium_sessions:       int                 = 0
    low_sessions:          int                 = 0

    def to_dict(self) -> dict:
        # Aggregated violation severity breakdown across all sessions
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for s in self.sessions:
            for v in s.violations:
                sev = getattr(v, "severity", "INFO")
                if isinstance(sev, str):
                    sev_upper = sev.upper()
                    sev_counts[sev_upper] = sev_counts.get(sev_upper, 0) + 1

        session_tiers = {
            "CRITICAL": self.critical_sessions,
            "HIGH":     self.high_sessions,
            "MEDIUM":   self.medium_sessions,
            "LOW":      self.low_sessions,
        }

        return {
            "evidence": self.evidence.to_dict() if hasattr(self.evidence, "to_dict") else {
                "filename":         self.evidence.filename,
                "sha256_hash":      self.evidence.sha256_hash,
                "file_size_bytes":  self.evidence.file_size_bytes,
                "total_packets":    self.evidence.total_packets,
                "capture_duration": self.evidence.capture_duration,
            },
            "enterprise_posture_index": round(self.enterprise_posture_index, 2),
            "overall_risk_tier":    self.overall_risk_tier.value,
            "scoring_policy": {
                "id":      self.scoring_policy_id,
                "version": self.scoring_policy_version,
                "weights": {
                    "tls_version":         0.25,
                    "cipher_suite":        0.20,
                    "cert_health":         0.20,
                    "starttls_transition": 0.15,
                    "forward_secrecy":     0.10,
                    "protocol_context":    0.10,
                },
                "risk_thresholds": {
                    "low":    80.0,
                    "medium": 55.0,
                    "high":   30.0,
                },
                "critical_caps": {
                    "plaintext":          0.0,
                    "sslv2_sslv3":        15.0,
                    "buffer_injection":   15.0,
                    "starttls_stripping": 15.0,
                    "broken_cipher":      20.0,
                    "invalid_cert":       60.0,
                },
            },
            "analysis_config":     self.analysis_config,
            "enterprise_explanation": self.enterprise_explanation,
            "schema_version":          self.schema_version,
            "forensic_engine_version": self.forensic_engine_version,
            "session_count":        len(self.sessions),
            "total_violations":     self.total_violations,
            "session_tier_breakdown": session_tiers,
            "violation_severity_breakdown": sev_counts,
            "risk_breakdown": session_tiers,  # Backward compatibility alias
            "sessions": [s.to_dict() for s in self.sessions],
        }
