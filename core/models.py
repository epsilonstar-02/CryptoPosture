"""
core/models.py
Data structures and schemas for the AI-Assisted Passive Network Forensic Framework.
Implements the session feature schema from §10 of the PRD.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

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
    NONE        = "None"
    ADVERTISED  = "Advertised"
    REQUESTED   = "Requested"
    NEGOTIATED  = "Negotiated"
    FAILED      = "Failed"
    STRIPPED    = "Stripped"


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
    """A single detected compliance violation."""
    code: str
    description: str
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    reference: str = ""  # RFC or NIST reference


@dataclass
class JA4Fingerprints:
    """Multi-layer JA4+ fingerprints."""
    ja4:  Optional[str] = None   # Client TLS fingerprint
    ja4s: Optional[str] = None   # Server TLS fingerprint
    ja4x: Optional[str] = None   # X.509 certificate fingerprint


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
    fingerprints: JA4Fingerprints = field(default_factory=JA4Fingerprints)

    violations:        list[Violation]   = field(default_factory=list)
    component_scores:  ComponentScores   = field(default_factory=ComponentScores)
    posture_score:     float             = 0.0
    risk_tier:         RiskTier          = RiskTier.CRITICAL

    # ML anomaly detection
    is_anomalous:     bool               = False
    anomaly_score:    Optional[float]    = None
    anomaly_features: dict               = field(default_factory=dict)

    # Buffer injection flag (Poddebniak et al.)
    buffer_injection_detected: bool = False

    # Research paper feature table fields
    sni_present:    bool  = False   # SNI extension presence (evaluates server targeting)
    bytes_pre_tls:  int   = 0       # Cleartext bytes observed before TLS record layer
    pqc_state:      int   = 0       # 0=Classical, 1=PQC Offered, 2=Hybrid PQC Negotiated
    cmd_inject_flag: bool = False   # Alias for buffer_injection_detected (feature table name)

    # Packet-level metadata
    packet_count: int = 0
    byte_count:   int = 0

    def to_dict(self) -> dict:
        """Serialize to PRD-compliant JSON-safe dictionary."""
        return {
            "session_id":     self.session_id,
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
            "cert": {
                "validity":            self.cert.validity.value,
                "key_length_bits":     self.cert.key_length_bits,
                "signature_algorithm": self.cert.signature_algorithm,
                "subject_cn":          self.cert.subject_cn,
                "issuer_cn":           self.cert.issuer_cn,
                "not_before":          self.cert.not_before,
                "not_after":           self.cert.not_after,
                "is_self_signed":      self.cert.is_self_signed,
            },
            "fingerprints": {
                "ja4":  self.fingerprints.ja4,
                "ja4s": self.fingerprints.ja4s,
                "ja4x": self.fingerprints.ja4x,
            },
            "violations": [
                {
                    "code":        v.code,
                    "description": v.description,
                    "severity":    v.severity,
                    "reference":   v.reference,
                }
                for v in self.violations
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
            "ml_anomaly": {
                "is_anomalous":  self.is_anomalous,
                "anomaly_score": self.anomaly_score,
                "top_features":  self.anomaly_features,
            },
            # Research paper feature table fields
            "sni_present":              bool(self.sni),
            "cmd_inject_flag":          self.buffer_injection_detected,
            "buffer_injection_detected": self.buffer_injection_detected,
            "bytes_pre_tls":            self.bytes_pre_tls,
            "pqc_state":               self.pqc_state,
            "packet_count": self.packet_count,
            "byte_count":   self.byte_count,
        }


# ---------------------------------------------------------------------------
# Enterprise-level aggregate (whole PCAP)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceMetadata:
    """Forensic evidence integrity record."""
    filename:         str = ""
    sha256_hash:      str = ""
    file_size_bytes:  int = 0
    total_packets:    int = 0
    capture_duration: float = 0.0


@dataclass
class EnterpriseSummary:
    """Aggregate forensic result for a complete PCAP capture."""
    evidence:              EvidenceMetadata    = field(default_factory=EvidenceMetadata)
    sessions:              list[SessionAnalysis] = field(default_factory=list)
    enterprise_posture_index: float             = 0.0
    overall_risk_tier:     RiskTier            = RiskTier.CRITICAL

    total_violations:      int                 = 0
    critical_sessions:     int                 = 0
    high_sessions:         int                 = 0
    medium_sessions:       int                 = 0
    low_sessions:          int                 = 0

    def to_dict(self) -> dict:
        return {
            "evidence": {
                "filename":         self.evidence.filename,
                "sha256_hash":      self.evidence.sha256_hash,
                "file_size_bytes":  self.evidence.file_size_bytes,
                "total_packets":    self.evidence.total_packets,
                "capture_duration": self.evidence.capture_duration,
            },
            "enterprise_posture_index": round(self.enterprise_posture_index, 2),
            "overall_risk_tier":    self.overall_risk_tier.value,
            "session_count":        len(self.sessions),
            "total_violations":     self.total_violations,
            "risk_breakdown": {
                "CRITICAL": self.critical_sessions,
                "HIGH":     self.high_sessions,
                "MEDIUM":   self.medium_sessions,
                "LOW":      self.low_sessions,
            },
            "sessions": [s.to_dict() for s in self.sessions],
        }
