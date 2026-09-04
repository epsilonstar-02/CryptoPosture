"""
core/rule_engine.py
Versioned, evidence-aware cryptographic policy and compliance engine.
Implements Pipeline Stage 9 (Rule Engine portion) from the project synopsis.

Standards enforced:
  - NIST SP 800-52 Rev. 2 (Guidelines for TLS Implementations)
  - RFC 9325 / BCP 195 (Recommendations for Secure TLS and DTLS)
  - RFC 8314 (Cleartext Considered Obsolete: Use of TLS for Email Submission and Access)
  - RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)
  - RFC 5280 (X.509 PKI Certificate and CRL Profile)
  - RFC 6125 (Representation and Verification of Domain-Based Application Service Identity)
  - Poddebniak et al. USENIX Security 2021 (STARTTLS Buffer Injection Analysis)

Architecture:
  - Structured, versioned PolicyCatalog with exportable JSON configuration
  - Rich PolicyFinding / Violation records carrying:
      rule_id, severity, status, confidence, evidence, remediation, reference, source_fields
  - Explicit outcomes: VIOLATION / PASS / NOT_EVALUATED / INCONCLUSIVE
  - Calibrated attack indicator confidence (CONFIRMED vs. MEDIUM/SUSPECTED)
  - Context-aware protocol rules (RFC MUST mandates vs. SHOULD recommendations)
  - Rule dependency and deduplication mechanisms
  - Strict separation of policy evaluation from scoring math
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CertValidity,
    ChannelType,
    ConfidenceLevel,
    FindingStatus,
    KeyExchange,
    Protocol,
    RiskTier,
    SessionAnalysis,
    StarttlsStatus,
    TLSVersion,
    Violation,
)


# ---------------------------------------------------------------------------
# Structured Policy Definition Models
# ---------------------------------------------------------------------------

@dataclass
class RuleDefinition:
    """Specification and guidance metadata for a compliance rule."""
    rule_id:        str
    title:          str
    description:    str
    severity:       str                   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    reference:      str                   # RFC or NIST citation
    category:       str                   # Domain category
    mandate_level:  str = "MUST"          # "MUST" (normative) vs "SHOULD" (recommendation)
    remediation:    str = ""              # Actionable fix advice
    source_fields:  list[str] = field(default_factory=list)
    parent_rule_id: Optional[str] = None  # Dependency for deduplication
    enabled:        bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id":        self.rule_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity,
            "reference":      self.reference,
            "category":       self.category,
            "mandate_level":  self.mandate_level,
            "remediation":    self.remediation,
            "source_fields":  self.source_fields,
            "parent_rule_id": self.parent_rule_id,
            "enabled":        self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RuleDefinition:
        return cls(
            rule_id        = data["rule_id"],
            title          = data.get("title", ""),
            description    = data.get("description", ""),
            severity       = data.get("severity", "MEDIUM"),
            reference      = data.get("reference", ""),
            category       = data.get("category", ""),
            mandate_level  = data.get("mandate_level", "MUST"),
            remediation    = data.get("remediation", ""),
            source_fields  = data.get("source_fields", []),
            parent_rule_id = data.get("parent_rule_id"),
            enabled        = data.get("enabled", True),
        )


@dataclass
class PolicyCatalog:
    """A versioned collection of cryptographic compliance rules."""
    policy_id:   str = "nist-bcp-forensic-v1"
    name:        str = "NIST SP 800-52 Rev. 2 & RFC 9325 Forensic Baseline"
    version:     str = "1.2.0"
    description: str = "Forensic baseline enforcing NIST SP 800-52r2, RFC 9325 (BCP 195), RFC 8314, and RFC 8996"
    rules:       dict[str, RuleDefinition] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "policy_id":   self.policy_id,
            "name":        self.name,
            "version":     self.version,
            "description": self.description,
            "rules":       {k: v.to_dict() for k, v in self.rules.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> PolicyCatalog:
        cat = cls(
            policy_id   = data.get("policy_id", "custom-policy"),
            name        = data.get("name", "Custom Policy"),
            version     = data.get("version", "1.0.0"),
            description = data.get("description", ""),
        )
        for k, v in data.get("rules", {}).items():
            cat.rules[k] = RuleDefinition.from_dict(v)
        return cat

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> PolicyCatalog:
        return cls.from_dict(json.loads(json_str))


# ---------------------------------------------------------------------------
# Default Forensic Policy Catalog
# ---------------------------------------------------------------------------

DEFAULT_POLICY_CATALOG = PolicyCatalog(
    policy_id   = "nist-bcp-forensic-v1",
    name        = "NIST SP 800-52r2 & RFC 9325 Forensic Policy",
    version     = "1.2.0",
    description = "Forensic compliance policy combining NIST SP 800-52 Rev. 2, RFC 9325 (BCP 195), RFC 8314, and RFC 8996",
    rules = {
        # ---- TLS Protocol Versions ----
        "DEPR-TLS-001": RuleDefinition(
            rule_id       = "DEPR-TLS-001",
            title         = "Deprecated SSLv2 / SSLv3 Protocol",
            description   = "SSLv2 and SSLv3 are cryptographically broken and formally deprecated (RFC 8996, RFC 9325 §3.1.1).",
            severity      = "CRITICAL",
            reference     = "RFC 8996, RFC 9325 §3.1.1",
            category      = "TLS_VERSION",
            mandate_level = "MUST NOT",
            remediation   = "Disable SSLv2 and SSLv3 across all server endpoints. Configure minimum TLS version to TLS 1.2 or TLS 1.3.",
            source_fields = ["tls_version"],
        ),
        "DEPR-TLS-002": RuleDefinition(
            rule_id       = "DEPR-TLS-002",
            title         = "Deprecated TLS 1.0 Protocol",
            description   = "TLS 1.0 is deprecated (RFC 8996) and vulnerable to CBC chosen-plaintext attacks (POODLE, BEAST, CRIME).",
            severity      = "HIGH",
            reference     = "RFC 8996, NIST SP 800-52r2 §3.1",
            category      = "TLS_VERSION",
            mandate_level = "MUST NOT",
            remediation   = "Disable TLS 1.0 on all mail server listeners and client configurations.",
            source_fields = ["tls_version"],
        ),
        "DEPR-TLS-003": RuleDefinition(
            rule_id       = "DEPR-TLS-003",
            title         = "Deprecated TLS 1.1 Protocol",
            description   = "TLS 1.1 is deprecated (RFC 8996) and lacks support for modern AEAD cipher suites.",
            severity      = "HIGH",
            reference     = "RFC 8996, NIST SP 800-52r2 §3.1",
            category      = "TLS_VERSION",
            mandate_level = "MUST NOT",
            remediation   = "Upgrade server configuration to require TLS 1.2 or TLS 1.3.",
            source_fields = ["tls_version"],
        ),
        "DEPR-TLS-004": RuleDefinition(
            rule_id       = "DEPR-TLS-004",
            title         = "Unencrypted Plaintext Session",
            description   = "No TLS detected — email session is transmitted entirely in plaintext (RFC 8314, RFC 9325).",
            severity      = "CRITICAL",
            reference     = "RFC 8314 §3, RFC 9325",
            category      = "TLS_VERSION",
            mandate_level = "MUST",
            remediation   = "Enforce TLS encryption for all email traffic; mandate Implicit TLS or require STARTTLS upgrade.",
            source_fields = ["channel_type", "protocol"],
        ),

        # ---- Cipher Suites ----
        "WEAK-CIPH-001": RuleDefinition(
            rule_id       = "WEAK-CIPH-001",
            title         = "Forbidden RC4 Stream Cipher",
            description   = "RC4 stream cipher is cryptographically broken and forbidden by RFC 7465.",
            severity      = "CRITICAL",
            reference     = "RFC 7465, NIST SP 800-52r2 §3.3",
            category      = "CIPHER_SUITE",
            mandate_level = "MUST NOT",
            remediation   = "Remove all RC4 cipher suites from server cipher suite configuration.",
            source_fields = ["cipher_suite"],
        ),
        "WEAK-CIPH-002": RuleDefinition(
            rule_id       = "WEAK-CIPH-002",
            title         = "SWEET32 Vulnerable 3DES Block Cipher",
            description   = "3DES/TDEA cipher vulnerable to SWEET32 birthday attack due to 64-bit block size (CVE-2016-2183).",
            severity      = "HIGH",
            reference     = "NIST SP 800-131A, RFC 9325 §4.1",
            category      = "CIPHER_SUITE",
            mandate_level = "MUST NOT",
            remediation   = "Disable 3DES/TDEA cipher suites. Prioritize AES-GCM or ChaCha20-Poly1305.",
            source_fields = ["cipher_suite"],
        ),
        "WEAK-CIPH-003": RuleDefinition(
            rule_id       = "WEAK-CIPH-003",
            title         = "Insecure NULL Cipher (Zero Encryption)",
            description   = "NULL cipher provides no confidentiality encryption — payload is transmitted in plaintext on wire.",
            severity      = "CRITICAL",
            reference     = "NIST SP 800-52r2, RFC 9325",
            category      = "CIPHER_SUITE",
            mandate_level = "MUST NOT",
            remediation   = "Disable all NULL encryption cipher suites immediately.",
            source_fields = ["cipher_suite"],
        ),
        "WEAK-CIPH-004": RuleDefinition(
            rule_id       = "WEAK-CIPH-004",
            title         = "Weakened Export-Grade Cipher",
            description   = "Export-grade cipher is intentionally weakened — vulnerable to FREAK/Logjam attacks.",
            severity      = "CRITICAL",
            reference     = "RFC 9325 §4.1, NIST SP 800-52r2",
            category      = "CIPHER_SUITE",
            mandate_level = "MUST NOT",
            remediation   = "Disable all legacy export-grade cipher suites.",
            source_fields = ["cipher_suite"],
        ),
        "WEAK-CIPH-005": RuleDefinition(
            rule_id       = "WEAK-CIPH-005",
            title         = "Generic Weak or Deprecated Cipher",
            description   = "Weak, anonymous, or deprecated cipher suite detected.",
            severity      = "HIGH",
            reference     = "NIST SP 800-52r2 §3.3",
            category      = "CIPHER_SUITE",
            mandate_level = "MUST NOT",
            remediation   = "Configure server to offer only modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305, AES-CCM).",
            source_fields = ["cipher_suite"],
        ),

        # ---- Forward Secrecy ----
        "FS-001": RuleDefinition(
            rule_id       = "FS-001",
            title         = "Missing Forward Secrecy",
            description   = "No forward secrecy — static RSA key exchange allows retroactive decryption of captured past sessions.",
            severity      = "HIGH",
            reference     = "NIST SP 800-52r2 §3.3.1, RFC 9325 §3",
            category      = "FORWARD_SECRECY",
            mandate_level = "SHOULD",
            remediation   = "Configure ephemeral Diffie-Hellman (ECDHE or DHE >= 2048-bit) key exchange.",
            source_fields = ["key_exchange", "cipher_suite"],
        ),
        "FS-002": RuleDefinition(
            rule_id       = "FS-002",
            title         = "Static RSA Key Exchange Detected",
            description   = "Static RSA key exchange detected — compromised server key exposes all past recorded sessions.",
            severity      = "HIGH",
            reference     = "RFC 9325 §3, NIST SP 800-52r2 §3.3",
            category      = "FORWARD_SECRECY",
            mandate_level = "MUST NOT",
            remediation   = "Disable TLS_RSA_* cipher suites in favor of TLS_ECDHE_* or TLS 1.3.",
            source_fields = ["key_exchange"],
            parent_rule_id = "FS-001",
        ),

        # ---- X.509 Certificates ----
        "CERT-001": RuleDefinition(
            rule_id       = "CERT-001",
            title         = "Expired X.509 Certificate",
            description   = "X.509 certificate has expired — TLS trust chain is invalid.",
            severity      = "CRITICAL",
            reference     = "RFC 5280 §4.1.2.5",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Renew certificate with a Certificate Authority and deploy on server.",
            source_fields = ["cert.not_after", "cert.validity"],
        ),
        "CERT-002": RuleDefinition(
            rule_id       = "CERT-002",
            title         = "Not Yet Valid X.509 Certificate",
            description   = "X.509 certificate is not yet valid (notBefore in the future).",
            severity      = "HIGH",
            reference     = "RFC 5280 §4.1.2.5",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Verify system time synchronization (NTP) or re-issue certificate with current activation date.",
            source_fields = ["cert.not_before", "cert.validity"],
        ),
        "CERT-003": RuleDefinition(
            rule_id       = "CERT-003",
            title         = "Self-Signed Certificate",
            description   = "Certificate is self-signed — no trusted public CA chain.",
            severity      = "MEDIUM",
            reference     = "RFC 5280, NIST SP 800-52r2 §3.2",
            category      = "CERTIFICATE",
            mandate_level = "SHOULD",
            remediation   = "Replace self-signed certificate with one issued by a trusted public CA or internal PKI.",
            source_fields = ["cert.is_self_signed", "cert.validity"],
        ),
        "CERT-004": RuleDefinition(
            rule_id       = "CERT-004",
            title         = "Insufficient RSA Key Length (< 2048 bits)",
            description   = "RSA/DH key size < 2048 bits — insufficient for security (NIST deprecated < 2048).",
            severity      = "HIGH",
            reference     = "NIST SP 800-131A, NIST SP 800-52r2 §3.2",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Generate 2048-bit or 4096-bit RSA keys, or migrate to ECDSA (secp256r1) / Ed25519.",
            source_fields = ["cert.key_length_bits"],
        ),
        "CERT-005": RuleDefinition(
            rule_id       = "CERT-005",
            title         = "Insufficient EC Key Size (< 224 bits)",
            description   = "EC key size < 224 bits — insufficient for security.",
            severity      = "HIGH",
            reference     = "NIST SP 800-57, NIST SP 800-52r2 §3.2",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Use standard NIST P-256 (secp256r1), P-384, or Curve25519.",
            source_fields = ["cert.key_length_bits"],
        ),
        "CERT-006": RuleDefinition(
            rule_id       = "CERT-006",
            title         = "Broken SHA-1 Certificate Signature",
            description   = "SHA-1 signature algorithm is cryptographically broken (SHATTERED attack).",
            severity      = "HIGH",
            reference     = "NIST SP 800-131A, RFC 9325 §3",
            category      = "CERTIFICATE",
            mandate_level = "MUST NOT",
            remediation   = "Re-issue certificate using SHA-256 or SHA-384 signature hash algorithm.",
            source_fields = ["cert.signature_algorithm"],
        ),
        "CERT-007": RuleDefinition(
            rule_id       = "CERT-007",
            title         = "Broken MD5 Certificate Signature",
            description   = "MD5 signature algorithm is completely broken — collision attacks demonstrated.",
            severity      = "CRITICAL",
            reference     = "RFC 9325, NIST SP 800-131A",
            category      = "CERTIFICATE",
            mandate_level = "MUST NOT",
            remediation   = "Revoke and replace certificate immediately using SHA-256+.",
            source_fields = ["cert.signature_algorithm"],
        ),
        "CERT-008": RuleDefinition(
            rule_id       = "CERT-008",
            title         = "Cryptographic Certificate Signature Verification Failure",
            description   = "Certificate cryptographic signature verification failed against declared key (forged or corrupted).",
            severity      = "CRITICAL",
            reference     = "RFC 5280 §4.1.1.3",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Investigate potential certificate tampering or man-in-the-middle forging.",
            source_fields = ["cert.signature_valid"],
        ),
        "CERT-009": RuleDefinition(
            rule_id       = "CERT-009",
            title         = "Certificate Hostname / SNI Mismatch",
            description   = "Client requested SNI does not match Subject Alternative Names (SAN) or Subject CN in certificate.",
            severity      = "HIGH",
            reference     = "RFC 6125, RFC 5280",
            category      = "CERTIFICATE",
            mandate_level = "MUST",
            remediation   = "Ensure certificate SAN extension covers all domain names used by connecting clients.",
            source_fields = ["sni", "cert.san_list", "cert.subject_cn"],
        ),

        # ---- STARTTLS & Attack Indicators ----
        "STARTTLS-001": RuleDefinition(
            rule_id       = "STARTTLS-001",
            title         = "Confirmed STARTTLS Stripping Attack Indicator",
            description   = "STARTTLS capability was stripped by on-path adversary (STRIPTLS attack). Server omitted STARTTLS advertisement and client transmitted credentials in cleartext.",
            severity      = "CRITICAL",
            reference     = "Durumeric et al. IMC 2015, RFC 8314",
            category      = "STARTTLS",
            mandate_level = "MUST",
            remediation   = "Enforce mandatory TLS on client configurations; deploy MTA-STS / DANE TLSA; investigate network path for MITM tampering.",
            source_fields = ["starttls_status", "bytes_pre_tls"],
        ),
        "STARTTLS-002": RuleDefinition(
            rule_id       = "STARTTLS-002",
            title         = "STARTTLS Negotiation Failure",
            description   = "STARTTLS negotiation failed or rejected by server — session fell back to plaintext.",
            severity      = "CRITICAL",
            reference     = "RFC 3207, RFC 8314",
            category      = "STARTTLS",
            mandate_level = "MUST",
            remediation   = "Diagnose mail server TLS handshake errors and prevent unencrypted fallback.",
            source_fields = ["starttls_status"],
        ),
        "STARTTLS-003": RuleDefinition(
            rule_id       = "STARTTLS-003",
            title         = "Unupgraded Opportunistic STARTTLS Session",
            description   = "Server advertised STARTTLS but client never upgraded.",
            severity      = "MEDIUM",
            reference     = "RFC 3207",
            category      = "STARTTLS",
            mandate_level = "SHOULD",
            remediation   = "Configure client to require TLS upgrade for all email sessions.",
            source_fields = ["starttls_status"],
        ),
        "STARTTLS-004": RuleDefinition(
            rule_id       = "STARTTLS-004",
            title         = "STARTTLS Buffer Injection Attack Detected",
            description   = "STARTTLS buffer injection attack detected — cleartext commands pipelined across TLS boundary (Poddebniak et al., USENIX '21).",
            severity      = "CRITICAL",
            reference     = "Poddebniak et al. USENIX Security 2021",
            category      = "STARTTLS",
            mandate_level = "MUST NOT",
            remediation   = "Upgrade mail server software to patch STARTTLS buffer injection vulnerabilities; enforce strict command pacing across TLS transition.",
            source_fields = ["buffer_injection_detected"],
        ),
        "STARTTLS-005": RuleDefinition(
            rule_id       = "STARTTLS-005",
            title         = "Suspected STARTTLS Stripping Indicator",
            description   = "Possible STARTTLS stripping detected on untrusted cleartext channel.",
            severity      = "HIGH",
            reference     = "Durumeric et al. IMC 2015",
            category      = "STARTTLS",
            mandate_level = "SHOULD",
            remediation   = "Verify mail server configuration advertises STARTTLS; check upstream firewalls/proxies stripping capabilities.",
            source_fields = ["starttls_status", "dst_port"],
        ),

        # ---- Protocol Context ----
        "PROTO-001": RuleDefinition(
            rule_id       = "PROTO-001",
            title         = "Cleartext Email Submission on Port 587/25",
            description   = "Email submission on port 587/25 without TLS — cleartext submission (RFC 8314 §3 obsoletes this).",
            severity      = "CRITICAL",
            reference     = "RFC 8314 §3",
            category      = "PROTOCOL_CONTEXT",
            mandate_level = "MUST NOT",
            remediation   = "Mandate TLS before authentication on port 587 (Submission) or migrate to port 465 (Implicit TLS/SMTPS).",
            source_fields = ["dst_port", "channel_type", "protocol"],
        ),
        "PROTO-002": RuleDefinition(
            rule_id       = "PROTO-002",
            title         = "Cleartext Email Access on Port 143/110",
            description   = "Email access (IMAP/POP3) without TLS — RFC 8314 §3 mandates Implicit TLS.",
            severity      = "CRITICAL",
            reference     = "RFC 8314 §3",
            category      = "PROTOCOL_CONTEXT",
            mandate_level = "MUST NOT",
            remediation   = "Migrate all mail access clients to port 993 (IMAPS) or port 995 (POP3S) using Implicit TLS.",
            source_fields = ["dst_port", "channel_type", "protocol"],
        ),
        "PROTO-003": RuleDefinition(
            rule_id       = "PROTO-003",
            title         = "Opportunistic STARTTLS for Mail Access",
            description   = "Using STARTTLS instead of Implicit TLS for mail access — RFC 8314 recommends Implicit TLS on ports 993/995.",
            severity      = "LOW",
            reference     = "RFC 8314 §3",
            category      = "PROTOCOL_CONTEXT",
            mandate_level = "SHOULD",
            remediation   = "Migrate email clients to Implicit TLS (ports 993/995) to eliminate STARTTLS downgrade and stripping vectors.",
            source_fields = ["dst_port", "channel_type", "protocol"],
        ),
        "PROTO-004": RuleDefinition(
            rule_id       = "PROTO-004",
            title         = "Cleartext MTA Transit Relay on Port 25",
            description   = "MTA-to-MTA relay on port 25 without TLS. While opportunistic relaying is historically permitted, RFC 8314 strongly advises encryption.",
            severity      = "HIGH",
            reference     = "RFC 3207, RFC 8314 §3",
            category      = "PROTOCOL_CONTEXT",
            mandate_level = "SHOULD",
            remediation   = "Deploy STARTTLS with DANE TLSA or MTA-STS policies to ensure transit encryption.",
            source_fields = ["dst_port", "channel_type", "protocol"],
        ),
    }
)


# ---------------------------------------------------------------------------
# Backwards-compatible V namespace mapping tuples to rule IDs
# ---------------------------------------------------------------------------

class V:
    """Violation code constants with metadata for backwards compatibility."""
    SSLV2_SSLV3          = ("DEPR-TLS-001", "SSLv2/SSLv3 is completely broken and formally deprecated (RFC 8996)", "CRITICAL", "RFC 8996, RFC 9325 §3.1.1")
    TLS10_DEPRECATED      = ("DEPR-TLS-002", "TLS 1.0 is deprecated (RFC 8996) — vulnerable to POODLE, BEAST, CRIME", "HIGH",     "RFC 8996, NIST SP 800-52r2")
    TLS11_DEPRECATED      = ("DEPR-TLS-003", "TLS 1.1 is deprecated (RFC 8996)", "HIGH", "RFC 8996, NIST SP 800-52r2")
    NO_TLS                = ("DEPR-TLS-004", "No TLS detected — all email traffic is transmitted in plaintext", "CRITICAL", "RFC 8314, RFC 9325")

    RC4_CIPHER            = ("WEAK-CIPH-001", "RC4 cipher is cryptographically broken and forbidden (RFC 7465)", "CRITICAL", "RFC 7465, NIST SP 800-52r2 §3.3")
    THREE_DES_CIPHER      = ("WEAK-CIPH-002", "3DES/TDEA cipher vulnerable to SWEET32 birthday attack (CVE-2016-2183)", "HIGH",     "NIST SP 800-131A, RFC 9325 §4.1")
    NULL_CIPHER           = ("WEAK-CIPH-003", "NULL cipher provides no encryption — plaintext on wire", "CRITICAL", "NIST SP 800-52r2")
    EXPORT_CIPHER         = ("WEAK-CIPH-004", "Export-grade cipher is intentionally weakened — vulnerable to FREAK/LOGJAM", "CRITICAL", "RFC 9325 §4.1")
    WEAK_CIPHER_GENERIC   = ("WEAK-CIPH-005", "Weak or deprecated cipher suite detected", "HIGH", "NIST SP 800-52r2 §3.3")

    NO_FORWARD_SECRECY    = ("FS-001", "No forward secrecy — static RSA key exchange allows decryption of past sessions", "HIGH", "NIST SP 800-52r2 §3.3.1, RFC 9325 §3")
    STATIC_RSA            = ("FS-002", "Static RSA key exchange detected — compromised server key exposes all past sessions", "HIGH", "RFC 9325 §3")

    CERT_EXPIRED          = ("CERT-001", "X.509 certificate has expired — TLS chain is invalid", "CRITICAL", "RFC 5280 §4.1.2.5")
    CERT_NOT_YET_VALID    = ("CERT-002", "X.509 certificate is not yet valid (notBefore in the future)", "HIGH",     "RFC 5280")
    CERT_SELF_SIGNED      = ("CERT-003", "Certificate is self-signed — no trusted CA chain", "MEDIUM",   "RFC 5280, NIST SP 800-52r2 §3.2")
    CERT_WEAK_KEY_RSA     = ("CERT-004", "RSA/DH key size < 2048 bits — insufficient for security (NIST deprecated < 2048)", "HIGH", "NIST SP 800-131A, NIST SP 800-52r2 §3.2")
    CERT_WEAK_KEY_EC      = ("CERT-005", "EC key size < 224 bits — insufficient for security", "HIGH", "NIST SP 800-57")
    CERT_SHA1_SIG         = ("CERT-006", "SHA-1 signature algorithm is cryptographically broken (SHATTERED attack)", "HIGH", "NIST SP 800-131A, RFC 9325 §3")
    CERT_MD5_SIG          = ("CERT-007", "MD5 signature algorithm is completely broken — collision attacks demonstrated", "CRITICAL", "RFC 9325, NIST SP 800-131A")

    STARTTLS_STRIPPED     = ("STARTTLS-001", "STARTTLS capability was stripped by on-path adversary (STRIPTLS attack)", "CRITICAL", "Durumeric et al. IMC 2015, RFC 8314")
    STARTTLS_FAILED       = ("STARTTLS-002", "STARTTLS negotiation failed — session fell back to plaintext", "CRITICAL", "RFC 3207, RFC 8314")
    STARTTLS_UNADVERTISED = ("STARTTLS-003", "Server advertised STARTTLS but client never upgraded", "MEDIUM",   "RFC 3207")
    BUFFER_INJECTION      = ("STARTTLS-004", "STARTTLS buffer injection attack detected — cleartext commands pipelined across TLS boundary (Poddebniak et al., USENIX '21)", "CRITICAL", "Poddebniak et al. USENIX Security 2021")
    STARTTLS_POSSIBLE_STRIP = ("STARTTLS-005", "Possible STARTTLS stripping detected on untrusted cleartext channel", "HIGH", "Durumeric et al. IMC 2015")

    CLEARTEXT_SUBMISSION  = ("PROTO-001", "Email submission on port 587/25 without TLS — cleartext submission (RFC 8314 §3 obsoletes this)", "CRITICAL", "RFC 8314 §3")
    CLEARTEXT_ACCESS      = ("PROTO-002", "Email access (IMAP/POP3) without TLS — RFC 8314 §3 mandates Implicit TLS", "CRITICAL", "RFC 8314 §3")
    OPPORTUNISTIC_NOT_IMPLICIT = ("PROTO-003", "Using STARTTLS instead of Implicit TLS for mail access — RFC 8314 recommends Implicit TLS on ports 993/995", "LOW", "RFC 8314 §3")


# ---------------------------------------------------------------------------
# Policy Engine Implementation
# ---------------------------------------------------------------------------

@dataclass
class PolicyEvaluationReport:
    """Complete evaluation report containing active violations and all policy findings."""
    violations:   list[Violation]
    all_findings: list[Violation]


class PolicyEngine:
    """
    Versioned, evidence-aware policy evaluator.
    Evaluates session telemetry against compliance rules, generating auditable findings
    with explicit outcomes, confidence levels, and deduplication.
    """

    def __init__(self, policy: Optional[PolicyCatalog] = None, deduplicate: bool = True):
        self.policy = policy or DEFAULT_POLICY_CATALOG
        self.deduplicate = deduplicate

    def _make_finding(
        self,
        rule_id: str,
        status: FindingStatus,
        confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
        observed: Any = None,
        expected: Any = None,
        extra_desc: str = "",
        details: str = "",
        is_primary: bool = True,
        suppressed_by: Optional[str] = None,
    ) -> Violation:
        rule_def = self.policy.rules.get(rule_id)
        if not rule_def:
            # Fallback for dynamic rule
            title = rule_id
            description = extra_desc or rule_id
            severity = "MEDIUM"
            reference = ""
            category = "CUSTOM"
            mandate_level = "MUST"
            remediation = ""
            source_fields = []
        else:
            title = rule_def.title
            base_desc = rule_def.description
            description = f"{base_desc} {extra_desc}".strip() if extra_desc else base_desc
            severity = rule_def.severity
            reference = rule_def.reference
            category = rule_def.category
            mandate_level = rule_def.mandate_level
            remediation = rule_def.remediation
            source_fields = rule_def.source_fields

        evidence_dict = {
            "observed": observed,
            "expected": expected,
            "details":  details or extra_desc,
        }
        if suppressed_by:
            evidence_dict["suppressed_by"] = suppressed_by

        return Violation(
            code          = rule_id,
            description   = description,
            severity      = severity,
            reference     = reference,
            rule_id       = rule_id,
            title         = title,
            status        = status,
            confidence    = confidence,
            evidence      = evidence_dict,
            remediation   = remediation,
            source_fields = source_fields,
            mandate_level = mandate_level,
            is_primary    = is_primary,
            category      = category,
        )

    # -----------------------------------------------------------------------
    # Domain Evaluators
    # -----------------------------------------------------------------------

    def _eval_tls_version(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        tv = s.tls_version
        channel = s.channel_type
        proto = s.protocol

        # Rule: DEPR-TLS-004 (Plaintext check)
        if channel == ChannelType.PLAINTEXT:
            if proto in (Protocol.SMTP, Protocol.IMAP, Protocol.POP3):
                findings.append(self._make_finding(
                    "DEPR-TLS-004",
                    status     = FindingStatus.VIOLATION,
                    confidence = ConfidenceLevel.CONFIRMED,
                    observed   = "PLAINTEXT",
                    expected   = "TLS 1.2 or TLS 1.3",
                    details    = f"Protocol {proto.value} session observed in cleartext without TLS record layer",
                ))
            else:
                findings.append(self._make_finding(
                    "DEPR-TLS-004",
                    status     = FindingStatus.NOT_EVALUATED,
                    observed   = proto.value,
                    details    = "Non-mail protocol session",
                ))
            # Other TLS version rules not evaluated for plaintext
            for r_id in ("DEPR-TLS-001", "DEPR-TLS-002", "DEPR-TLS-003"):
                findings.append(self._make_finding(
                    r_id,
                    status   = FindingStatus.NOT_EVALUATED,
                    observed = "PLAINTEXT",
                    details  = "Session transmitted in cleartext; TLS version rules not applicable",
                ))
            return findings

        # If TLS was expected but handshake is inconclusive/truncated
        if tv is None:
            status = FindingStatus.INCONCLUSIVE
            conf = ConfidenceLevel.LOW
            diag = s.tls_diagnostics[0] if s.tls_diagnostics else "TLS handshake not captured or truncated"
            for r_id in ("DEPR-TLS-001", "DEPR-TLS-002", "DEPR-TLS-003", "DEPR-TLS-004"):
                findings.append(self._make_finding(
                    r_id,
                    status     = status,
                    confidence = conf,
                    observed   = "None",
                    expected   = "TLS 1.2 or TLS 1.3",
                    details    = diag,
                ))
            return findings

        # Positive evaluation of TLS version
        # DEPR-TLS-004 passed
        findings.append(self._make_finding(
            "DEPR-TLS-004",
            status     = FindingStatus.PASS,
            confidence = ConfidenceLevel.CONFIRMED,
            observed   = tv.value,
            expected   = "TLS 1.2 or TLS 1.3",
        ))

        # DEPR-TLS-001 (SSLv2/SSLv3)
        if tv in (TLSVersion.SSLv2, TLSVersion.SSLv3):
            findings.append(self._make_finding(
                "DEPR-TLS-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
                expected   = "TLS 1.2 or TLS 1.3",
                extra_desc = f"Detected: {tv.value}",
            ))
        else:
            findings.append(self._make_finding(
                "DEPR-TLS-001",
                status     = FindingStatus.PASS,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
            ))

        # DEPR-TLS-002 (TLS 1.0)
        if tv == TLSVersion.TLS10:
            findings.append(self._make_finding(
                "DEPR-TLS-002",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
                expected   = "TLS 1.2 or TLS 1.3",
                extra_desc = "Detected: TLS 1.0",
            ))
        else:
            findings.append(self._make_finding(
                "DEPR-TLS-002",
                status     = FindingStatus.PASS,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
            ))

        # DEPR-TLS-003 (TLS 1.1)
        if tv == TLSVersion.TLS11:
            findings.append(self._make_finding(
                "DEPR-TLS-003",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
                expected   = "TLS 1.2 or TLS 1.3",
                extra_desc = "Detected: TLS 1.1",
            ))
        else:
            findings.append(self._make_finding(
                "DEPR-TLS-003",
                status     = FindingStatus.PASS,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = tv.value,
            ))

        return findings

    def _eval_ciphers(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        cipher = (s.cipher_suite or "").upper()
        cipher_rules = ["WEAK-CIPH-001", "WEAK-CIPH-002", "WEAK-CIPH-003", "WEAK-CIPH-004", "WEAK-CIPH-005"]

        if s.channel_type == ChannelType.PLAINTEXT:
            for r_id in cipher_rules:
                findings.append(self._make_finding(
                    r_id,
                    status   = FindingStatus.NOT_EVALUATED,
                    observed = "PLAINTEXT",
                    details  = "Session transmitted in cleartext; cipher evaluation not applicable",
                ))
            return findings

        if not cipher or cipher.startswith("0X"):
            # Missing or unparsed cipher
            is_trunc = s.handshake_status in ("INCONCLUSIVE_TRUNCATED", "INCONCLUSIVE_CLIENT_HELLO_ONLY", "INCONCLUSIVE_NO_HANDSHAKE")
            status = FindingStatus.INCONCLUSIVE if is_trunc else FindingStatus.NOT_EVALUATED
            for r_id in cipher_rules:
                findings.append(self._make_finding(
                    r_id,
                    status     = status,
                    confidence = ConfidenceLevel.LOW,
                    observed   = cipher or "None",
                    details    = f"Selected cipher suite uncaptured or unparsed ({s.handshake_status})",
                ))
            return findings

        # Evaluate specific weak cipher patterns
        # WEAK-CIPH-001 (RC4)
        if "RC4" in cipher:
            findings.append(self._make_finding(
                "WEAK-CIPH-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = s.cipher_suite,
                expected   = "AEAD (AES-GCM, ChaCha20-Poly1305)",
                extra_desc = f"Detected: {s.cipher_suite}",
            ))
        else:
            findings.append(self._make_finding("WEAK-CIPH-001", status=FindingStatus.PASS, observed=s.cipher_suite))

        # WEAK-CIPH-002 (3DES)
        if "3DES" in cipher or "TDEA" in cipher:
            findings.append(self._make_finding(
                "WEAK-CIPH-002",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = s.cipher_suite,
                expected   = "AEAD (AES-GCM, ChaCha20-Poly1305)",
                extra_desc = f"Detected: {s.cipher_suite}",
            ))
        else:
            findings.append(self._make_finding("WEAK-CIPH-002", status=FindingStatus.PASS, observed=s.cipher_suite))

        # WEAK-CIPH-003 (NULL)
        if "_NULL_" in cipher or cipher.endswith("_NULL") or cipher == "TLS_NULL_WITH_NULL_NULL":
            findings.append(self._make_finding(
                "WEAK-CIPH-003",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = s.cipher_suite,
                expected   = "Authenticated Encryption",
                extra_desc = f"Detected: {s.cipher_suite}",
            ))
        else:
            findings.append(self._make_finding("WEAK-CIPH-003", status=FindingStatus.PASS, observed=s.cipher_suite))

        # WEAK-CIPH-004 (EXPORT)
        if "EXPORT" in cipher:
            findings.append(self._make_finding(
                "WEAK-CIPH-004",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = s.cipher_suite,
                expected   = "Standard Strength (>= 128 bits)",
                extra_desc = f"Detected: {s.cipher_suite}",
            ))
        else:
            findings.append(self._make_finding("WEAK-CIPH-004", status=FindingStatus.PASS, observed=s.cipher_suite))

        # WEAK-CIPH-005 (Generic weak / Anonymous)
        if "DH_ANON" in cipher or "AECDH" in cipher or "DES_CBC" in cipher:
            findings.append(self._make_finding(
                "WEAK-CIPH-005",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = s.cipher_suite,
                expected   = "Authenticated TLS cipher",
                extra_desc = f"Detected: {s.cipher_suite}",
            ))
        else:
            findings.append(self._make_finding("WEAK-CIPH-005", status=FindingStatus.PASS, observed=s.cipher_suite))

        return findings

    def _eval_forward_secrecy(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        if s.channel_type == ChannelType.PLAINTEXT:
            findings.append(self._make_finding("FS-001", status=FindingStatus.NOT_EVALUATED, observed="PLAINTEXT"))
            findings.append(self._make_finding("FS-002", status=FindingStatus.NOT_EVALUATED, observed="PLAINTEXT"))
            return findings

        ke = s.key_exchange
        if ke is None or ke == KeyExchange.UNKNOWN:
            status = FindingStatus.INCONCLUSIVE if s.handshake_status != "COMPLETED" else FindingStatus.NOT_EVALUATED
            findings.append(self._make_finding("FS-001", status=status, confidence=ConfidenceLevel.LOW, observed="UNKNOWN"))
            findings.append(self._make_finding("FS-002", status=status, confidence=ConfidenceLevel.LOW, observed="UNKNOWN"))
            return findings

        # FS-001: Missing forward secrecy
        if ke in (KeyExchange.RSA,):
            fs1 = self._make_finding(
                "FS-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = ke.value,
                expected   = "ECDHE or DHE",
                extra_desc = f"Key exchange: {ke.value}",
                is_primary = True,
            )
            findings.append(fs1)

            # FS-002: Static RSA key exchange (subsumed by FS-001)
            fs2 = self._make_finding(
                "FS-002",
                status        = FindingStatus.VIOLATION,
                confidence    = ConfidenceLevel.CONFIRMED,
                observed      = ke.value,
                expected      = "ECDHE or DHE",
                extra_desc    = "Static RSA key transport detected",
                is_primary    = not self.deduplicate,
                suppressed_by = "FS-001" if self.deduplicate else None,
            )
            findings.append(fs2)
        else:
            findings.append(self._make_finding("FS-001", status=FindingStatus.PASS, observed=ke.value))
            findings.append(self._make_finding("FS-002", status=FindingStatus.PASS, observed=ke.value))

        return findings

    def _eval_certificates(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        cert_rules = ["CERT-001", "CERT-002", "CERT-003", "CERT-004", "CERT-005", "CERT-006", "CERT-007", "CERT-008", "CERT-009"]
        cert = s.cert

        if s.channel_type == ChannelType.PLAINTEXT:
            for r_id in cert_rules:
                findings.append(self._make_finding(r_id, status=FindingStatus.NOT_EVALUATED, observed="PLAINTEXT"))
            return findings

        if cert is None or cert.validity == CertValidity.UNKNOWN:
            # Check if TLS handshake was truncated before certificate message
            is_trunc = s.handshake_status in ("INCONCLUSIVE_TRUNCATED", "INCONCLUSIVE_CLIENT_HELLO_ONLY", "INCONCLUSIVE_NO_HANDSHAKE")
            status = FindingStatus.INCONCLUSIVE if is_trunc else FindingStatus.NOT_EVALUATED
            for r_id in cert_rules:
                findings.append(self._make_finding(
                    r_id,
                    status     = status,
                    confidence = ConfidenceLevel.LOW,
                    observed   = "None",
                    details    = "X.509 certificate was not captured in session stream",
                ))
            return findings

        # CERT-001 (Expired)
        if cert.validity == CertValidity.EXPIRED:
            findings.append(self._make_finding(
                "CERT-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"Expired: {cert.not_after}",
                expected   = "Valid activation window",
                extra_desc = f"Expired: {cert.not_after}",
            ))
        else:
            findings.append(self._make_finding("CERT-001", status=FindingStatus.PASS, observed=cert.not_after))

        # CERT-002 (Not Yet Valid)
        if cert.validity == CertValidity.NOT_YET_VALID:
            findings.append(self._make_finding(
                "CERT-002",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"NotBefore: {cert.not_before}",
                expected   = "Valid activation window",
                extra_desc = f"NotBefore: {cert.not_before}",
            ))
        else:
            findings.append(self._make_finding("CERT-002", status=FindingStatus.PASS, observed=cert.not_before))

        # CERT-003 (Self-Signed)
        if cert.is_self_signed or cert.validity == CertValidity.SELF_SIGNED:
            findings.append(self._make_finding(
                "CERT-003",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"Subject=Issuer: {cert.subject_cn}",
                expected   = "CA-Signed Certificate Chain",
                extra_desc = f"Subject=Issuer: {cert.subject_cn}",
            ))
        else:
            findings.append(self._make_finding("CERT-003", status=FindingStatus.PASS, observed=cert.issuer_cn))

        # CERT-004 & CERT-005 (Key sizes)
        key_len = cert.key_length_bits
        key_type = (cert.key_type or "").upper()
        sig = (cert.signature_algorithm or "").upper()

        if key_len is not None:
            if ("EC" in key_type or "EC" in sig) and key_len < 224:
                findings.append(self._make_finding(
                    "CERT-005",
                    status     = FindingStatus.VIOLATION,
                    confidence = ConfidenceLevel.CONFIRMED,
                    observed   = f"{key_len} bits",
                    expected   = ">= 224 bits",
                    extra_desc = f"EC key size: {key_len} bits",
                ))
            else:
                findings.append(self._make_finding("CERT-005", status=FindingStatus.PASS, observed=f"{key_len} bits"))

            if ("RSA" in key_type or "RSA" in sig or "DH" in key_type) and key_len < 2048:
                findings.append(self._make_finding(
                    "CERT-004",
                    status     = FindingStatus.VIOLATION,
                    confidence = ConfidenceLevel.CONFIRMED,
                    observed   = f"{key_len} bits",
                    expected   = ">= 2048 bits",
                    extra_desc = f"Key size: {key_len} bits",
                ))
            else:
                findings.append(self._make_finding("CERT-004", status=FindingStatus.PASS, observed=f"{key_len} bits"))
        else:
            findings.append(self._make_finding("CERT-004", status=FindingStatus.NOT_EVALUATED))
            findings.append(self._make_finding("CERT-005", status=FindingStatus.NOT_EVALUATED))

        # CERT-006 & CERT-007 (Signature algorithms)
        if "MD5" in sig:
            findings.append(self._make_finding(
                "CERT-007",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = cert.signature_algorithm,
                expected   = "SHA-256 or SHA-384",
                extra_desc = f"Algorithm: {cert.signature_algorithm}",
            ))
        else:
            findings.append(self._make_finding("CERT-007", status=FindingStatus.PASS, observed=cert.signature_algorithm))

        if "SHA1" in sig or "SHA-1" in sig:
            findings.append(self._make_finding(
                "CERT-006",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = cert.signature_algorithm,
                expected   = "SHA-256 or SHA-384",
                extra_desc = f"Algorithm: {cert.signature_algorithm}",
            ))
        else:
            findings.append(self._make_finding("CERT-006", status=FindingStatus.PASS, observed=cert.signature_algorithm))

        # CERT-008 (Cryptographic Signature Verification Failure)
        if cert.signature_valid is False:
            findings.append(self._make_finding(
                "CERT-008",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = "Signature verification failed",
                expected   = "Valid cryptographic signature",
                details    = "; ".join(cert.diagnostics),
            ))
        elif cert.signature_valid is True:
            findings.append(self._make_finding("CERT-008", status=FindingStatus.PASS, observed="Verified"))
        else:
            findings.append(self._make_finding("CERT-008", status=FindingStatus.NOT_EVALUATED))

        # CERT-009 (SNI vs SAN/CN Mismatch)
        if cert.san_matches_sni is False:
            findings.append(self._make_finding(
                "CERT-009",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"SNI '{s.sni}' does not match SANs {cert.san_list} or CN '{cert.subject_cn}'",
                expected   = f"SAN/CN matching '{s.sni}'",
                extra_desc = f"SNI mismatch: {s.sni}",
            ))
        elif cert.san_matches_sni is True:
            findings.append(self._make_finding("CERT-009", status=FindingStatus.PASS, observed=s.sni))
        else:
            findings.append(self._make_finding("CERT-009", status=FindingStatus.NOT_EVALUATED))

        return findings

    def _eval_starttls(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        status = s.starttls_status
        starttls_rules = ["STARTTLS-001", "STARTTLS-002", "STARTTLS-003", "STARTTLS-004", "STARTTLS-005"]

        if status == StarttlsStatus.INCONCLUSIVE:
            for r_id in starttls_rules:
                findings.append(self._make_finding(
                    r_id,
                    status     = FindingStatus.INCONCLUSIVE,
                    confidence = ConfidenceLevel.LOW,
                    observed   = "INCONCLUSIVE",
                    details    = "Capture truncated or incomplete during STARTTLS negotiation",
                ))
            return findings

        # STARTTLS-001: Confirmed stripping with credential fallback
        if status == StarttlsStatus.STRIPPED:
            findings.append(self._make_finding(
                "STARTTLS-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = "STRIPPED",
                expected   = "STARTTLS Advertised & Negotiated",
                details    = "STARTTLS omitted from EHLO reply and client transmitted cleartext credentials",
            ))
        else:
            findings.append(self._make_finding("STARTTLS-001", status=FindingStatus.PASS, observed=status.value))

        # STARTTLS-005: Suspected / unconfirmed stripping
        if status == StarttlsStatus.POSSIBLE_STRIPPING:
            findings.append(self._make_finding(
                "STARTTLS-005",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.MEDIUM,
                observed   = "POSSIBLE_STRIPPING",
                expected   = "STARTTLS Advertised",
                details    = "STARTTLS omitted on expected submission port without observed authentication",
            ))
        else:
            findings.append(self._make_finding("STARTTLS-005", status=FindingStatus.PASS, observed=status.value))

        # STARTTLS-002: Negotiation failed
        if status == StarttlsStatus.FAILED:
            findings.append(self._make_finding(
                "STARTTLS-002",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = "FAILED",
                expected   = "220 Ready to start TLS",
                details    = "Server rejected STARTTLS upgrade request or acknowledged but resumed in cleartext",
            ))
        else:
            findings.append(self._make_finding("STARTTLS-002", status=FindingStatus.PASS, observed=status.value))

        # STARTTLS-003: Advertised but client did not request
        if status == StarttlsStatus.ADVERTISED:
            findings.append(self._make_finding(
                "STARTTLS-003",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = "ADVERTISED",
                expected   = "STARTTLS Requested",
                details    = "Server offered STARTTLS capability but client continued in cleartext",
            ))
        else:
            findings.append(self._make_finding("STARTTLS-003", status=FindingStatus.PASS, observed=status.value))

        # STARTTLS-004: Buffer injection
        if s.buffer_injection_detected:
            findings.append(self._make_finding(
                "STARTTLS-004",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = "BUFFER_INJECTION_DETECTED",
                expected   = "Strict protocol boundary synchronization",
                details    = "Cleartext application commands pipelined across the TLS transition boundary",
            ))
        else:
            findings.append(self._make_finding("STARTTLS-004", status=FindingStatus.PASS, observed="No injection detected"))

        return findings

    def _eval_protocol_context(self, s: SessionAnalysis) -> list[Violation]:
        findings = []
        port = s.dst_port
        proto = s.protocol

        # PROTO-001 (Cleartext submission port 25 or 587)
        if s.channel_type == ChannelType.PLAINTEXT and proto == Protocol.SMTP and port in (25, 587):
            findings.append(self._make_finding(
                "PROTO-001",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"Port: {port}",
                expected   = "TLS Encrypted Submission",
                extra_desc = f"Port: {port}",
                details    = f"SMTP submission on port {port} without TLS encryption violates RFC 8314 §3",
            ))
        else:
            findings.append(self._make_finding("PROTO-001", status=FindingStatus.PASS, observed=f"Port: {port}"))

        # PROTO-002 (Cleartext mail access on 143 or 110)
        if s.channel_type == ChannelType.PLAINTEXT and proto in (Protocol.IMAP, Protocol.POP3) and port in (143, 110):
            findings.append(self._make_finding(
                "PROTO-002",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"Port: {port}",
                expected   = "Port 993 (IMAPS) or 995 (POP3S)",
                extra_desc = f"Port: {port}",
                details    = f"Cleartext {proto.value} access on port {port} violates RFC 8314 §3 mandate",
            ))
        else:
            findings.append(self._make_finding("PROTO-002", status=FindingStatus.PASS, observed=f"Port: {port}"))

        # PROTO-003 (Opportunistic STARTTLS instead of Implicit TLS for mail access)
        if s.channel_type == ChannelType.STARTTLS and proto in (Protocol.IMAP, Protocol.POP3) and port in (143, 110):
            target_port = 993 if proto == Protocol.IMAP else 995
            target_name = "IMAPS" if proto == Protocol.IMAP else "POP3S"
            findings.append(self._make_finding(
                "PROTO-003",
                status     = FindingStatus.VIOLATION,
                confidence = ConfidenceLevel.CONFIRMED,
                observed   = f"STARTTLS on port {port}",
                expected   = f"Port {target_port} ({target_name})",
                extra_desc = f"Use port {target_port} ({target_name}) instead",
            ))
        else:
            findings.append(self._make_finding("PROTO-003", status=FindingStatus.PASS))

        return findings

    # -----------------------------------------------------------------------
    # Main Evaluator Entry Point
    # -----------------------------------------------------------------------

    def evaluate(self, session: SessionAnalysis) -> PolicyEvaluationReport:
        """
        Evaluate full session against policy catalog.
        Returns PolicyEvaluationReport containing active violations and all findings.
        """
        all_findings: list[Violation] = []

        all_findings.extend(self._eval_tls_version(session))
        all_findings.extend(self._eval_ciphers(session))
        all_findings.extend(self._eval_forward_secrecy(session))
        all_findings.extend(self._eval_certificates(session))
        all_findings.extend(self._eval_starttls(session))
        all_findings.extend(self._eval_protocol_context(session))

        # Filter active violations (primary violations if deduplicated)
        active_violations = [
            f for f in all_findings
            if f.status == FindingStatus.VIOLATION and (f.is_primary or not self.deduplicate)
        ]

        return PolicyEvaluationReport(
            violations   = active_violations,
            all_findings = all_findings,
        )


# ---------------------------------------------------------------------------
# Backwards-compatible Helper Function
# ---------------------------------------------------------------------------

def _make(v_tuple, extra_desc: str = "") -> Violation:
    code, desc, sev, ref = v_tuple
    full_desc = f"{desc}. {extra_desc}".strip(" .") if extra_desc else desc
    return Violation(
        code        = code,
        description = full_desc,
        severity    = sev,
        reference   = ref,
        rule_id     = code,
    )


def run_rules(
    session: SessionAnalysis,
    policy: Optional[PolicyCatalog] = None,
    deduplicate: bool = True,
) -> List[Violation]:
    """
    Run all compliance checks on a SessionAnalysis and return a list of active violations.
    Also populates session.policy_findings with the full evaluation matrix.
    This is the primary entry point for Pipeline Stage 9.
    """
    engine = PolicyEngine(policy=policy, deduplicate=deduplicate)
    report = engine.evaluate(session)

    # Attach complete evaluation matrix to session
    session.violations = report.violations
    session.policy_findings = report.all_findings

    return report.violations
