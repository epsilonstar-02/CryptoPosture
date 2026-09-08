# 🔐 AI-Assisted Passive Network Forensic Framework
## Enterprise Email Cryptographic Posture Assessment

> **Smart India Hackathon (SIH-26) Demo Prototype**

A passive, out-of-band forensic framework that ingests PCAP captures of enterprise email traffic (SMTP / IMAP / POP3) and produces per-session cryptographic posture scores, violation reports, and an Enterprise Posture Index — without transmitting a single packet.

---

## 🚀 Quick Start (5 minutes)

```bash
# Option A — Automated setup (recommended)
bash setup.sh
source .venv/bin/activate
streamlit run dashboard/app.py

# Option B — Manual (if you have uv installed)
uv sync
uv run streamlit run dashboard/app.py

# Option C — pip
pip install -r requirements.txt
streamlit run dashboard/app.py
```

Dashboard opens at **http://localhost:8501** — click any demo scenario in the sidebar.

---

## 📊 What It Does

For each email session in a PCAP file, the framework outputs:

| Output | Description |
|---|---|
| **SHA-256 hash** | Evidence integrity — the PCAP is never modified |
| **Channel type** | Implicit TLS / STARTTLS / Plaintext |
| **TLS version** | TLS 1.3, 1.2, 1.1, 1.0, SSLv3, SSLv2 |
| **Cipher suite** | Full IANA name; flags 3DES, RC4, NULL, export |
| **X.509 certificate** | Validity, key size, signature algorithm, self-signed flag |
| **Violation list** | Specific NIST SP 800-52 / RFC 9325 / RFC 8314 violations |
| **Posture score (0-100)** | S = max(0, sum(wi*Si) - sum(Pk)) across 6 weighted sub-domains |
| **Risk tier** | LOW / MEDIUM / HIGH / CRITICAL |
| **JA4 / JA4S / JA4X** | Multi-layer TLS and certificate fingerprints |
| **ML anomaly score** | Isolation Forest out-of-distribution detection |
| **Buffer injection flag** | Poddebniak et al. (USENIX Security 2021) attack detection |
| **Enterprise Posture Index** | Volume-weighted harmonic mean across all sessions |

---

---

## 🏢 Realistic Multi-Session Simulations & Benchmark Corpus

The framework includes realistic multi-session enterprise network captures, active attack campaign scenarios, and a 15-scenario ground-truth RFC/NIST validation benchmark:

### Multi-Session Enterprise Simulations
| Simulation File | Flows / Pkts | Description | Target Risk Tier |
|---|---|---|---|
| `enterprise_network_simulation.pcap` | **16 flows** / 119 pkts | Full corporate mail perimeter (Exec, Eng with PQC, HR, Finance, MTA, POP3S, CI/CD), legacy 3DES, expired certs, cleartext stripping, buffer injection | **CRITICAL** (EPI 1.02) |
| `mitm_attack_campaign.pcap` | **6 flows** / 46 pkts | Active adversarial campaign: credential theft via STARTTLS stripping, buffer injection exfiltration, forced downgrade to TLS 1.0/3DES, phishing SNI mismatch | **CRITICAL** (EPI 0.18) |
| `cloud_migration_audit.pcap` | **8 flows** / 63 pkts | Hybrid cloud migration exposure: modern M365/Workspace (TLS 1.3/PQC) vs legacy on-prem Exchange, unencrypted ERP, and shadow IT hardware | **CRITICAL** (EPI 0.83) |

### Ground-Truth Deterministic Benchmarks (15 PCAPs)
- **Tier 1 (Synthetic Fixtures):** `clean_implicit_tls`, `weak_cipher_starttls`, `stripped_starttls_plaintext`, `expired_cert_implicit_tls`, `buffer_injection_attack`
- **Tier 2 (Real Mail-Server Lab Captures):** `postfix_submission_tls13`, `dovecot_imaps_tls12`, `sendmail_opportunistic_starttls`
- **Tier 3 (Adversarial Edge Cases):** `cert_sni_mismatch`, `cert_weak_rsa1024`, `tcp_fragmented_client_hello`, `tcp_retransmission_duplicates`, `out_of_order_tcp_segments`, `malformed_tls_record_length`, `incomplete_tls_handshake_rst`

---

## 🛠 CLI Usage

```bash
# ⚡ Instant 1-Click Live Demo (analyzes 16-flow enterprise simulation)
python main.py --demo

# Analyze any PCAP/PCAPNG file (prints terminal executive summary + JSON)
python main.py --analyze sample_pcaps/enterprise_network_simulation.pcap

# Export an HTML forensic report
python main.py --analyze sample_pcaps/enterprise_network_simulation.pcap --html --output report.html

# Regenerate all benchmark PCAPs and enterprise simulations
python main.py --generate-samples

# Launch FastAPI REST server (docs at :8000/docs)
python main.py --run-api

# Run full test suite (258 automated tests)
python main.py --test
```

---

## 📐 Scoring Model (`crypto-posture-v1`)

The framework implements an **Evidence-Aware Multi-Dimensional Cryptographic Posture Model** with **Non-Additive Critical Score Caps** at the session level, aggregated to an enterprise posture index via a **Volume-Weighted Harmonic Mean**.

### Session Posture Formulation

$$w_i^{\text{eff}} = \frac{w_i}{\sum_{j \in \text{assessed}} w_j} \qquad S_{\text{renorm}} = \sum_{i \in \text{assessed}} w_i^{\text{eff}} \cdot S_i$$

$$S_{\text{session}} = \min\left(S_{\text{renorm}}, \text{Cap}_{\min}\right)$$

### 1. Calibrated Evaluation Dimensions & Base Weights

| Sub-Domain | Base Weight ($w_i$) | Scoring Criteria & Regulatory Grounding | Standards Authority |
|---|---|---|---|
| **TLS Version** | 0.25 | TLS 1.3 (100) > TLS 1.2 (80) > TLS 1.1 (20) > TLS 1.0/SSLv3 (0) | RFC 9325 / RFC 8996 / NIST SP 800-52r2 |
| **Cipher Suite** | 0.20 | AEAD (100) > CBC with SHA-256 (50) > 3DES (10) > RC4/NULL (0) | NIST SP 800-52r2 §3.3.1 / RFC 9325 |
| **Certificate Health** | 0.20 | Valid PKI chain & key ≥2048-bit RSA/256-bit ECC (100) > Self-signed (70) > Expired (10) | RFC 5280 / NIST SP 800-57 Part 1 |
| **STARTTLS Transition** | 0.15 | Implicit TLS (100) > Successful STARTTLS negotiation (80) > Cleartext fallback (0) | RFC 8314 §3 / RFC 3207 / RFC 3501 |
| **Forward Secrecy** | 0.10 | Ephemeral ECDHE (100) > DHE (80) > Static RSA without PFS (0) | RFC 9325 §4.2 / NIST SP 800-52r2 |
| **Protocol Hygiene** | 0.10 | ALPN, SNI, Extended Master Secret (100) > Downgrade/stripping, buffer injection (0) | RFC 8446 / RFC 7627 / Poddebniak et al. |

*Dynamic Renormalization:* When dimensions cannot be verified (e.g. non-mail protocol, unobserved certificate chain, or implicit TLS without STARTTLS negotiation), unobserved dimensions receive 0% effective weight ($w_i^{\text{eff}} = 0$) and evaluated dimensions dynamically scale so that $\sum w_i^{\text{eff}} = 1.0$.

### 2. Non-Additive Critical Score Caps

| Trigger Condition | Cap Ceiling | Vulnerability Impact | Reference |
|---|---|---|---|
| **Plaintext Mail / Cleartext Auth** | $\le 0.0$ | Total confidentiality compromise | RFC 8314 §3 |
| **SSLv2 / SSLv3 Active** | $\le 15.0$ | Prohibited obsolete protocols (POODLE/DROWN) | RFC 8996 |
| **Buffer Injection Detected** | $\le 15.0$ | Active command pipelining exploit across TLS boundary | USENIX Security '21 |
| **STARTTLS Stripping Downgrade** | $\le 15.0$ | Active MitM downgrade attack | RFC 3207 / RFC 8314 |
| **Prohibited / Null / Export Cipher** | $\le 20.0$ | Cryptographically void encryption | NIST SP 800-52r2 §3.3.1 |
| **Invalid / Self-Signed / Expired Cert** | $\le 60.0$ | Trust chain invalidation | RFC 5280 / NIST SP 800-57 |

### 3. Enterprise Aggregation & Calibrated Risk Tiers

$$H = \frac{\sum w_i}{\sum \frac{w_i}{S_i}}$$

Reconstructed TCP byte volume serves as the exposure proxy. The harmonic mean enforces the **Weakest-Link Principle** so that high-risk sessions cannot be averaged away.

| Risk Tier | Posture Range | Compliance State |
|---|---|---|
| **LOW** | $80.0 - 100.0$ | Compliant with modern RFC 9325 & NIST SP 800-52r2 |
| **MEDIUM** | $55.0 - 79.9$ | Operational with legacy configurations (e.g. CBC ciphers, self-signed certs) |
| **HIGH** | $30.0 - 54.9$ | Major vulnerabilities or deprecated protocols (TLS 1.0/1.1, missing PFS) |
| **CRITICAL** | $0.0 - 29.9$ | Catastrophic flaws: cleartext transmission, SSLv2/v3, buffer injection, stripping |

---

---

## 🧪 Three-Tier Evidence Laboratory & Ground-Truth Benchmark Suite

To ensure forensic credibility and prevent self-referential validation bias, the test corpus is partitioned into **three distinct tiers**, backed by an automated machine-readable manifest (`manifest.json`) and an independent reference verifier:

> ⚖️ **Judicial & Forensic Evidence Positioning**:  
> *"We use synthetic captures as controlled ground-truth fixtures for deterministic testing, and we separately validate the forensic pipeline against real mail-server captures."*

| Tier | Corpus Focus | Scenarios Included | Forensic Purpose |
|---|---|---|---|
| **Tier 1** | **Deterministic Synthetic Fixtures** | `clean_implicit_tls`<br>`weak_cipher_starttls`<br>`stripped_starttls_plaintext`<br>`expired_cert_implicit_tls`<br>`buffer_injection_attack` | Fixed cryptographic parameters, simulated Root CA hierarchy (no self-signed false positives on clean sessions), verified SHA-1 signatures, Poddebniak buffer injection. Exact ground-truth unit/regression verification. |
| **Tier 2** | **Real Mail-Server Lab Captures** | `postfix_submission_tls13`<br>`dovecot_imaps_tls12`<br>`sendmail_opportunistic_starttls` | Authentic Postfix 3.x, Dovecot, and Sendmail sessions with real TLS 1.3/1.2 handshakes, full extension suites (ALPN, key_share, supported_groups), and authentic TCP window dynamics. |
| **Tier 3** | **Adversarial & Edge Cases** | `tcp_fragmented_client_hello`<br>`out_of_order_tcp_segments`<br>`tcp_retransmission_duplicates`<br>`incomplete_tls_handshake_rst`<br>`malformed_tls_record_length`<br>`cert_weak_rsa1024`<br>`cert_sni_mismatch` | Robustness stress tests covering TCP segment fragmentation across packets, inverted sequence numbers, dropped-ACK retransmissions, abrupt RST termination, corrupted record lengths, weak 1024-bit RSA keys, and SNI mismatches. |

### Ground-Truth Benchmark Commands
```bash
# Generate all 15 scenarios across all 3 tiers and build manifest.json
python -m generator.pcap_generator --tier all --verify

# Run independent reference verifier (raw packet inspection without pipeline bias)
python -m generator.reference_verifier

# Run full ground-truth benchmark test suite
pytest tests/test_ground_truth_benchmark.py -v
```

---

## 📁 Project Structure

```
SIH-26-Demo/
├── core/
│   ├── models.py            — Data structures and PRD Section 10 JSON schema
│   ├── ingestion.py         — PCAP reader + SHA-256 evidence hashing
│   ├── reassembly.py        — TCP 5-tuple stream reassembly
│   ├── starttls_tracker.py  — STARTTLS FSM + buffer injection detector
│   ├── crypto_parser.py     — TLS ClientHello/ServerHello + X.509 parser
│   ├── fingerprinting.py    — JA4, JA4S, JA4X fingerprinting
│   ├── rule_engine.py       — NIST SP 800-52 / RFC 9325 compliance rules
│   ├── scorer.py            — Posture scoring formula + EPI aggregation
│   ├── ml_anomaly.py        — Isolation Forest anomaly detection
│   ├── report_exporter.py   — JSON + HTML report generation
│   └── pipeline.py          — End-to-end orchestration
├── generator/
│   ├── pcap_generator.py    — Three-Tier PCAP evidence generator & manifest builder
│   ├── reference_verifier.py— Independent raw-packet benchmark reference verifier
│   └── lab_capture_runner.py— Real mail-server live capture orchestration harness
├── api/
│   └── app.py               — FastAPI REST API
├── dashboard/
│   └── app.py               — Streamlit interactive dashboard
├── sample_pcaps/            — Generated PCAPs (15 scenarios) + manifest.json
├── tests/
│   ├── test_end_to_end.py   — 15 integration + unit tests
│   └── test_ground_truth_benchmark.py — 17 ground-truth & independent verification tests
├── main.py                  — Unified CLI
├── setup.sh                 — One-command reproducible setup
└── requirements.txt         — Pinned dependency list
```

---

## 🏛 Standards and References

- **NIST SP 800-52 Rev. 2** — Guidelines for TLS Implementation
- **RFC 9325 / BCP 195** — Secure Use of Transport Layer Security
- **RFC 8314** — Implicit TLS mandate (cleartext obsolete)
- **RFC 8996** — TLS 1.0 / TLS 1.1 deprecation
- **RFC 3207** — SMTP STARTTLS (opportunistic)
- **Poddebniak et al. (USENIX Security 2021)** — STARTTLS buffer injection attacks
- **Durumeric et al. (IMC 2015)** — Empirical analysis of email security
- **FoxIO JA4+** — Next-generation TLS fingerprinting

---

## Legal Notice

This tool is designed for authorized forensic analysis only. It operates passively on pre-captured PCAP evidence files and does not transmit any network traffic. All synthetic demo PCAPs use private IP address ranges and do not contain real user data.