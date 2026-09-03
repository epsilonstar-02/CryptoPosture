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

## 🧪 Demo Scenarios

Five synthetic forensic test PCAPs are pre-generated:

| File | Expected Score | Expected Risk |
|---|---|---|
| `clean_implicit_tls.pcap` | 90-100 | LOW |
| `weak_cipher_starttls.pcap` | 35-55 | HIGH (3DES, TLS 1.0, no FS) |
| `stripped_starttls_plaintext.pcap` | 0 | CRITICAL (no TLS, cleartext) |
| `expired_cert_implicit_tls.pcap` | 70-95 | LOW-MEDIUM |
| `buffer_injection_attack.pcap` | 25-40 | HIGH (Poddebniak injection) |

---

## 🛠 CLI Usage

```bash
# Analyze a PCAP file (prints JSON)
python main.py --analyze sample_pcaps/weak_cipher_starttls.pcap

# Export an HTML forensic report
python main.py --analyze sample_pcaps/buffer_injection_attack.pcap --html --output report.html

# Regenerate synthetic demo PCAPs
python main.py --generate-samples

# Launch Streamlit dashboard
python main.py --run-dashboard

# Launch FastAPI REST server (docs at :8000/docs)
python main.py --run-api

# Run test suite (15 tests)
python main.py --test
```

---

## 📐 Scoring Model

```
S_session = max(0, sum(wi * Si) - sum(Pk))
```

| Sub-Domain | Weight | Score Criteria |
|---|---|---|
| TLS Version | 0.25 | TLS 1.3=100, TLS 1.2=80, TLS 1.1=20, TLS 1.0=0 |
| Cipher Suite | 0.20 | AEAD=100, CBC=50, 3DES=10, RC4/NULL=0 |
| Certificate Health | 0.20 | Valid public CA=100, Self-signed=70, Expired=10 |
| STARTTLS Transition | 0.15 | Implicit TLS=100, STARTTLS=80, Plaintext=0 |
| Forward Secrecy | 0.10 | ECDHE=90, DHE=70, RSA=0 |
| Protocol Context | 0.10 | SMTPS/IMAPS=100, Port 587=80, Cleartext port 25=20 |

**Enterprise Posture Index** = volume-weighted harmonic mean across all sessions.

Risk tiers: `90-100 LOW` | `75-89 GOOD` | `50-74 MEDIUM` | `25-49 HIGH` | `0-24 CRITICAL`

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
│   └── pcap_generator.py    — Synthetic PCAP generation (5 scenarios)
├── api/
│   └── app.py               — FastAPI REST API
├── dashboard/
│   └── app.py               — Streamlit interactive dashboard
├── sample_pcaps/            — Generated forensic test PCAPs
├── tests/
│   └── test_end_to_end.py   — 15 integration + unit tests
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