# Product Requirements Document & Build Roadmap
## AI-Assisted Passive Network Forensic Framework for Enterprise Email Cryptographic Posture Assessment
**Context:** Smart India Hackathon (SIH) submission · Team of 2–3 · Build window: 7–10 days · Deliverables: working prototype + pitch deck

---

## 0. Reality Check First

The source documents describe a research-grade system: 10-stage pipeline, JA4/JA4S/JA4X/JA4T fingerprinting, Cisco Mercury fusion, MTA-STS/DANE DNS auditing, PQC drift tracking, a Cost-Sensitive Random Forest + Isolation Forest + TreeSHAP ML stack, and a CycloneDX CBOM exporter. That is a 6–12 month research project, not a 10-day build.

**The job for the next 10 days is not to build all of it — it's to build a working, demoable slice that proves the concept, plus a deck that convincingly sells the full vision.** Judges at SIH reward: a working demo, a clear problem-solution narrative, technical depth they can verify live, and evidence you understand what's real vs. roadmap. This PRD is scoped accordingly — an MVP core plus a clearly labeled "future roadmap" tier for everything that doesn't fit.

Everything below is organized into:
- **P0 (Must-Have / Demo Core)** — has to work live, no excuses
- **P1 (Should-Have / Stretch)** — build if time remains, big demo impact per effort
- **P2 (Vision / Roadmap slide only)** — described in the PPT, not built

---

## 1. Problem Statement

Enterprise email (SMTP/IMAP/POP3) still relies heavily on opportunistic TLS (STARTTLS), which fails open to plaintext on error and is vulnerable to stripping, buffer-injection, and cross-protocol confusion attacks (ALPACA). Existing tools (Wireshark, Zeek) decode packets and log protocol events but don't **synthesize cryptographic parameters across a session into a single, quantifiable, explainable posture score**. SOCs and auditors have no passive, evidence-safe way to answer "is this captured email traffic actually secure, and where exactly did it fail?"

## 2. Goal for the Hackathon

Build a tool that ingests a PCAP of email traffic and outputs, per session:
1. Whether encryption was used at all, and how it was negotiated (implicit TLS vs. STARTTLS vs. plaintext)
2. Whether the TLS handshake and certificate meet modern standards
3. A single explainable **0–100 Cryptographic Posture Score**
4. A flagged list of concrete violations (deprecated protocol, weak cipher, expired cert, stripped STARTTLS, etc.)
5. A dashboard/report a non-expert judge can read in 30 seconds

That is the whole pitch. Everything else (JA4 fingerprinting, ML anomaly detection, DNS auditing, PQC tracking) is either a stretch feature or a roadmap slide.

## 3. Target Users (for the deck)

- **SOC analysts** — need fast triage of "is this session bad, and why"
- **DFIR investigators** — need a defensible, exportable report for incident writeups
- **Compliance auditors** — need a pass/fail against known baselines (NIST SP 800-52, RFC 9325)

## 4. Scope

### 4.1 P0 — Must-Have (the demo has to run on this)

| # | Feature | What it does | Why P0 |
|---|---|---|---|
| 1 | **PCAP ingestion** | Load a `.pcap`/`.pcapng`, validate it, compute a SHA-256 hash for "evidence integrity" | Entry point of the whole pipeline; also a cheap, impressive "forensic soundness" talking point |
| 2 | **TCP stream reassembly** | Reconstruct bidirectional SMTP/IMAP/POP3 sessions from packets | Nothing downstream works without this |
| 3 | **STARTTLS state tracking** | Detect: plaintext-only, STARTTLS advertised/negotiated/failed, or implicit TLS (ports 465/993/995) | This is the single most demo-able "wow, it caught that" feature |
| 4 | **TLS handshake parsing** | Extract TLS version, cipher suite, key exchange (RSA/DHE/ECDHE) from ClientHello/ServerHello | Core of the posture score |
| 5 | **X.509 certificate parsing** | Extract validity dates, key size, signature algorithm, self-signed/expired flags | Core of the posture score |
| 6 | **Deterministic rule engine** | Hard-coded checks against NIST SP 800-52 Rev.2 / RFC 9325: flag SSLv2/3, TLS 1.0/1.1, RC4/3DES/NULL ciphers, MD5/SHA-1 signatures, expired certs, key <2048-bit RSA | This *is* the product's credibility — deterministic, explainable, no ML needed to be trustworthy |
| 7 | **Posture scoring formula** | Implement `S_session = max(0, Σ(wᵢ·Sᵢ) − ΣPₖ)` across the 6 sub-domains from the synopsis (TLS version, cipher, cert health, STARTTLS/transition, forward secrecy, protocol context) | This is your headline metric — the number judges will remember |
| 8 | **Report output** | JSON export per session + a human-readable summary (table or simple HTML) | Judges need to see structured, exportable forensic output |
| 9 | **Minimal dashboard/UI** | A simple web page or Streamlit app: upload PCAP → table of sessions → posture score, risk tier, and violation list | This is what's on screen during the live demo |
| 10 | **Synthetic demo PCAPs** | 3–5 curated `.pcap` files you generate/capture yourself showing: (a) clean implicit TLS session, (b) STARTTLS with weak cipher, (c) plaintext/stripped STARTTLS, (d) expired cert | **Critical** — do not rely on finding "real" vulnerable traffic; build your own demo data early (see Day 2 below) |

### 4.2 P1 — Should-Have (stretch, high demo value per hour of effort)

| # | Feature | Why it's worth it if time allows |
|---|---|---|
| 11 | **Risk tier classification (rule-based, not ML)** | LOW/MEDIUM/HIGH/CRITICAL bucket from the posture score — gives judges an instant traffic-light read without needing real ML |
| 12 | **JA4 client fingerprint (simplified)** | Even a partial JA4 (TLS version + cipher count + SNI presence, skip the full spec) is an easy "we implemented real fingerprinting research" line |
| 13 | **Isolation Forest anomaly flag** | `sklearn.ensemble.IsolationForest` on your extracted feature vector — a few lines of code, but lets you legitimately say "unsupervised ML anomaly detection" in the pitch |
| 14 | **Command-injection / buffer-pipelining detector** | Check for cleartext application bytes appended in the same TCP segment as the STARTTLS response — directly demonstrates you understood the Poddebniak et al. research, which is a strong differentiation point |
| 15 | **Enterprise Posture Index (aggregate)** | The volume-weighted harmonic mean across all sessions in a capture — one more headline number for the exec-summary view |

### 4.3 P2 — Vision / Roadmap Slide Only (do NOT attempt to build)

- Full JA4S / JA4X / JA4T / Cisco Mercury multi-layer fingerprint fusion
- Passive MTA-STS / DANE DNS auditing
- Post-quantum readiness state classification (X25519MLKEM768 detection)
- Cost-Sensitive Random Forest supervised classifier (needs labeled training data you don't have time to build)
- TreeSHAP explainability layer
- CycloneDX CBOM export
- ALPACA cross-protocol confusion detection (needs multi-protocol capture correlation — high effort, low demo payoff)
- React/Plotly production dashboard, SIEM integration

Present this tier explicitly on a **"Roadmap Beyond the Hackathon"** slide. Judges consistently reward teams who show they know the difference between what they built and what they're claiming — it reads as maturity, not weakness.

## 5. Non-Functional Requirements

- **Must run offline / air-gapped** during the demo (no dependency on live internet lookups — this also matches the "passive, out-of-band forensic" story)
- **Must process a demo PCAP (a few hundred packets) in under ~10 seconds** — nothing kills a demo like a spinner
- **Evidence immutability**: never write to the original PCAP; hash it on ingest and display the hash in the UI (cheap, real forensic-soundness signal)
- **Reproducible setup**: one `requirements.txt` / `setup.sh` a judge or teammate can run in under 5 minutes

## 6. Recommended Tech Stack

| Layer | Tool | Why |
|---|---|---|
| Packet parsing / TCP reassembly | **Scapy** (Python) | Fastest to prototype with; handles PCAP read + TCP/IP dissection out of the box |
| TLS/X.509 deep parsing | **Scapy's TLS layer**, or `cryptography` + manual ClientHello/ServerHello byte parsing if Scapy's TLS support is too limited | Fallback plan matters — test this on Day 1 |
| Rule engine | Plain Python (dict-based rule table) | No need for a framework; keep it simple and legible for judges reading your code |
| ML (P1 only) | `scikit-learn` (IsolationForest) | Minimal setup, well documented, fast to fit on small feature sets |
| Backend/API | **FastAPI** | Async, auto-generates OpenAPI docs (nice to show), trivial to wire to a frontend |
| Frontend/dashboard | **Streamlit** (fastest) or a minimal React page if a teammate is strong in frontend | Streamlit lets one person build upload→table→score UI in a few hours |
| Report export | Plain `json.dumps` + Jinja2-rendered HTML/PDF summary | Don't build a real PDF pipeline from scratch — Jinja2 → HTML → browser print-to-PDF is enough |
| Demo PCAPs | Your own mail server (e.g., local Postfix/Dovecot in Docker) + `openssl s_client`/`swaks` to force specific TLS versions/ciphers, captured with `tcpdump` | This is the single highest-leverage task — do it Day 1–2 |

## 7. Success Metrics (for your own tracking, and a good deck slide)

- Number of distinct violation types correctly detected across your demo PCAP set (target: 6+)
- End-to-end processing time per PCAP (target: <10s)
- Posture score correctly differentiates your "good," "medium," and "bad" demo sessions (e.g., 90+, 50–70, <30)
- Live demo runs without a crash, twice, in front of two different people, before the actual presentation

---

## 8. Team Split (2–3 people)

Assuming **3 people**; if you're 2, merge Track A and Track C.

- **Track A — Packet/Protocol Engineer**: PCAP ingestion, TCP reassembly, STARTTLS state machine, TLS/X.509 parsing (items 1–5)
- **Track B — Scoring/ML Engineer**: rule engine, posture scoring formula, risk tiers, JSON schema, (P1) Isolation Forest (items 6, 7, 11, 13)
- **Track C — Product/Frontend**: demo PCAP generation, dashboard/UI, report rendering, PPT and demo script (items 9, 10, and the deck)

All three converge for integration on Day 6–7.

## 9. Day-by-Day Roadmap (10-day version — cut Day 9 if you only have 7)

### Day 1 — Setup & Spike
- Repo, environment, dependency check (Scapy TLS parsing — confirm it works on a real TLS ClientHello before committing to it)
- Spin up a local mail server (Docker: Postfix + Dovecot, or use a pre-built "vulnerable mail lab" image) for generating demo traffic
- Define the exact JSON feature schema (see §10 below) — lock this early, everyone codes against it
- Finalize which sub-scope (P0 list) each track owns

### Day 2 — Demo Data + Ingestion
- **Highest priority task of the whole project**: capture 4–5 PCAPs showing distinct scenarios (clean implicit TLS / weak-cipher STARTTLS / plaintext-fallback / expired cert / stripped STARTTLS if you can simulate a MITM with `mitmproxy` or a simple STARTTLS-stripping proxy script)
- Build PCAP ingestion + SHA-256 hashing + basic packet loading

### Day 3 — Stream Reassembly & STARTTLS State Machine
- TCP 5-tuple tracking, bidirectional stream reconstruction
- Finite-state tracking of STARTTLS: none → advertised → requested → acknowledged → TLS record start (or: failed/stripped)
- Unit-test this against your Day 2 PCAPs — this is the feature most likely to visibly wow judges, get it rock solid

### Day 4 — TLS + X.509 Parsing
- Extract TLS version, cipher suite, key exchange type from the handshake
- Parse certificate: validity window, key size, signature algorithm, self-signed check
- Handle parse failures gracefully (malformed/incomplete handshakes should not crash the pipeline)

### Day 5 — Rule Engine + Scoring
- Implement the deterministic violation rules (§4.1 item 6)
- Implement the posture scoring formula with the 6 weighted sub-domains and penalty deductions
- Output the full JSON per session

### Day 6 — Integration + Dashboard v1
- Wire ingestion → reassembly → parsing → scoring into one pipeline (FastAPI endpoint or CLI, whichever is faster for your team)
- Streamlit/React dashboard: upload PCAP, see a session table with posture score + risk tier + violations
- **Full pipeline should run end-to-end on at least one demo PCAP by end of Day 6** — this is your integration checkpoint; if it's not working, cut a P1 feature immediately rather than let this slip

### Day 7 — Stretch Features (only if Day 6 checkpoint passed)
- Pick 1–2 from the P1 list based on what's most demo-compelling and least risky (recommend: risk tiers first — cheapest; command-injection detector second — most differentiating)
- Polish the dashboard (violation explanations in plain English, not just codes)

### Day 8 — Report Export + Hardening
- JSON schema finalization, HTML/PDF summary export
- Error handling pass: what happens with a corrupt PCAP, an empty capture, a non-email PCAP? Judges do sometimes prod at edge cases
- Freeze features. No new code after today.

### Day 9 — PPT + Demo Script
- Build the deck (structure in §11)
- Write and rehearse a 3–4 minute live demo script: which PCAP you upload, what you point at on screen, in what order
- Record a backup demo video in case live networking/projector fails at the venue — **do this, it saves teams every year**

### Day 10 — Dry Run + Buffer
- Full dry run in front of someone outside the team
- Fix only what's broken; do not add features
- Charge laptops, export offline copies of everything, test on the actual presentation machine if possible

---

## 10. Session Feature Schema (lock this on Day 1)

```json
{
  "session_id": "string",
  "protocol": "SMTP | IMAP | POP3",
  "channel_type": "Implicit TLS | STARTTLS | Plaintext",
  "starttls_status": "None | Advertised | Negotiated | Failed | Stripped",
  "tls_version": "TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3 | null",
  "cipher_suite": "string",
  "key_exchange": "RSA | DHE | ECDHE | null",
  "cert": {
    "validity": "Valid | Expired | NotYetValid | SelfSigned",
    "key_length_bits": 2048,
    "signature_algorithm": "SHA256withRSA"
  },
  "violations": ["Deprecated TLS 1.0", "RSA key < 2048 bits"],
  "component_scores": {
    "tls_version": 80, "cipher_suite": 100, "cert_health": 90,
    "starttls_transition": 80, "forward_secrecy": 90, "protocol_context": 100
  },
  "posture_score": 87.5,
  "risk_tier": "LOW | MEDIUM | HIGH | CRITICAL"
}
```

## 11. Suggested PPT Structure (SIH decks are usually ~10–12 slides)

1. **Title** — project name, team, problem statement in one line
2. **Problem** — why email TLS is still broken (STARTTLS fail-open, real CVE-style stats from Durumeric/Poddebniak/Brinkmann papers — cite the actual numbers, e.g., only ~35% of servers configured for strict auth)
3. **Why existing tools fall short** — the Wireshark/Zeek/Cisco Mercury comparison table from the research doc (this table is already built for you — reuse it)
4. **Our approach** — the pipeline diagram, scoped honestly to what's built (P0) vs. planned (P2)
5. **Architecture** — simplified version of the 10-stage pipeline table, P0 stages highlighted
6. **The scoring model** — show the formula and the 6 weighted sub-domains; this is your "mathematically rigorous" credibility slide
7. **Live demo / demo screenshots** — screenshot the dashboard on 2–3 of your demo PCAPs (plus do it live)
8. **What makes this novel** — STARTTLS downgrade causality tracking, explainable deterministic scoring (not a black box), passive/out-of-band evidence-safe design
9. **Tech stack**
10. **Roadmap beyond the hackathon** — the P2 list, framed as vision (JA4+ fingerprinting, PQC readiness, XAI, DNS-based MTA-STS/DANE auditing, enterprise dashboard)
11. **Impact** — who uses this (SOC/DFIR/auditors) and what it saves them (time-to-triage, defensibility of findings)
12. **Team + thank you**

---

## 12. Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Can't find/capture realistic vulnerable email PCAPs | Build your own lab (Day 1–2) — don't depend on finding real-world captures; synthetic, clearly-labeled demo traffic is completely acceptable at SIH |
| TLS/X.509 byte-level parsing eats the whole week | Timebox Day 4 to one day; if Scapy's TLS layer is too limited, fall back to a minimal manual parser for just the fields you need (version, cipher suite ID, cert bytes) — you don't need a full TLS stack |
| Integration breaks late | Lock the JSON schema on Day 1, integrate early and often (don't wait until Day 6 to try connecting pieces for the first time) |
| Live demo fails at venue (wifi/projector/etc.) | Record a backup video on Day 9; test on presentation hardware if possible |
| Scope creep into P1/P2 features | Hard freeze after Day 8; the checkpoint on Day 6 (full pipeline runs end-to-end) is the gate — don't add stretch features before that passes |

---

**Bottom line:** win this with a small number of features that work reliably and a scoring model you can explain in one sentence ("we turn a packet capture into a single, explainable 0–100 security score, and show exactly why"), backed by a deck that's honest about what's built vs. what's roadmap. That combination beats a half-working attempt at the full research system every time.
