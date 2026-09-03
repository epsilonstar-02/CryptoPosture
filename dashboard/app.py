"""
dashboard/app.py
Streamlit interactive forensic dashboard for the Email Cryptographic Forensics Framework.
Provides: PCAP upload, sample selection, live analysis, session explorer, and report export.

Run with: streamlit run dashboard/app.py
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import streamlit as st

# Ensure project root is on sys.path when running `streamlit run dashboard/app.py`
_root = Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from core.pipeline import analyze_pcap
from core.report_exporter import export_json, export_html
from generator.pcap_generator import generate_all, DEFAULT_OUTPUT_DIR, SCENARIO_GENERATORS, _SAMPLE_DESCRIPTIONS  # noqa

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="CryptoPosture — Email Forensic Framework",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS — dark premium theme
# ---------------------------------------------------------------------------

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
  }

  /* Main background */
  .main { background: #07071a; }
  .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d0d2b 0%, #0a0a1e 100%);
    border-right: 1px solid #1e1e3e;
  }

  /* Headers */
  h1 { font-weight: 900; letter-spacing: -1px; }
  h2 { font-weight: 700; }
  h3 { font-weight: 600; color: #7b9bff !important; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #0f0f1e;
    border: 1px solid #1e1e3e;
    border-radius: 12px;
    padding: 16px;
  }
  [data-testid="stMetricLabel"] { color: #888 !important; font-size: 0.8em !important; }
  [data-testid="stMetricValue"] { color: #e0e0ff !important; font-weight: 700; }

  /* Buttons */
  .stButton > button {
    background: linear-gradient(135deg, #3d5aff, #7b3dff);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.5em 1.2em;
    transition: opacity 0.2s;
  }
  .stButton > button:hover { opacity: 0.85; }

  /* File uploader */
  [data-testid="stFileUploader"] {
    background: #0f0f1e;
    border: 2px dashed #2a2a6e;
    border-radius: 12px;
    padding: 12px;
  }

  /* Expander */
  [data-testid="stExpander"] {
    background: #0f0f1e;
    border: 1px solid #1e1e3e;
    border-radius: 10px;
  }

  /* Code / mono */
  code { font-family: 'JetBrains Mono', monospace !important; color: #a0b0ff; }

  /* Divider */
  hr { border-color: #1e1e3e; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #0a0a1e; }
  ::-webkit-scrollbar-thumb { background: #2a2a6e; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SAMPLE_DIR = Path(DEFAULT_OUTPUT_DIR)

RISK_COLORS = {
    "CRITICAL": "#ff3b3b",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffe066",
    "LOW":      "#00d68f",
}

SAMPLE_DESCRIPTIONS = {
    "clean_implicit_tls":          "✅ IMAPS TLS 1.3, ECDHE, AES-256-GCM (Good session — expected LOW risk)",
    "weak_cipher_starttls":        "⚠️ SMTP STARTTLS, TLS 1.0, 3DES cipher (Deprecated — expected HIGH risk)",
    "stripped_starttls_plaintext": "🚨 SMTP STARTTLS stripped by MITM, cleartext AUTH (expected CRITICAL)",
    "expired_cert_implicit_tls":   "⚠️ IMAPS TLS 1.2, expired X.509 certificate (expected MEDIUM–HIGH)",
    "buffer_injection_attack":     "💀 SMTP STARTTLS + Poddebniak buffer injection attack (expected CRITICAL)",
}


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

if "summary" not in st.session_state:
    st.session_state.summary = None
if "analysis_time" not in st.session_state:
    st.session_state.analysis_time = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_color(score: float) -> str:
    if score >= 80: return "#00d68f"
    if score >= 55: return "#ffe066"
    if score >= 30: return "#ff9500"
    return "#ff3b3b"


def _badge_html(tier: str) -> str:
    color = RISK_COLORS.get(tier, "#aaa")
    return f'<span style="background:{color}20;color:{color};padding:2px 10px;border-radius:6px;font-weight:700;font-size:0.85em;border:1px solid {color}55;">{tier}</span>'


def _score_gauge(score: float, size: int = 80) -> str:
    color = _score_color(score)
    return f"""
    <div style="text-align:center;width:{size}px;display:inline-block;">
      <div style="font-size:{size//2.5:.0f}px;font-weight:900;color:{color};line-height:1;">{score:.0f}</div>
      <div style="font-size:{size//10:.0f}px;color:#666;font-weight:500;">/100</div>
    </div>
    """


def _ensure_samples():
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    missing = any(
        not (SAMPLE_DIR / f"{name}.pcap").exists()
        for name in SCENARIO_GENERATORS
    )
    if missing:
        with st.spinner("⚙️ Generating synthetic demo PCAPs..."):
            generate_all(SAMPLE_DIR)


def _run_analysis(filepath: str, filename: str = "") -> None:
    start = time.perf_counter()
    with st.spinner("🔍 Analyzing PCAP — running forensic pipeline..."):
        summary = analyze_pcap(filepath, run_ml=True)
    elapsed = time.perf_counter() - start

    if filename:
        summary.evidence.filename = filename

    st.session_state.summary       = summary
    st.session_state.analysis_time = elapsed


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:12px 0 20px;">
      <div style="font-size:2.5em;">🔐</div>
      <div style="font-weight:900;font-size:1.1em;color:#7b9bff;letter-spacing:-0.5px;">CryptoPosture</div>
      <div style="color:#555;font-size:0.75em;margin-top:2px;">Email Cryptographic Forensics</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # Upload section
    st.markdown("### 📁 Upload PCAP")
    uploaded_file = st.file_uploader(
        "Drag and drop or click to upload",
        type=["pcap", "pcapng"],
        label_visibility="collapsed",
    )
    if uploaded_file:
        if st.button("🔬 Analyze Uploaded File", use_container_width=True):
            with tempfile.NamedTemporaryFile(
                suffix=Path(uploaded_file.name).suffix, delete=False
            ) as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name
            try:
                _run_analysis(tmp_path, filename=uploaded_file.name)
            finally:
                os.unlink(tmp_path)

    st.divider()

    # Sample PCAP selector
    st.markdown("### 🧪 Demo PCAPs")
    _ensure_samples()

    for name, desc in SAMPLE_DESCRIPTIONS.items():
        path = SAMPLE_DIR / f"{name}.pcap"
        label = name.replace("_", " ").title()
        if st.button(f"{label}", key=f"sample_{name}", use_container_width=True, help=desc):
            _run_analysis(str(path), filename=f"{name}.pcap")

    st.divider()

    if st.button("🔄 Regenerate Demo PCAPs", use_container_width=True):
        with st.spinner("Generating..."):
            generate_all(SAMPLE_DIR)
        st.success("✅ Demo PCAPs regenerated!")

    st.markdown("""
    <div style="position:fixed;bottom:12px;left:0;right:0;text-align:center;color:#333;font-size:0.7em;padding:0 10px;">
      SIH-26 Demo · AI-Assisted Passive<br>Network Forensic Framework
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

st.markdown("""
<h1 style="margin-bottom:4px;">
  🔐 Email Cryptographic Posture Framework
</h1>
<p style="color:#555;margin-bottom:24px;font-size:0.9em;">
  AI-Assisted Passive Network Forensics · NIST SP 800-52 · RFC 9325 · RFC 8314
</p>
""", unsafe_allow_html=True)

if st.session_state.summary is None:
    # Landing state
    st.info("👈 Upload a PCAP file or select a demo scenario from the sidebar to begin forensic analysis.")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        **🔬 What This Analyzes**
        - SMTP / IMAP / POP3 traffic
        - TLS handshake parameters
        - X.509 certificate health
        - STARTTLS negotiation
        - Buffer injection attacks
        """)
    with col2:
        st.markdown("""
        **📊 Scoring Model**
        - TLS Version (weight 0.25)
        - Cipher Suite (weight 0.20)
        - Certificate Health (0.20)
        - STARTTLS Transition (0.15)
        - Forward Secrecy (0.10)
        - Protocol Context (0.10)
        """)
    with col3:
        st.markdown("""
        **⚙️ Standards Checked**
        - NIST SP 800-52 Rev. 2
        - RFC 9325 / BCP 195
        - RFC 8314 (Implicit TLS)
        - RFC 8996 (TLS deprecation)
        - RFC 3207 (STARTTLS)
        - Poddebniak et al. (USENIX '21)
        """)
    st.stop()


# ---------------------------------------------------------------------------
# Results: Evidence Header
# ---------------------------------------------------------------------------

summary = st.session_state.summary
data    = summary.to_dict()
ev      = data["evidence"]
epi     = data["enterprise_posture_index"]
tier    = data["overall_risk_tier"]
rb      = data["risk_breakdown"]
sessions = data.get("sessions", [])
epi_color = _score_color(epi)

# Evidence integrity banner
st.markdown(f"""
<div style="background:#0a0a1e;border:1px solid #1e1e3e;border-radius:12px;padding:14px 20px;margin-bottom:20px;">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
    <div>
      <span style="color:#7b9bff;font-weight:700;font-size:1.05em;">📄 {ev.get('filename','Unknown')}</span>
      <span style="color:#444;margin-left:12px;font-size:0.8em;">Forensic Evidence</span>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72em;color:#555;word-break:break-all;">
      SHA-256: <span style="color:#3d5aff">{ev.get('sha256_hash','')}</span>
    </div>
    <div style="font-size:0.82em;color:#555;">
      {ev.get('total_packets',0):,} packets · {ev.get('file_size_bytes',0):,} bytes · 
      {ev.get('capture_duration',0):.3f}s · Analyzed in {st.session_state.analysis_time:.2f}s
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Enterprise Posture Index + Risk Summary
# ---------------------------------------------------------------------------

col_epi, col_risk = st.columns([1, 2])

with col_epi:
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#0d0d2b,#12124a);border:1px solid #2a2a6e;
                border-radius:16px;padding:24px;text-align:center;">
      <div style="font-size:4.5em;font-weight:900;color:{epi_color};line-height:1;">{epi:.1f}</div>
      <div style="color:#888;font-size:0.85em;margin-top:4px;">Enterprise Posture Index</div>
      <div style="margin-top:12px;">{_badge_html(tier)}</div>
    </div>
    """, unsafe_allow_html=True)

with col_risk:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🔴 CRITICAL", rb.get("CRITICAL", 0))
    c2.metric("🟠 HIGH",     rb.get("HIGH", 0))
    c3.metric("🟡 MEDIUM",   rb.get("MEDIUM", 0))
    c4.metric("🟢 LOW",      rb.get("LOW", 0))

    st.metric("Total Violations", data.get("total_violations", 0))
    st.metric("Sessions Analyzed", data.get("session_count", 0))


st.divider()


# ---------------------------------------------------------------------------
# Session Table
# ---------------------------------------------------------------------------

st.markdown("### 📋 Session Analysis")

if not sessions:
    st.warning("No email sessions detected in this PCAP. Try the demo PCAPs or ensure the capture contains SMTP/IMAP/POP3 traffic on standard ports.")
else:
    # Summary table
    table_rows = []
    for i, s in enumerate(sessions):
        tier_s = s.get("risk_tier", "?")
        score_s = s.get("posture_score", 0)
        color = RISK_COLORS.get(tier_s, "#aaa")
        table_rows.append({
            "#": i + 1,
            "Protocol": s.get("protocol", "?"),
            "Flow": f"{s.get('src_ip','')}:{s.get('src_port','')} → {s.get('dst_ip','')}:{s.get('dst_port','')}",
            "Channel": s.get("channel_type", "?"),
            "TLS": s.get("tls_version") or "—",
            "Cipher": (s.get("cipher_suite") or "—")[:40],
            "Score": score_s,
            "Risk": tier_s,
            "Violations": len(s.get("violations", [])),
            "ML Anomaly": "⚡ YES" if s.get("ml_anomaly", {}).get("is_anomalous") else "—",
        })

    import pandas as pd
    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()

    # ---- Session Detail Cards ----
    st.markdown("### 🔍 Session Deep-Dive")
    for i, s in enumerate(sessions):
        tier_s  = s.get("risk_tier", "UNKNOWN")
        score_s = s.get("posture_score", 0)
        color   = RISK_COLORS.get(tier_s, "#aaa")

        with st.expander(
            f"Session #{i+1} — {s.get('protocol','?')}  "
            f"{s.get('src_ip','')}:{s.get('src_port','')} → {s.get('dst_ip','')}:{s.get('dst_port','')}  "
            f"│  Score: {score_s:.1f}  │  {tier_s}",
            expanded=(i == 0)
        ):
            col_a, col_b, col_c = st.columns([1, 1, 1])

            with col_a:
                st.markdown("**🔗 TLS Parameters**")
                st.markdown(f"""
                | Field | Value |
                |-------|-------|
                | Channel | `{s.get('channel_type','?')}` |
                | STARTTLS Status | `{s.get('starttls_status','?')}` |
                | TLS Version | `{s.get('tls_version') or '—'}` |
                | Cipher Suite | `{(s.get('cipher_suite') or '—')[:35]}` |
                | Key Exchange | `{s.get('key_exchange') or '—'}` |
                | SNI | `{s.get('sni') or '—'}` |
                """)

            with col_b:
                cert = s.get("cert", {})
                st.markdown("**📜 Certificate**")
                st.markdown(f"""
                | Field | Value |
                |-------|-------|
                | Status | `{cert.get('validity','?')}` |
                | Key Size | `{cert.get('key_length_bits','?')} bits` |
                | Sig Algo | `{cert.get('signature_algorithm','?') or '—'}` |
                | Subject CN | `{cert.get('subject_cn','?') or '—'}` |
                | Issuer CN | `{cert.get('issuer_cn','?') or '—'}` |
                | Not After | `{(cert.get('not_after','?') or '—')[:10]}` |
                """)

            with col_c:
                fp = s.get("fingerprints", {})
                ml = s.get("ml_anomaly", {})
                st.markdown("**🧬 Fingerprints & ML**")
                st.markdown(f"""
                | Field | Value |
                |-------|-------|
                | JA4 | `{fp.get('ja4','—') or '—'}` |
                | JA4S | `{fp.get('ja4s','—') or '—'}` |
                | JA4X | `{fp.get('ja4x','—') or '—'}` |
                | Anomaly | `{'YES ⚡' if ml.get('is_anomalous') else 'No'}` |
                | Anomaly Score | `{ml.get('anomaly_score','—')}` |
                | Buffer Inject | `{'YES ⚠️' if s.get('buffer_injection_detected') else 'No'}` |
                """)

            # Component score bars
            st.markdown("**📊 Component Scores**")
            cs = s.get("component_scores", {})
            bar_cols = st.columns(6)
            labels = [
                ("TLS Version", "tls_version"),
                ("Cipher Suite", "cipher_suite"),
                ("Cert Health", "cert_health"),
                ("STARTTLS", "starttls_transition"),
                ("Fwd Secrecy", "forward_secrecy"),
                ("Proto Ctx", "protocol_context"),
            ]
            for col, (label, key) in zip(bar_cols, labels):
                val = cs.get(key, 0)
                col.metric(label, f"{val:.0f}")

            # Violations
            violations = s.get("violations", [])
            if violations:
                st.markdown(f"**⚠️ Violations ({len(violations)})**")
                for v in violations:
                    sev_color = {"CRITICAL": "error", "HIGH": "warning", "MEDIUM": "warning", "LOW": "info"}.get(v["severity"], "info")
                    if sev_color == "error":
                        st.error(f"**[{v['code']}]** `{v['severity']}` — {v['description']}  \n*Ref: {v.get('reference','')}*")
                    elif sev_color == "warning":
                        st.warning(f"**[{v['code']}]** `{v['severity']}` — {v['description']}  \n*Ref: {v.get('reference','')}*")
                    else:
                        st.info(f"**[{v['code']}]** `{v['severity']}` — {v['description']}")
            else:
                st.success("✅ No violations detected for this session.")

            if ml.get("is_anomalous") and ml.get("top_features"):
                st.markdown("**🤖 ML Anomaly Feature Drivers**")
                feats = ml.get("top_features", {})
                feat_df = pd.DataFrame(
                    [{"Feature": k, "Z-Score Deviation": v} for k, v in feats.items()]
                )
                st.dataframe(feat_df, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Export Controls
# ---------------------------------------------------------------------------

st.divider()
st.markdown("### 📥 Export Reports")

col_json, col_html = st.columns(2)

with col_json:
    json_str = export_json(summary)
    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_str,
        file_name=f"forensic_report_{ev.get('filename','pcap').replace('.','_')}.json",
        mime="application/json",
        use_container_width=True,
    )
    with st.expander("Preview JSON"):
        st.code(json_str[:3000] + ("\n... (truncated)" if len(json_str) > 3000 else ""), language="json")

with col_html:
    html_str = export_html(summary)
    st.download_button(
        label="⬇️ Download HTML Report",
        data=html_str,
        file_name=f"forensic_report_{ev.get('filename','pcap').replace('.','_')}.html",
        mime="text/html",
        use_container_width=True,
    )


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.divider()
st.markdown("""
<div style="text-align:center;color:#333;font-size:0.75em;padding:12px;">
  🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework for Enterprise Email Cryptographic Posture Assessment<br>
  SIH-26 Demo · For authorized forensic use only · All analyses performed offline, no data transmitted externally.
</div>
""", unsafe_allow_html=True)
