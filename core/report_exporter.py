"""
core/report_exporter.py
Forensic report generation: JSON and self-contained HTML exports.
Implements Pipeline Stage 10 from the project synopsis.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import EnterpriseSummary, RiskTier


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(summary: EnterpriseSummary, output_path: Optional[str | Path] = None) -> str:
    """
    Serialize an EnterpriseSummary to JSON (PRD §10 schema).
    If output_path is given, write the file and return the path string.
    Otherwise returns the JSON string.
    """
    data = summary.to_dict()
    js = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(js, encoding="utf-8")
        return str(output_path)
    return js


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_RISK_COLORS = {
    "CRITICAL": ("#ff3b3b", "#3d0000"),
    "HIGH":     ("#ff9500", "#3d2200"),
    "MEDIUM":   ("#ffe066", "#3d3000"),
    "LOW":      ("#00d68f", "#003d25"),
}

_SCORE_GRADIENT_COLOR = {
    (0, 30):   "#ff3b3b",
    (30, 55):  "#ff9500",
    (55, 80):  "#ffe066",
    (80, 101): "#00d68f",
}


def _score_color(score: float) -> str:
    for (lo, hi), color in _SCORE_GRADIENT_COLOR.items():
        if lo <= score < hi:
            return color
    return "#00d68f"


def _badge(tier: str) -> str:
    fg, bg = _RISK_COLORS.get(tier, ("#fff", "#333"))
    return f'<span style="background:{bg};color:{fg};padding:3px 10px;border-radius:4px;font-weight:700;font-size:0.85em;border:1px solid {fg}33;">{tier}</span>'


def _violation_rows(violations: list) -> str:
    if not violations:
        return "<tr><td colspan='4' style='color:#666;font-style:italic;'>No violations detected</td></tr>"
    rows = []
    sev_colors = {"CRITICAL": "#ff3b3b", "HIGH": "#ff9500", "MEDIUM": "#ffe066", "LOW": "#00d68f"}
    for v in violations:
        color = sev_colors.get(v["severity"], "#aaa")
        rows.append(
            f"<tr>"
            f"<td><code style='color:{color};font-size:0.8em'>{v['code']}</code></td>"
            f"<td style='color:{color};font-weight:600;font-size:0.85em'>{v['severity']}</td>"
            f"<td style='font-size:0.9em'>{v['description']}</td>"
            f"<td style='font-size:0.75em;color:#888'>{v.get('reference','')}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _session_cards(sessions: list) -> str:
    cards = []
    for i, s in enumerate(sessions):
        tier  = s.get("risk_tier", "UNKNOWN")
        score = s.get("posture_score", 0)
        color = _score_color(score)
        badge = _badge(tier)
        cs    = s.get("component_scores", {})

        # Radar-like bar chart for component scores
        def bar(label, val):
            w = int(val)
            c = _score_color(val)
            return f"""
            <div style="margin:4px 0;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="width:130px;font-size:0.75em;color:#aaa;text-align:right">{label}</span>
                <div style="flex:1;background:#1a1a2e;border-radius:4px;height:12px;overflow:hidden;">
                  <div style="width:{w}%;height:100%;background:{c};border-radius:4px;transition:width 0.5s;"></div>
                </div>
                <span style="width:36px;font-size:0.75em;color:{c};font-weight:700">{val:.0f}</span>
              </div>
            </div>"""

        bars = (
            bar("TLS Version",     cs.get("tls_version", 0)) +
            bar("Cipher Suite",    cs.get("cipher_suite", 0)) +
            bar("Cert Health",     cs.get("cert_health", 0)) +
            bar("STARTTLS",        cs.get("starttls_transition", 0)) +
            bar("Forward Secrecy", cs.get("forward_secrecy", 0)) +
            bar("Protocol Ctx",    cs.get("protocol_context", 0))
        )

        cert = s.get("cert", {})
        fp   = s.get("fingerprints", {})
        ml   = s.get("ml_anomaly", {})
        is_anomalous = ml.get("is_anomalous", False)

        anomaly_badge = ""
        if is_anomalous:
            anomaly_score = ml.get("anomaly_score", 0)
            anomaly_badge = f'<span style="background:#5c0099;color:#e8b4ff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;margin-left:8px;">⚡ ML ANOMALY {anomaly_score:.2f}</span>'

        inj = s.get("buffer_injection_detected", False)
        inj_badge = '<span style="background:#3d0000;color:#ff6b6b;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;margin-left:8px;">⚠ BUFFER INJECTION</span>' if inj else ""

        cards.append(f"""
        <div style="background:#0f0f1e;border:1px solid #1e1e3e;border-radius:12px;padding:20px;margin-bottom:18px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
            <div>
              <span style="font-size:1.1em;font-weight:700;color:#e0e0ff;">{s.get('protocol','?')} Session #{i+1}</span>
              <span style="color:#666;font-size:0.85em;margin-left:10px">{s.get('src_ip','')}:{s.get('src_port','')} → {s.get('dst_ip','')}:{s.get('dst_port','')}</span>
              {anomaly_badge}{inj_badge}
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
              <div style="text-align:center;">
                <div style="font-size:2em;font-weight:900;color:{color};">{score:.1f}</div>
                <div style="font-size:0.7em;color:#666;">/ 100</div>
              </div>
              {badge}
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px;">
            <div>
              <table style="width:100%;border-collapse:collapse;font-size:0.85em;">
                <tr><td style="color:#666;padding:2px 8px">Channel</td><td style="color:#e0e0ff">{s.get('channel_type','?')}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">STARTTLS</td><td style="color:#e0e0ff">{s.get('starttls_status','?')}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">TLS Version</td><td style="color:#e0e0ff">{s.get('tls_version') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">Cipher Suite</td><td style="color:#e0e0ff;font-size:0.85em">{s.get('cipher_suite') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">Key Exchange</td><td style="color:#e0e0ff">{s.get('key_exchange') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">SNI</td><td style="color:#e0e0ff">{s.get('sni') or '—'}</td></tr>
              </table>
            </div>
            <div>
              <table style="width:100%;border-collapse:collapse;font-size:0.85em;">
                <tr><td style="color:#666;padding:2px 8px">Cert Status</td><td style="color:#e0e0ff">{cert.get('validity','?')}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">Key Size</td><td style="color:#e0e0ff">{cert.get('key_length_bits','?') or '—'} bits</td></tr>
                <tr><td style="color:#666;padding:2px 8px">Sig Algorithm</td><td style="color:#e0e0ff">{cert.get('signature_algorithm','?') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">Subject CN</td><td style="color:#e0e0ff">{cert.get('subject_cn','?') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">JA4</td><td style="color:#7b7bff;font-size:0.8em;font-family:monospace">{fp.get('ja4','—') or '—'}</td></tr>
                <tr><td style="color:#666;padding:2px 8px">JA4X</td><td style="color:#7b7bff;font-size:0.8em;font-family:monospace">{fp.get('ja4x','—') or '—'}</td></tr>
              </table>
            </div>
          </div>

          <div style="margin-bottom:14px;">
            <div style="font-size:0.8em;color:#666;margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Component Scores</div>
            {bars}
          </div>

          <details style="margin-top:8px;">
            <summary style="cursor:pointer;color:#7b7bff;font-size:0.9em;font-weight:600;">
              Violations ({len(s.get('violations',[]))})
            </summary>
            <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:0.85em;">
              <thead>
                <tr style="border-bottom:1px solid #1e1e3e;">
                  <th style="text-align:left;padding:4px 8px;color:#666">Code</th>
                  <th style="text-align:left;padding:4px 8px;color:#666">Severity</th>
                  <th style="text-align:left;padding:4px 8px;color:#666">Description</th>
                  <th style="text-align:left;padding:4px 8px;color:#666">Reference</th>
                </tr>
              </thead>
              <tbody>
                {_violation_rows(s.get('violations',[]))}
              </tbody>
            </table>
          </details>
        </div>
        """)

    return "\n".join(cards)


def export_html(summary: EnterpriseSummary, output_path: Optional[str | Path] = None) -> str:
    """
    Generate a self-contained, dark-themed HTML forensic report.
    If output_path given, writes file and returns path. Otherwise returns HTML string.
    """
    data  = summary.to_dict()
    ev    = data["evidence"]
    epi   = data["enterprise_posture_index"]
    tier  = data["overall_risk_tier"]
    rb    = data["risk_breakdown"]
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    epi_color = _score_color(epi)

    session_html = _session_cards(data.get("sessions", []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Cryptographic Posture Report — {ev.get('filename','Unknown')}</title>
<meta name="description" content="AI-Assisted Passive Network Forensic Framework — Email Cryptographic Posture Assessment Report">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #07071a; color: #d0d0f0; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 20px; }}
  header {{ background: linear-gradient(135deg, #0d0d2b 0%, #12124a 100%); border: 1px solid #1e1e5e; border-radius: 16px; padding: 28px 32px; margin-bottom: 24px; }}
  header h1 {{ font-size: 1.5em; font-weight: 900; color: #7b9bff; margin-bottom: 6px; letter-spacing: -0.5px; }}
  header p {{ color: #888; font-size: 0.9em; }}
  .evidence-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .ev-card {{ background: #0f0f1e; border: 1px solid #1e1e3e; border-radius: 10px; padding: 14px 16px; }}
  .ev-card .label {{ color: #666; font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }}
  .ev-card .value {{ color: #e0e0ff; font-weight: 700; font-size: 0.95em; word-break: break-all; }}
  .epi-card {{ background: linear-gradient(135deg, #0d0d2b, #12124a); border: 1px solid #2a2a6e; border-radius: 16px; padding: 24px; margin-bottom: 24px; display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }}
  .epi-score {{ text-align: center; }}
  .epi-number {{ font-size: 5em; font-weight: 900; color: {epi_color}; line-height: 1; }}
  .epi-label {{ color: #666; font-size: 0.85em; margin-top: 4px; }}
  .risk-breakdown {{ display: flex; gap: 16px; flex-wrap: wrap; }}
  .risk-pill {{ padding: 6px 16px; border-radius: 8px; text-align: center; min-width: 80px; }}
  .section-title {{ font-size: 1.1em; font-weight: 700; color: #7b7bff; text-transform: uppercase; letter-spacing: 2px; margin: 24px 0 14px; padding-bottom: 6px; border-bottom: 1px solid #1e1e3e; }}
  code {{ font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace; font-size: 0.85em; background: #0a0a1e; padding: 2px 6px; border-radius: 4px; color: #a0b0ff; }}
  details summary {{ outline: none; }}
  footer {{ text-align: center; padding: 20px; color: #444; font-size: 0.8em; margin-top: 24px; border-top: 1px solid #111; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🔐 Email Cryptographic Posture Forensic Report</h1>
  <p>AI-Assisted Passive Network Forensic Framework &nbsp;·&nbsp; Generated: {now}</p>
</header>

<div class="section-title">Evidence Integrity</div>
<div class="evidence-grid">
  <div class="ev-card"><div class="label">File</div><div class="value">{ev.get('filename','?')}</div></div>
  <div class="ev-card"><div class="label">SHA-256</div><div class="value" style="font-family:monospace;font-size:0.75em">{ev.get('sha256_hash','?')}</div></div>
  <div class="ev-card"><div class="label">Size</div><div class="value">{ev.get('file_size_bytes',0):,} bytes</div></div>
  <div class="ev-card"><div class="label">Packets</div><div class="value">{ev.get('total_packets',0):,}</div></div>
  <div class="ev-card"><div class="label">Duration</div><div class="value">{ev.get('capture_duration',0):.3f}s</div></div>
  <div class="ev-card"><div class="label">Sessions</div><div class="value">{data.get('session_count',0)}</div></div>
</div>

<div class="epi-card">
  <div class="epi-score">
    <div class="epi-number">{epi:.1f}</div>
    <div class="epi-label">Enterprise Posture Index</div>
  </div>
  <div>
    <div style="font-size:1.6em;font-weight:800;color:#e0e0ff;margin-bottom:8px">{_badge(tier)} Overall Risk</div>
    <div style="color:#888;font-size:0.9em;margin-bottom:16px">{data.get('total_violations',0)} total violations across {data.get('session_count',0)} sessions</div>
    <div class="risk-breakdown">
      <div class="risk-pill" style="background:#3d0000;color:#ff3b3b">CRITICAL<br><strong>{rb.get('CRITICAL',0)}</strong></div>
      <div class="risk-pill" style="background:#3d2200;color:#ff9500">HIGH<br><strong>{rb.get('HIGH',0)}</strong></div>
      <div class="risk-pill" style="background:#3d3000;color:#ffe066">MEDIUM<br><strong>{rb.get('MEDIUM',0)}</strong></div>
      <div class="risk-pill" style="background:#003d25;color:#00d68f">LOW<br><strong>{rb.get('LOW',0)}</strong></div>
    </div>
  </div>
</div>

<div class="section-title">Session Analysis</div>
{session_html}

<footer>
  Produced by SIH-26 Demo &nbsp;·&nbsp; AI-Assisted Passive Network Forensic Framework &nbsp;·&nbsp; For authorized forensic use only.
</footer>
</div>
</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
        return str(output_path)
    return html
