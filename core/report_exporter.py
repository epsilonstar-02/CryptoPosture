"""
core/report_exporter.py
Production-grade Forensic Report Generation: JSON and Self-Contained HTML Exports.
Implements Pipeline Stage 12 from the project architecture.

Structure of the HTML Forensic Report:
  Section 1: Evidence Integrity & Chain of Custody
             - Authoritative SHA-256 hash, Evidence ID, file metadata, link layer,
               tamper verification, engine & schema version, scoring & rule policies.
  Section 2: Executive Assessment & Enterprise Risk
             - Enterprise Posture Index (EPI), Overall Risk Tier, session health distribution,
               volume-weighted harmonic aggregation, dominant compliance findings.
  Section 3: Session Forensic Analysis & Telemetry
             - Flow 5-tuple, protocol lineage, transport security, TLS record & handshake,
               X.509 certificate health & chain, JA4+ fingerprints, PQC state, buffer injection.
  Section 4: Why This Score? (Standards-Informed Audit Trail)
             - 6-dimension component score breakdown, formula contributions, critical caps applied,
               and structured 5-part Finding Audits (Evidence, Standards Basis, Interpretation,
               Confidence, Recommended Remediation).
  Capture-Relative Outlier Inspection (Isolation Forest):
             - Liu et al. (ICDM 2008) score s(x, n), threshold check, advisory callout,
               and Most Unusual Characteristics table (population Z-score deviations).

Security & Safe Rendering:
  All dynamic network packet artifacts (SNI, Subject CNs, Issuer, diagnostics, violation texts)
  are strictly HTML-escaped using `html.escape()` to prevent XSS / HTML injection attacks.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import EnterpriseSummary, RiskTier


# ---------------------------------------------------------------------------
# Safe Rendering Utilities
# ---------------------------------------------------------------------------

def _e(val: Any) -> str:
    """Safely escape dynamic values for HTML embedding to prevent XSS."""
    if val is None:
        return "—"
    return html.escape(str(val))


def _score_color(score: float) -> str:
    """Map posture score (0–100) to standard forensic status color."""
    if score >= 80.0:
        return "#00d68f"   # Low risk / Green
    if score >= 55.0:
        return "#ffe066"   # Medium risk / Yellow
    if score >= 30.0:
        return "#ff9500"   # High risk / Orange
    return "#ff3b3b"       # Critical risk / Red


_RISK_PALETTES = {
    "CRITICAL": ("#ff3b3b", "#3d0000"),
    "HIGH":     ("#ff9500", "#3d2200"),
    "MEDIUM":   ("#ffe066", "#3d3000"),
    "LOW":      ("#00d68f", "#003d25"),
    "UNKNOWN":  ("#a0b0ff", "#1a1a3e"),
}


def _badge(tier: str) -> str:
    """Render a risk tier badge with safe styling."""
    safe_tier = _e(tier).upper()
    fg, bg = _RISK_PALETTES.get(safe_tier, ("#ffffff", "#222222"))
    return (
        f'<span style="background:{bg};color:{fg};padding:3px 10px;'
        f'border-radius:4px;font-weight:700;font-size:0.82em;border:1px solid {fg}44;">'
        f'{safe_tier}</span>'
    )


def _confidence_badge(conf: str) -> str:
    """Render confidence level badge."""
    c = str(conf).upper()
    colors = {
        "CONFIRMED": ("#00d68f", "#003d25"),
        "HIGH":      ("#7b9bff", "#12124a"),
        "MEDIUM":    ("#ffe066", "#3d3000"),
        "LOW":       ("#ff9500", "#3d2200"),
        "SUSPECTED": ("#ff6b6b", "#3d0000"),
    }
    fg, bg = colors.get(c, ("#aaaaaa", "#222222"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-weight:700;font-size:0.75em;border:1px solid {fg}44;">'
        f'{_e(c)}</span>'
    )


# ---------------------------------------------------------------------------
# Section 1: Evidence Integrity & Chain of Custody
# ---------------------------------------------------------------------------

def _render_evidence_integrity_section(data: dict) -> str:
    ev = data.get("evidence", {})
    cfg = data.get("analysis_config", {}) or {}
    scoring_policy = data.get("scoring_policy", {}) or {}

    sha256 = _e(ev.get("sha256_hash") or "UNKNOWN")
    filename = _e(ev.get("filename") or "Unknown File")
    evidence_id = _e(ev.get("evidence_id") or "—")
    capture_format = _e(ev.get("capture_format") or "PCAP")
    link_layer = _e(ev.get("link_layer_type") or "Ethernet")
    total_packets = f"{ev.get('total_packets', 0):,}"
    file_size = f"{ev.get('file_size_bytes', 0):,} bytes"
    duration = f"{ev.get('capture_duration', 0.0):.3f}s"
    tamper_free = ev.get("is_tamper_free", True)
    tamper_badge = (
        '<span style="color:#00d68f;font-weight:700;">✓ Verified Tamper-Free</span>'
        if tamper_free
        else '<span style="color:#ff3b3b;font-weight:700;">⚠ Integrity Mismatch Detected</span>'
    )

    scoring_pol_id = _e(scoring_policy.get("id") or cfg.get("scoring_policy_id") or "crypto-posture-v1")
    scoring_pol_ver = _e(scoring_policy.get("version") or cfg.get("scoring_policy_version") or "1.0")
    rule_pol_id = _e(cfg.get("rule_policy_id") or "nist-bcp-forensic-v1")
    rule_pol_ver = _e(cfg.get("rule_policy_version") or "1.2.0")
    engine_ver = _e(data.get("forensic_engine_version") or cfg.get("engine_version") or "1.2.0")
    schema_ver = _e(data.get("schema_version") or "2.0.0")
    config_id = _e(cfg.get("config_id") or "default-forensic-v1")

    return f"""
    <div style="background:#0c0c1e;border:1px solid #1e1e44;border-radius:12px;padding:20px;margin-bottom:24px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:16px;">
        <div style="font-size:1.1em;font-weight:700;color:#7b9bff;text-transform:uppercase;letter-spacing:1px;">
          1. Evidence Integrity &amp; Chain of Custody
        </div>
        <div style="font-size:0.85em;background:#141432;padding:4px 12px;border-radius:6px;border:1px solid #2a2a5a;">
          {tamper_badge}
        </div>
      </div>

      <div style="background:#070714;border:1px solid #161630;border-radius:8px;padding:12px 16px;margin-bottom:16px;">
        <div style="color:#777;font-size:0.75em;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">
          Authoritative Cryptographic Digest (SHA-256)
        </div>
        <div style="font-family:monospace;font-size:0.95em;color:#e8e8ff;word-break:break-all;font-weight:700;">
          {sha256}
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:12px;margin-bottom:16px;">
        <div class="ev-card"><div class="label">Evidence File</div><div class="value">{filename}</div></div>
        <div class="ev-card"><div class="label">Evidence ID</div><div class="value" style="font-family:monospace;">{evidence_id}</div></div>
        <div class="ev-card"><div class="label">File Size</div><div class="value">{file_size}</div></div>
        <div class="ev-card"><div class="label">Total Packets</div><div class="value">{total_packets}</div></div>
        <div class="ev-card"><div class="label">Capture Duration</div><div class="value">{duration}</div></div>
        <div class="ev-card"><div class="label">Capture Format</div><div class="value">{capture_format} ({link_layer})</div></div>
      </div>

      <div style="background:#090918;border:1px solid #181836;border-radius:8px;padding:12px 16px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;font-size:0.82em;">
        <div><span style="color:#666;">Scoring Policy:</span> <code style="color:#a0b0ff;">{scoring_pol_id} v{scoring_pol_ver}</code></div>
        <div><span style="color:#666;">Rule Policy:</span> <code style="color:#a0b0ff;">{rule_pol_id} v{rule_pol_ver}</code></div>
        <div><span style="color:#666;">Forensic Engine:</span> <code style="color:#a0b0ff;">v{engine_ver}</code></div>
        <div><span style="color:#666;">Schema:</span> <code style="color:#a0b0ff;">v{schema_ver}</code></div>
        <div><span style="color:#666;">Config ID:</span> <code style="color:#a0b0ff;">{config_id}</code></div>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 2: Executive Assessment & Enterprise Risk
# ---------------------------------------------------------------------------

def _render_executive_assessment_section(data: dict) -> str:
    epi = float(data.get("enterprise_posture_index", 0.0))
    tier = str(data.get("overall_risk_tier", "CRITICAL"))
    epi_color = _score_color(epi)
    rb = data.get("risk_breakdown", {})
    session_count = int(data.get("session_count", 0))
    total_violations = int(data.get("total_violations", 0))

    # Clean sessions vs degraded
    clean_count = sum(1 for s in data.get("sessions", []) if len(s.get("violations", [])) == 0)
    degraded_count = session_count - clean_count

    # Dominant findings calculation across all sessions
    violation_counter = Counter()
    violation_meta = {}
    for s in data.get("sessions", []):
        seen_in_session = set()
        for v in s.get("violations", []):
            code = v.get("code") or v.get("rule_id") or "UNKNOWN"
            if code not in seen_in_session:
                seen_in_session.add(code)
                violation_counter[code] += 1
                if code not in violation_meta:
                    violation_meta[code] = {
                        "severity": v.get("severity", "HIGH"),
                        "title": v.get("title") or v.get("description", ""),
                        "reference": v.get("reference", ""),
                    }

    dominant_rows = []
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_dominant = sorted(
        violation_counter.items(),
        key=lambda kv: (sev_order.get(violation_meta[kv[0]]["severity"], 99), -kv[1]),
    )[:5]

    for code, count in sorted_dominant:
        meta = violation_meta[code]
        sev = meta["severity"]
        fg, bg = _RISK_PALETTES.get(sev, ("#aaa", "#222"))
        pct = (count / session_count * 100) if session_count > 0 else 0
        dominant_rows.append(
            f'<tr style="border-bottom:1px solid #161630;">'
            f'<td style="padding:6px 8px;font-family:monospace;font-weight:700;color:{fg};">{_e(code)}</td>'
            f'<td style="padding:6px 8px;"><span style="background:{bg};color:{fg};padding:1px 6px;border-radius:3px;font-size:0.75em;font-weight:700;">{_e(sev)}</span></td>'
            f'<td style="padding:6px 8px;color:#d0d0f0;font-size:0.85em;">{_e(meta["title"])}</td>'
            f'<td style="padding:6px 8px;color:#7b9bff;font-size:0.8em;font-family:monospace;">{_e(meta["reference"])}</td>'
            f'<td style="padding:6px 8px;text-align:right;font-weight:700;color:#e0e0ff;">{count} <span style="color:#666;font-size:0.8em;">({pct:.0f}%)</span></td>'
            f'</tr>'
        )

    dominant_html = "".join(dominant_rows) if dominant_rows else '<tr><td colspan="5" style="padding:10px;text-align:center;color:#00d68f;">✓ No compliance violations detected in capture.</td></tr>'

    return f"""
    <div style="background:#0c0c1e;border:1px solid #1e1e44;border-radius:12px;padding:20px;margin-bottom:24px;">
      <div style="font-size:1.1em;font-weight:700;color:#7b9bff;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;">
        2. Executive Assessment &amp; Enterprise Risk
      </div>

      <div style="display:grid;grid-template-columns:1fr 2fr;gap:20px;margin-bottom:20px;align-items:center;">
        <div style="background:linear-gradient(135deg, #0d0d2b, #12124a);border:1px solid #2a2a6e;border-radius:12px;padding:20px;text-align:center;">
          <div style="font-size:3.8em;font-weight:900;color:{epi_color};line-height:1;margin-bottom:4px;">
            {epi:.1f}
          </div>
          <div style="color:#888;font-size:0.8em;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
            Enterprise Posture Index (EPI)
          </div>
          <div>{_badge(tier)}</div>
        </div>

        <div>
          <div style="font-size:1.05em;font-weight:700;color:#e0e0ff;margin-bottom:8px;">
            Session Health &amp; Exposure Distribution
          </div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
            <div class="risk-pill" style="background:#3d0000;color:#ff3b3b;border:1px solid #ff3b3b44;">CRITICAL<br><strong>{rb.get('CRITICAL',0)}</strong></div>
            <div class="risk-pill" style="background:#3d2200;color:#ff9500;border:1px solid #ff950044;">HIGH<br><strong>{rb.get('HIGH',0)}</strong></div>
            <div class="risk-pill" style="background:#3d3000;color:#ffe066;border:1px solid #ffe06644;">MEDIUM<br><strong>{rb.get('MEDIUM',0)}</strong></div>
            <div class="risk-pill" style="background:#003d25;color:#00d68f;border:1px solid #00d68f44;">LOW<br><strong>{rb.get('LOW',0)}</strong></div>
          </div>
          <div style="font-size:0.85em;color:#aaa;line-height:1.5;">
            Total Sessions Analyzed: <strong style="color:#e0e0ff;">{session_count}</strong> &nbsp;·&nbsp;
            Clean Sessions: <strong style="color:#00d68f;">{clean_count}</strong> &nbsp;·&nbsp;
            Degraded Sessions: <strong style="color:#ff9500;">{degraded_count}</strong> &nbsp;·&nbsp;
            Total Rule Violations: <strong style="color:#ff6b6b;">{total_violations}</strong>
          </div>
          <div style="font-size:0.75em;color:#666;margin-top:6px;">
            Harmonic Mean Aggregation: Volume-weighted by <code>byte_count</code> exposure proxy. Penalizes weakest-link protocol failures.
          </div>
        </div>
      </div>

      <div style="background:#080816;border:1px solid #181836;border-radius:8px;padding:14px 16px;">
        <div style="font-size:0.85em;font-weight:700;color:#a0b0ff;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">
          Primary Compliance Weaknesses &amp; Dominant Findings
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:0.82em;">
          <thead>
            <tr style="border-bottom:1px solid #2a2a5e;color:#888;text-align:left;">
              <th style="padding:4px 8px;">Code</th>
              <th style="padding:4px 8px;">Severity</th>
              <th style="padding:4px 8px;">Finding Description</th>
              <th style="padding:4px 8px;">Normative Standard</th>
              <th style="padding:4px 8px;text-align:right;">Impacted Sessions</th>
            </tr>
          </thead>
          <tbody>
            {dominant_html}
          </tbody>
        </table>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# Section 4 Helpers: Structured 5-Part Finding Audit Cards
# ---------------------------------------------------------------------------

def _render_structured_findings_audit(violations: list) -> str:
    """
    Render structured 5-part audit cards for every detected finding:
      1. Evidence
      2. Standards Basis
      3. Interpretation
      4. Confidence
      5. Recommended Remediation
    """
    if not violations:
        return """
        <div style="padding:12px 16px;background:#002214;border:1px solid #005530;border-radius:8px;color:#00d68f;font-size:0.85em;margin-top:10px;">
          ✓ <strong>Compliant Session:</strong> Zero RFC or NIST cryptographic compliance violations detected.
        </div>
        """

    cards = []
    for v in violations:
        code = _e(v.get("code") or v.get("rule_id") or "VIOLATION")
        title = _e(v.get("title") or code)
        sev = str(v.get("severity", "HIGH")).upper()
        fg, bg = _RISK_PALETTES.get(sev, ("#aaa", "#222"))
        ref = _e(v.get("reference") or "RFC / NIST Guideline")
        desc = _e(v.get("description") or "Non-compliant cryptographic configuration.")
        conf = _e(v.get("confidence") or "CONFIRMED")
        remediation = _e(v.get("remediation") or "Update configuration to adhere to modern cryptographic standards.")

        # Extract structured evidence dictionary or provenance facts
        ev_dict = v.get("evidence", {})
        ev_items = []
        if isinstance(ev_dict, dict) and ev_dict:
            for k, val in ev_dict.items():
                if k in ("session_id", "stream_id", "observed_version", "cert_serial", "bytes_pre_tls", "packet_count"):
                    ev_items.append(f"<code>{_e(k)}</code>: <span style='color:#e0e0ff;'>{_e(val)}</span>")
            ev_summary = " &nbsp;·&nbsp; ".join(ev_items) if ev_items else _e(str(ev_dict))
        else:
            ev_summary = _e(str(ev_dict or "Observable network session packet trace"))

        cards.append(f"""
        <div style="background:#0a0a18;border:1px solid #202040;border-left:4px solid {fg};border-radius:6px;padding:12px 16px;margin-bottom:10px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;">
            <div>
              <span style="font-family:monospace;font-weight:700;color:{fg};font-size:0.9em;">[{code}]</span>
              <strong style="color:#e0e0ff;font-size:0.9em;margin-left:6px;">{title}</strong>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              <span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:700;border:1px solid {fg}44;">{sev}</span>
              {_confidence_badge(conf)}
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr;gap:6px;font-size:0.82em;line-height:1.45;">
            <div>
              <strong style="color:#888;">1. Evidence:</strong>
              <span style="color:#b8b8dd;margin-left:6px;">{ev_summary}</span>
            </div>
            <div>
              <strong style="color:#888;">2. Standards Basis:</strong>
              <span style="color:#7b9bff;font-family:monospace;margin-left:6px;">{ref}</span>
            </div>
            <div>
              <strong style="color:#888;">3. Interpretation:</strong>
              <span style="color:#d0d0f0;margin-left:6px;">{desc}</span>
            </div>
            <div>
              <strong style="color:#888;">4. Recommended Remediation:</strong>
              <span style="color:#00d68f;margin-left:6px;">{remediation}</span>
            </div>
          </div>
        </div>
        """)

    return "".join(cards)


# ---------------------------------------------------------------------------
# Section 4: Why This Score? (Standards-Informed Audit Trail)
# ---------------------------------------------------------------------------

def _scoring_explanation_html(s: dict) -> str:
    expl = s.get("scoring_explanation")
    if not expl:
        return ""

    caps = expl.get("critical_caps_applied", [])
    cap_html = ""
    if caps:
        cap_items = []
        for c in caps:
            cap_val = float(c.get("cap_value", 0.0))
            finding = _e(c.get("finding", ""))
            ref = _e(c.get("reference", ""))
            reason = _e(c.get("reason", ""))
            cap_items.append(
                f'<div style="background:#2a0808;border-left:4px solid #ff3b3b;padding:8px 12px;border-radius:4px;margin-bottom:8px;">'
                f'<strong style="color:#ff6b6b">CRITICAL CAP APPLIED:</strong> Final score capped at <strong>{cap_val:.1f} / 100</strong> '
                f'due to <em>{finding}</em> ({ref}).'
                f'<div style="color:#bbb;font-size:0.85em;margin-top:2px;">{reason}</div>'
                f'</div>'
            )
        cap_html = "".join(cap_items)

    status_colors = {
        "PASS":           ("#00d68f", "#003d25"),
        "DEGRADED":       ("#ffe066", "#3d3000"),
        "VIOLATION":      ("#ff3b3b", "#3d0000"),
        "INCONCLUSIVE":   ("#a0b0ff", "#1a1a3e"),
        "NOT_APPLICABLE": ("#888888", "#222222"),
    }

    name_map = {
        "tls_version":         "TLS Version",
        "cipher_suite":        "Cipher Suite",
        "cert_health":         "Certificate Health",
        "starttls_transition": "STARTTLS Transition",
        "forward_secrecy":     "Forward Secrecy",
        "protocol_context":    "Protocol Context",
    }

    rows = []
    comp_ratio = expl.get("evidence_completeness_ratio", 1.0)
    ev_note = expl.get("evidence_note", "")
    for comp in expl.get("components", []):
        c_raw = comp.get("component")
        c_name = _e(name_map.get(c_raw, c_raw))
        status = str(comp.get("assessment", "PASS")).upper()
        fg, bg = status_colors.get(status, ("#aaa", "#222"))
        badge = f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-weight:700;font-size:0.8em;border:1px solid {fg}44;">{_e(status)}</span>'
        refs = _e(", ".join(comp.get("references", [])))
        obs = _e(comp.get("observed", "—"))
        score_val = float(comp.get("component_score", 0.0))
        weight_val = float(comp.get("weight", 0.0))
        eff_weight_val = float(comp.get("effective_weight", weight_val))
        contrib_val = float(comp.get("effective_contribution", comp.get("contribution", 0.0)))
        reason = _e(comp.get("reason", ""))

        if status in ("INCONCLUSIVE", "NOT_APPLICABLE"):
            weight_text = f'{score_val:.0f} × 0% <span style="color:#666;">(base {weight_val*100:.0f}%, excluded)</span> = <strong style="color:#666;">0.0</strong>'
        elif abs(eff_weight_val - weight_val) > 0.001:
            weight_text = f'{score_val:.0f} × {eff_weight_val*100:.1f}% <span style="color:#7b9bff;">(base {weight_val*100:.0f}%)</span> = <strong style="color:#e0e0ff;">{contrib_val:.1f}</strong>'
        else:
            weight_text = f'{score_val:.0f} × {weight_val*100:.0f}% = <strong style="color:#e0e0ff;">{contrib_val:.1f}</strong>'

        rows.append(
            f'<tr style="border-bottom:1px solid #1a1a36;">'
            f'<td style="padding:6px 8px;font-weight:600;color:#c0c0f0;">{c_name}</td>'
            f'<td style="padding:6px 8px;color:#e0e0ff;font-family:monospace;font-size:0.85em;">{obs}</td>'
            f'<td style="padding:6px 8px;">{badge}</td>'
            f'<td style="padding:6px 8px;font-family:monospace;font-size:0.85em;color:#aaa;">'
            f'{weight_text}'
            f'</td>'
            f'<td style="padding:6px 8px;font-size:0.8em;color:#aaa;">{reason}<br><span style="color:#7b9bff;font-size:0.85em;">{refs}</span></td>'
            f'</tr>'
        )

    rows_html = "".join(rows)
    conf = _e(expl.get("overall_confidence", "HIGH"))
    conf_badge = _confidence_badge(conf)
    pol_id = _e(expl.get("policy_id") or "crypto-posture-v1")
    pol_ver = _e(expl.get("policy_version") or "1.0")

    note_html = f'<div style="background:#0a0a20;border-left:3px solid #7b9bff;padding:6px 10px;border-radius:4px;font-size:0.8em;color:#a0b0ff;margin-bottom:10px;">ℹ <strong>Evidence Coverage ({comp_ratio*100:.0f}% assessable):</strong> {_e(ev_note)}</div>' if ev_note else ''

    return f"""
    <details style="margin-top:14px;background:#080816;border:1px solid #1e1e44;border-radius:8px;padding:12px 16px;">
      <summary style="cursor:pointer;color:#7b9bff;font-size:0.95em;font-weight:700;display:flex;justify-content:space-between;align-items:center;">
        <span>🔍 4. Why This Score? (Standards-Informed Audit Trail)</span>
        <span style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:0.8em;color:#888;">Evaluation Confidence:</span>
          {conf_badge}
        </span>
      </summary>
      <div style="margin-top:12px;">
        {cap_html}
        {note_html}
        <table style="width:100%;border-collapse:collapse;font-size:0.85em;margin-top:8px;">
          <thead>
            <tr style="border-bottom:1px solid #2a2a5e;color:#888;text-align:left;">
              <th style="padding:4px 8px;">Dimension</th>
              <th style="padding:4px 8px;">Observed Evidence</th>
              <th style="padding:4px 8px;">Status</th>
              <th style="padding:4px 8px;">Formula Contribution</th>
              <th style="padding:4px 8px;">Standards Rationale &amp; Citations</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
        <div style="margin-top:10px;font-size:0.75em;color:#666;display:flex;justify-content:space-between;align-items:center;">
          <span>Mathematical Model: <code>S = min(Cap_min, S_renormalized) [Evidence-Aware Dynamic Renormalization &amp; Critical Caps]</code></span>
          <span>Scoring Policy: <code>{pol_id} v{pol_ver}</code></span>
        </div>
      </div>
    </details>
    """


# ---------------------------------------------------------------------------
# Capture-Relative Anomaly Inspection Panel (Isolation Forest)
# ---------------------------------------------------------------------------

def _ml_anomaly_html(s: dict) -> str:
    ml = s.get("ml_anomaly", {})
    if not ml:
        return ""
    is_anom = ml.get("is_anomalous", False)
    status = ml.get("status", "")
    score = ml.get("anomaly_score")
    traits = ml.get("unusual_characteristics", {}) or ml.get("top_features", {})

    if is_anom and score is not None:
        trait_rows = []
        for feat, z in traits.items():
            trait_rows.append(
                f'<tr style="border-bottom:1px solid #231238;">'
                f'<td style="padding:4px 8px;color:#e0e0ff;font-family:monospace;">{_e(feat)}</td>'
                f'<td style="padding:4px 8px;color:#ff80df;font-weight:700;">Z = {float(z):.3f}</td>'
                f'</tr>'
            )
        traits_table = "".join(trait_rows)
        return f"""
        <div style="background:#140a24;border:1px solid #4a1570;border-radius:8px;padding:12px 16px;margin-top:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:8px;">
            <span style="font-weight:700;color:#e8b4ff;font-size:0.9em;">⚡ Capture-Relative Outlier Detected (Isolation Forest)</span>
            <span style="font-size:0.85em;color:#e8b4ff;font-weight:700;background:#350055;padding:2px 8px;border-radius:4px;">
              Liu et al. Score: {score:.4f} (Threshold: ≥0.65)
            </span>
          </div>
          <div style="font-size:0.8em;color:#b0a0cc;margin-bottom:8px;line-height:1.4;">
            <em>Advisory Signal:</em> This session exhibits statistically unusual observable telemetry relative to peer sessions in this capture. Deterministic rule compliance remains authoritative.
          </div>
          <div style="font-size:0.8em;font-weight:600;color:#e8b4ff;margin-bottom:4px;">Most Unusual Characteristics (Population Deviation):</div>
          <table style="width:100%;border-collapse:collapse;font-size:0.8em;background:#0d0517;border-radius:6px;">
            <tbody>
              {traits_table}
            </tbody>
          </table>
        </div>
        """
    elif status == "INSUFFICIENT_BASELINE":
        return """
        <div style="background:#0b0b18;border:1px solid #1a1a36;border-radius:8px;padding:8px 14px;margin-top:12px;font-size:0.8em;color:#707090;">
          ℹ️ <strong>ML Anomaly Analysis:</strong> Capture contains fewer than 5 sessions. Capture-relative outlier detection was not trained to avoid unrepresentative false alarms.
        </div>
        """
    return ""


# ---------------------------------------------------------------------------
# Section 3: Session Forensic Analysis
# ---------------------------------------------------------------------------

def _render_session_cards(sessions: list) -> str:
    cards = []
    for i, s in enumerate(sessions):
        tier = str(s.get("risk_tier", "UNKNOWN"))
        score = float(s.get("posture_score", 0.0))
        color = _score_color(score)
        badge = _badge(tier)
        cs = s.get("component_scores", {})

        def bar(label: str, val: float) -> str:
            w = max(0, min(100, int(val)))
            c = _score_color(val)
            safe_label = _e(label)
            return f"""
            <div style="margin:4px 0;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="width:130px;font-size:0.75em;color:#aaa;text-align:right">{safe_label}</span>
                <div style="flex:1;background:#1a1a2e;border-radius:4px;height:12px;overflow:hidden;">
                  <div style="width:{w}%;height:100%;background:{c};border-radius:4px;transition:width 0.5s;"></div>
                </div>
                <span style="width:36px;font-size:0.75em;color:{c};font-weight:700">{val:.0f}</span>
              </div>
            </div>"""

        bars = (
            bar("TLS Version",     cs.get("tls_version", 0.0)) +
            bar("Cipher Suite",    cs.get("cipher_suite", 0.0)) +
            bar("Cert Health",     cs.get("cert_health", 0.0)) +
            bar("STARTTLS",        cs.get("starttls_transition", 0.0)) +
            bar("Forward Secrecy", cs.get("forward_secrecy", 0.0)) +
            bar("Protocol Ctx",    cs.get("protocol_context", 0.0))
        )

        cert = s.get("cert", {}) or {}
        fp = s.get("fingerprints", {}) or {}
        ml = s.get("ml_anomaly", {}) or {}
        is_anomalous = ml.get("is_anomalous", False)
        ml_status = ml.get("status", "")

        anomaly_badge = ""
        if is_anomalous:
            anomaly_score = float(ml.get("anomaly_score", 0.0))
            anomaly_badge = f'<span style="background:#5c0099;color:#e8b4ff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;margin-left:8px;">⚡ CAPTURE ANOMALY {anomaly_score:.2f}</span>'
        elif ml_status == "INSUFFICIENT_BASELINE":
            anomaly_badge = '<span style="background:#1a1a2e;color:#8888aa;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600;margin-left:8px;">ML: &lt;5 SESSIONS</span>'

        inj = s.get("buffer_injection_detected", False)
        inj_badge = '<span style="background:#3d0000;color:#ff6b6b;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;margin-left:8px;">⚠ BUFFER INJECTION (Poddebniak et al.)</span>' if inj else ""

        proto = _e(s.get("protocol", "?"))
        flow_str = f"{_e(s.get('src_ip',''))}:{_e(s.get('src_port',''))} → {_e(s.get('dst_ip',''))}:{_e(s.get('dst_port',''))}"
        flow_id = _e(s.get("flow_id") or "—")
        session_id = _e(s.get("session_id") or f"sess_{i+1}")
        packet_count = _e(s.get("packet_count", 0))
        byte_count = _e(s.get("byte_count", 0))
        bytes_pre_tls = _e(s.get("bytes_pre_tls", 0))

        # PQC mapping
        pqc_state_raw = s.get("pqc_state", 0)
        pqc_text = ["Classical Only", "PQC Offered in ClientHello", "Hybrid PQC Negotiated"][pqc_state_raw] if 0 <= pqc_state_raw <= 2 else "Classical"
        pqc_color = "#00d68f" if pqc_state_raw == 2 else "#7b9bff" if pqc_state_raw == 1 else "#aaa"

        explanation_panel = _scoring_explanation_html(s)
        ml_panel = _ml_anomaly_html(s)
        findings_audit_panel = _render_structured_findings_audit(s.get("violations", []))

        cards.append(f"""
        <div style="background:#0f0f1e;border:1px solid #1e1e3e;border-radius:12px;padding:20px;margin-bottom:24px;">
          <!-- Card Header -->
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
            <div>
              <span style="font-size:1.15em;font-weight:700;color:#e0e0ff;">{proto} Session #{i+1}</span>
              <span style="color:#666;font-size:0.85em;margin-left:10px;font-family:monospace;">{flow_str}</span>
              {anomaly_badge}{inj_badge}
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
              <div style="text-align:center;">
                <div style="font-size:2.2em;font-weight:900;color:{color};line-height:1;">{score:.1f}</div>
                <div style="font-size:0.7em;color:#666;">/ 100</div>
              </div>
              {badge}
            </div>
          </div>

          <!-- Forensic Provenance Lineage Banner -->
          <div style="background:#080816;border:1px solid #181836;border-radius:6px;padding:8px 14px;margin-bottom:14px;font-size:0.78em;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;color:#888;">
            <div><span style="color:#666;">Flow ID:</span> <code style="color:#a0b0ff;">{flow_id}</code></div>
            <div><span style="color:#666;">Session ID:</span> <code style="color:#a0b0ff;">{session_id}</code></div>
            <div><span style="color:#666;">Packets:</span> <strong style="color:#e0e0ff;">{packet_count}</strong></div>
            <div><span style="color:#666;">Traffic:</span> <strong style="color:#e0e0ff;">{byte_count} B</strong></div>
            <div><span style="color:#666;">Pre-TLS Bytes:</span> <strong style="color:{'#ff6b6b' if int(s.get('bytes_pre_tls',0)) > 0 else '#00d68f'};">{bytes_pre_tls} B</strong></div>
          </div>

          <!-- 2-Column Forensic Telemetry Grid -->
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px;">
            <div>
              <table style="width:100%;border-collapse:collapse;font-size:0.85em;">
                <tr><td style="color:#666;padding:3px 8px;">Channel Mode</td><td style="color:#e0e0ff;font-weight:600;">{_e(s.get('channel_type','?'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">STARTTLS Status</td><td style="color:#e0e0ff;">{_e(s.get('starttls_status','?'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">TLS Version</td><td style="color:#e0e0ff;font-weight:700;">{_e(s.get('tls_version') or '—')}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Cipher Suite</td><td style="color:#e0e0ff;font-family:monospace;font-size:0.85em;">{_e(s.get('cipher_suite') or '—')}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Key Exchange</td><td style="color:#e0e0ff;">{_e(s.get('key_exchange') or '—')}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Server Name (SNI)</td><td style="color:#7b9bff;font-family:monospace;">{_e(s.get('sni') or 'None')}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">PQC Posture</td><td style="color:{pqc_color};font-weight:600;">{_e(pqc_text)}</td></tr>
              </table>
            </div>
            <div>
              <table style="width:100%;border-collapse:collapse;font-size:0.85em;">
                <tr><td style="color:#666;padding:3px 8px;">Cert Validity</td><td style="color:#e0e0ff;">{_e(cert.get('validity','?'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Key Length</td><td style="color:#e0e0ff;">{_e(cert.get('key_length_bits','?'))} bits ({_e(cert.get('key_type') or 'RSA')})</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Signature Digest</td><td style="color:#e0e0ff;">{_e(cert.get('signature_algorithm','—'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">Subject CN</td><td style="color:#e0e0ff;font-family:monospace;">{_e(cert.get('subject_cn','—'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">JA4 Client FP</td><td style="color:#7b7bff;font-size:0.8em;font-family:monospace;">{_e(fp.get('ja4','—'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">JA4S Server FP</td><td style="color:#7b7bff;font-size:0.8em;font-family:monospace;">{_e(fp.get('ja4s','—'))}</td></tr>
                <tr><td style="color:#666;padding:3px 8px;">JA4X Cert FP</td><td style="color:#7b7bff;font-size:0.8em;font-family:monospace;">{_e(fp.get('ja4x','—'))}</td></tr>
              </table>
            </div>
          </div>

          <!-- Component Score Bars -->
          <div style="margin-bottom:14px;">
            <div style="font-size:0.8em;color:#666;margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">
              Component Scores (0–100)
            </div>
            {bars}
          </div>

          <!-- Section 4: Why This Score? Audit Trail -->
          {explanation_panel}

          <!-- Isolation Forest Outlier Inspection -->
          {ml_panel}

          <!-- Structured 5-Part Findings Audit List -->
          <details style="margin-top:12px;" open>
            <summary style="cursor:pointer;color:#7b9bff;font-size:0.9em;font-weight:700;">
              Compliance Findings &amp; Violations ({len(s.get('violations',[]))})
            </summary>
            <div style="margin-top:10px;">
              {findings_audit_panel}
            </div>
          </details>
        </div>
        """)

    return "\n".join(cards)


# ---------------------------------------------------------------------------
# Public Exporters
# ---------------------------------------------------------------------------

def export_json(summary: EnterpriseSummary, output_path: Optional[str | Path] = None) -> str:
    """
    Serialize an EnterpriseSummary to JSON conforming to PRD §10 schema.
    If output_path is provided, writes the file and returns the path string.
    Otherwise returns the JSON string.
    """
    data = summary.to_dict()
    js = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(js, encoding="utf-8")
        return str(output_path)
    return js


def export_html(summary: EnterpriseSummary, output_path: Optional[str | Path] = None) -> str:
    """
    Generate an authoritative, self-contained, dark-themed HTML forensic report.
    Organized into four definitive sections:
      1. Evidence Integrity & Chain of Custody
      2. Executive Assessment & Enterprise Risk
      3. Session Forensic Analysis & Telemetry
      4. Why This Score? (Standards-Informed Audit Trail & 5-Part Finding Audits)

    If output_path is provided, writes the HTML file and returns the path.
    Otherwise returns the complete HTML document string.
    """
    data = summary.to_dict()
    ev = data.get("evidence", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    section1_html = _render_evidence_integrity_section(data)
    section2_html = _render_executive_assessment_section(data)
    section3_html = _render_session_cards(data.get("sessions", []))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Cryptographic Posture Forensic Report — {_e(ev.get('filename','Unknown'))}</title>
<meta name="description" content="AI-Assisted Passive Network Forensic Framework — Email Cryptographic Posture Assessment Report">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #060614; color: #d0d0f0; line-height: 1.6; }}
  .container {{ max-width: 1240px; margin: 0 auto; padding: 28px 20px; }}
  header {{ background: linear-gradient(135deg, #0d0d2b 0%, #12124a 100%); border: 1px solid #1e1e5e; border-radius: 16px; padding: 28px 32px; margin-bottom: 24px; }}
  header h1 {{ font-size: 1.6em; font-weight: 900; color: #7b9bff; margin-bottom: 6px; letter-spacing: -0.5px; }}
  header p {{ color: #888; font-size: 0.9em; }}
  .section-title {{ font-size: 1.1em; font-weight: 700; color: #7b9bff; text-transform: uppercase; letter-spacing: 1.5px; margin: 28px 0 14px; padding-bottom: 6px; border-bottom: 1px solid #1e1e3e; }}
  .ev-card {{ background: #0f0f1e; border: 1px solid #1e1e3e; border-radius: 10px; padding: 12px 14px; }}
  .ev-card .label {{ color: #666; font-size: 0.72em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 3px; }}
  .ev-card .value {{ color: #e0e0ff; font-weight: 700; font-size: 0.9em; word-break: break-all; }}
  .risk-pill {{ padding: 6px 16px; border-radius: 8px; text-align: center; min-width: 84px; }}
  code {{ font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace; font-size: 0.85em; background: #0a0a1e; padding: 2px 6px; border-radius: 4px; color: #a0b0ff; }}
  details summary {{ outline: none; }}
  footer {{ text-align: center; padding: 24px; color: #444; font-size: 0.8em; margin-top: 32px; border-top: 1px solid #111; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🔐 Email Cryptographic Posture Forensic Report</h1>
  <p>AI-Assisted Passive Network Forensic Framework &nbsp;·&nbsp; Generated: {now} &nbsp;·&nbsp; Authorized Forensic Audit Trail</p>
</header>

<!-- 1. Evidence Integrity & Chain of Custody -->
{section1_html}

<!-- 2. Executive Assessment & Enterprise Risk -->
{section2_html}

<!-- 3. Session Forensic Analysis & Telemetry -->
<div class="section-title">3. Session Forensic Analysis &amp; Telemetry</div>
{section3_html}

<footer>
  Produced by SIH-26 Demo &nbsp;·&nbsp; Passive Network Cryptographic Forensic Framework &nbsp;·&nbsp; Grounded in RFC 9325, RFC 8314, RFC 8996 &amp; NIST SP 800-52r2
</footer>
</div>
</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html_content, encoding="utf-8")
        return str(output_path)
    return html_content
