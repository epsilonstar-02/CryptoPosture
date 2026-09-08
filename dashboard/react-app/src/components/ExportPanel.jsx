import { useCallback, useState } from 'react'

export default function ExportPanel({ data, onToast }) {
  const [jsonOpen, setJsonOpen] = useState(false)

  const jsonStr  = data ? JSON.stringify(data, null, 2) : ''
  const filename = data?.evidence?.filename?.replace(/\./g, '_') || 'pcap'
  const preview  = jsonStr.slice(0, 600) + (jsonStr.length > 600 ? '\n...' : '')

  const downloadJSON = useCallback(() => {
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `forensic_report_${filename}.json`
    a.click()
    URL.revokeObjectURL(url)
    onToast?.('JSON report downloaded.', 'success')
  }, [jsonStr, filename, onToast])

  const copyJSON = useCallback(() => {
    navigator.clipboard.writeText(jsonStr).then(() => {
      onToast?.('JSON copied to clipboard.', 'success')
    }).catch(() => {
      onToast?.('Copy failed — try downloading instead.', 'error')
    })
  }, [jsonStr, onToast])

  const downloadHTML = useCallback(() => {
    try {
      const html = buildHTMLReport(data)
      const blob = new Blob([html], { type: 'text/html' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = `forensic_report_${filename}.html`
      a.click()
      URL.revokeObjectURL(url)
      onToast?.('HTML report downloaded.', 'success')
    } catch (e) {
      onToast?.(`HTML export failed: ${e.message}`, 'error')
    }
  }, [data, filename, onToast])

  if (!data) return null

  return (
    <div className="export-grid fade-in">
      {/* JSON */}
      <div className="panel export-card">
        <div className="export-card-title">
          <span style={{ fontSize: '1rem' }}>{ }</span>
          JSON Forensic Report
        </div>
        <div className="export-card-desc">
          Full machine-readable report with all session data, scores, violations, and ML anomalies.
        </div>

        <button
          className="toggle-btn"
          onClick={() => setJsonOpen(v => !v)}
        >
          <span className={`toggle-chevron${jsonOpen ? ' toggle-chevron--open' : ''}`}>▶</span>
          {jsonOpen ? 'Hide' : 'Show'} preview
        </button>

        {jsonOpen && <div className="json-preview">{preview}</div>}

        <div className="export-btn-row">
          <button className="btn btn--primary" onClick={downloadJSON}>
            ⬇ Download JSON
          </button>
          <button className="btn btn--ghost btn--copy btn--sm" onClick={copyJSON} title="Copy JSON to clipboard">
            ⎘
          </button>
        </div>
      </div>

      {/* HTML */}
      <div className="panel export-card">
        <div className="export-card-title">
          <span style={{ fontSize: '1rem' }}>🌐</span>
          HTML Forensic Report
        </div>
        <div className="export-card-desc">
          Self-contained HTML report suitable for sharing and archiving as legal evidence.
        </div>

        <div className="export-features">
          {[
            'Evidence integrity hash embedded',
            'Per-session TLS posture details',
            'Violation list with RFC references',
            'Enterprise Posture Index summary',
            'No external dependencies',
          ].map(f => (
            <div key={f} className="export-feature-item">{f}</div>
          ))}
        </div>

        <button className="btn btn--primary" onClick={downloadHTML}>
          ⬇ Download HTML Report
        </button>
      </div>
    </div>
  )
}

// ─── Self-contained Multi-Section HTML Report Builder ───────────────────────

function buildHTMLReport(data) {
  if (!data) return ''
  const ev   = data.evidence || {}
  const epi  = data.enterprise_posture_index ?? 0
  const tier = data.overall_risk_tier ?? 'UNKNOWN'
  const rb   = data.session_tier_breakdown || data.risk_breakdown || {}
  const policy = data.scoring_policy || { id: 'crypto-posture-v1', version: '1.0' }
  const expl = data.enterprise_explanation || {}
  const sessions = data.sessions || []
  const now  = new Date().toUTCString()

  const riskColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }
  const tc = riskColor[tier] || '#aaa'

  const sessionCards = sessions.map((s, idx) => {
    const cert = s.cert || {}
    const fp = s.fingerprints || {}
    const ml = s.ml_anomaly || {}
    const se = s.scoring_explanation || {}
    const caps = se.critical_caps_applied || []
    const comps = se.components || []
    const viols = s.violations || []

    const pqcLabel = s.pqc_state === 2 ? 'Hybrid PQC (Negotiated)' : s.pqc_state === 1 ? 'PQC Offered' : 'Classical Only'

    return `
    <div class="session-card">
      <div class="session-head">
        <div>
          <span class="badge" style="background:${riskColor[s.risk_tier]}22;color:${riskColor[s.risk_tier]};border-color:${riskColor[s.risk_tier]}44">
            ${s.risk_tier}
          </span>
          <strong style="margin-left:10px;font-size:1.05em;color:#e0e0ff">Session #${idx + 1}: ${s.protocol} &nbsp;·&nbsp; ${s.src_ip}:${s.src_port} &rarr; ${s.dst_ip}:${s.dst_port}</strong>
        </div>
        <div style="font-family:'Courier New',monospace;font-size:1.1em;font-weight:700;color:${riskColor[s.risk_tier]}">
          Posture: ${(s.posture_score || 0).toFixed(1)} / 100 &nbsp;<span style="font-size:0.75em;color:#888">(Confidence: ${s.confidence || 'HIGH'})</span>
        </div>
      </div>

      <div class="meta-grid">
        <div><span class="label">Channel:</span> <strong>${s.channel_type}</strong></div>
        <div><span class="label">STARTTLS:</span> <strong>${s.starttls_status}</strong></div>
        <div><span class="label">TLS Version:</span> <strong>${s.tls_version || '—'}</strong></div>
        <div><span class="label">Cipher:</span> <code>${s.cipher_suite || '—'}</code></div>
        <div><span class="label">Key Exchange:</span> <strong>${s.key_exchange || '—'}</strong></div>
        <div><span class="label">PQC State:</span> <strong>${pqcLabel}</strong></div>
        <div><span class="label">Cert Subject:</span> <strong>${cert.subject_cn || '—'}</strong></div>
        <div><span class="label">Cert Validity:</span> <strong>${cert.validity || '—'} (${cert.key_length_bits || '—'} bits)</strong></div>
        <div><span class="label">JA4:</span> <code>${fp.ja4 || '—'}</code></div>
        <div><span class="label">Outlier / Liu Score:</span> <strong>${ml.is_anomalous ? '⚡ Outlier' : (ml.status === 'INSUFFICIENT_BASELINE' ? '<5 sessions' : 'Normal')} (${ml.anomaly_score != null ? ml.anomaly_score.toFixed(4) : '—'})</strong></div>
      </div>

      ${caps.length > 0 ? `
      <div style="margin-top:12px;padding:10px;background:#3d0000;border:1px solid #ef4444;border-radius:6px;font-size:0.85em">
        ${caps.map(c => `
          <div style="color:#ff6b6b;font-weight:700">⚠ SCORE CAPPED AT ${c.cap_value.toFixed(1)}/100: ${c.finding}</div>
          <div style="color:#ddd;margin-top:2px">${c.reason}</div>
          ${c.reference ? `<div style="color:#3dd8e8;font-size:0.8em;margin-top:2px">Ref: ${c.reference}</div>` : ''}
        `).join('')}
      </div>` : ''}

      ${comps.length > 0 ? `
      <div style="margin-top:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <div style="font-size:0.82em;font-weight:700;color:#7b9bff;text-transform:uppercase">Scoring Dimension Audit (Evidence-Aware Dynamic Renormalization)</div>
          ${s.scoring_explanation?.evidence_coverage ? `<div style="font-size:0.75em;color:#aaa">Coverage: <strong>${s.scoring_explanation.evidence_coverage}</strong></div>` : ''}
        </div>
        ${s.scoring_explanation?.evidence_note ? `<div style="font-size:0.75em;color:#3dd8e8;background:#061826;padding:5px 10px;border-radius:4px;margin-bottom:8px">ℹ ${s.scoring_explanation.evidence_note}</div>` : ''}
        <table class="data-table">
          <thead><tr><th>Dimension</th><th>Observed</th><th>Assessment</th><th>Score</th><th>Base Wt</th><th>Eff Wt</th><th>Contrib</th><th>Standards Basis</th></tr></thead>
          <tbody>
            ${comps.map(c => `
              <tr>
                <td><strong>${c.component}</strong></td>
                <td><code>${c.observed || '—'}</code></td>
                <td><span class="pill-sm">${c.assessment}</span></td>
                <td>${c.component_score.toFixed(0)}</td>
                <td>${(c.weight * 100).toFixed(0)}%</td>
                <td style="color:#3dd8e8;font-weight:600">${c.effective_weight != null ? (c.effective_weight * 100).toFixed(1) + '%' : (c.weight * 100).toFixed(0) + '%'}</td>
                <td><strong>+${(c.effective_contribution != null ? c.effective_contribution : c.contribution).toFixed(1)}</strong></td>
                <td style="font-size:0.85em;color:#a0b0ff">${(c.references || []).join(', ')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        ${s.scoring_explanation ? `
        <div style="font-size:0.74em;color:#888;margin-top:6px;font-family:monospace">
          Reconciliation: Base Sum = ${s.scoring_explanation.raw_base_score?.toFixed(1) ?? '—'} · Renormalized = ${s.scoring_explanation.renormalized_score?.toFixed(1) ?? '—'}${s.scoring_explanation.critical_floor_applied != null ? ` · Critical Cap Ceiling = ${s.scoring_explanation.critical_floor_applied.toFixed(1)}` : ''} → Final Score = ${s.posture_score?.toFixed(1)}
        </div>` : ''}
      </div>` : ''}

      ${viols.length > 0 ? `
      <div style="margin-top:14px">
        <div style="font-size:0.82em;font-weight:700;color:#ff6b6b;text-transform:uppercase;margin-bottom:6px">RFC / NIST Policy Violations (${viols.length})</div>
        ${viols.map(v => `
          <div style="padding:8px 10px;background:#0d1820;border-left:3px solid ${riskColor[v.severity] || '#aaa'};border-radius:4px;margin-bottom:6px;font-size:0.82em">
            <div>
              <strong style="color:${riskColor[v.severity]};font-family:monospace">[${v.code}]</strong>
              ${v.mandate_level ? `<span style="font-size:0.75em;padding:1px 4px;border-radius:3px;background:rgba(255,255,255,0.1);margin-left:6px">${v.mandate_level}</span>` : ''}
              &nbsp;${v.description}
            </div>
            ${v.reference ? `<div style="color:#7b9bff;font-size:0.8em;margin-top:2px">Ref: ${v.reference}</div>` : ''}
            ${v.remediation ? `<div style="color:#50e9b1;font-size:0.8em;margin-top:2px">Remediation: ${v.remediation}</div>` : ''}
          </div>
        `).join('')}
      </div>` : '<div style="margin-top:10px;font-size:0.8em;color:#50e9b1">✔ No cryptographic violations detected in this session.</div>'}
    </div>
    `
  }).join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Forensic Report — ${ev.filename || 'unknown'}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #060614; color: #d0d0f0; padding: 28px; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.6rem; color: #7b9bff; margin-bottom: 4px; font-weight: 800; }
  .panel { background: #0c0c20; border: 1px solid #1a1a45; border-radius: 10px; padding: 18px 22px; margin-bottom: 20px; }
  .section-title { font-size: 1.05rem; font-weight: 700; color: #7b9bff; text-transform: uppercase; letter-spacing: 1px; margin: 24px 0 12px; border-bottom: 1px solid #1a1a45; padding-bottom: 4px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 99px; font-weight: 700; font-size: 0.72rem; border: 1px solid transparent; }
  .pill-sm { font-size: 0.7rem; font-family: monospace; padding: 1px 6px; border-radius: 3px; background: rgba(255,255,255,0.06); }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 16px; font-size: 0.8rem; margin-top: 10px; }
  .label { color: #888; font-size: 0.75rem; text-transform: uppercase; }
  .session-card { background: #0c0c24; border: 1px solid #1b1b46; border-radius: 8px; padding: 16px; margin-bottom: 14px; }
  .session-head { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #161638; padding-bottom: 10px; flex-wrap: wrap; gap: 8px; }
  table.data-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; margin-top: 6px; }
  table.data-table th { background: #111130; padding: 6px 10px; text-align: left; color: #888; text-transform: uppercase; font-size: 0.68rem; }
  table.data-table td { padding: 6px 10px; border-bottom: 1px solid #161638; font-family: 'Courier New', monospace; }
  code { font-family: 'Courier New', monospace; color: #3dd8e8; background: #08081a; padding: 1px 5px; border-radius: 3px; }
  .footer { text-align: center; color: #555; font-size: 0.75rem; margin-top: 36px; border-top: 1px solid #111; padding-top: 16px; }
</style>
</head>
<body>
<div class="container">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;margin-bottom:16px">
    <div>
      <h1>🔐 Email Cryptographic Posture Forensic Report</h1>
      <div style="color:#777;font-size:0.8rem">AI-Assisted Passive Network Forensics &nbsp;·&nbsp; Authorized Forensic Audit Trail &nbsp;·&nbsp; Generated: ${now}</div>
    </div>
    <div style="text-align:right">
      <span class="badge" style="background:#3dd8e822;color:#3dd8e8;border-color:#3dd8e844">POLICY: ${policy.id} v${policy.version}</span>
      <div style="font-size:0.75rem;color:#666;margin-top:4px">Engine v${data.forensic_engine_version || '1.0.0'} · Schema v${data.schema_version || '2.0'}</div>
    </div>
  </div>

  <!-- 1. Evidence Integrity & Chain of Custody -->
  <div class="section-title">1. Evidence Integrity &amp; Chain of Custody</div>
  <div class="panel">
    <div class="meta-grid">
      <div><span class="label">Evidence File</span><br/><strong>${ev.filename || 'Unknown'}</strong></div>
      <div><span class="label">Evidence ID</span><br/><code>${ev.evidence_id || '—'}</code></div>
      <div><span class="label">SHA-256 Hash</span><br/><code style="font-size:0.75em">${ev.sha256_hash || '—'}</code></div>
      <div><span class="label">Format &amp; Link Layer</span><br/><strong>${ev.capture_format || 'PCAP'} &nbsp;·&nbsp; ${ev.link_layer_type || 'Ethernet'}</strong></div>
      <div><span class="label">Packet Count</span><br/><strong>${(ev.total_packets || 0).toLocaleString()} packets</strong></div>
      <div><span class="label">File Size</span><br/><strong>${(ev.file_size_bytes || 0).toLocaleString()} bytes</strong></div>
      <div><span class="label">Capture Duration</span><br/><strong>${(ev.capture_duration || 0).toFixed(3)} seconds</strong></div>
      <div><span class="label">Integrity Status</span><br/><strong style="color:${ev.is_tamper_free === false ? '#ef4444' : '#22c55e'}">${ev.is_tamper_free === false ? '⚠ Tamper Detected' : '✔ Verified Tamper-Free'}</strong></div>
    </div>
  </div>

  <!-- 2. Executive Assessment & Enterprise Risk -->
  <div class="section-title">2. Executive Assessment &amp; Enterprise Risk</div>
  <div class="panel" style="display:flex;align-items:center;gap:28px;flex-wrap:wrap">
    <div style="text-align:center;min-width:120px">
      <div style="font-size:3.5rem;font-weight:900;color:${tc};font-family:monospace;line-height:1">${epi.toFixed(1)}</div>
      <div style="color:#888;font-size:0.75rem;margin-top:4px">Enterprise Posture Index / 100</div>
      <span class="badge" style="background:${tc}22;color:${tc};border-color:${tc}44;margin-top:6px">${tier} OVERALL RISK</span>
    </div>
    <div style="flex:1;min-width:260px">
      <div style="color:#aaa;font-size:0.82rem;margin-bottom:8px">
        <strong>${data.session_count || sessions.length}</strong> sessions analyzed &nbsp;·&nbsp;
        <strong>${data.total_violations || 0}</strong> RFC / NIST violations detected across capture
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <span class="badge" style="background:#ef444422;color:#ef4444;border-color:#ef444444">CRITICAL: ${rb.CRITICAL || 0}</span>
        <span class="badge" style="background:#f9731622;color:#f97316;border-color:#f9731644">HIGH: ${rb.HIGH || 0}</span>
        <span class="badge" style="background:#eab30822;color:#eab308;border-color:#eab30844">MEDIUM: ${rb.MEDIUM || 0}</span>
        <span class="badge" style="background:#22c55e22;color:#22c55e;border-color:#22c55e44">LOW: ${rb.LOW || 0}</span>
      </div>
      <div style="font-size:0.75rem;color:#777;background:#080816;padding:8px 12px;border-radius:6px;border:1px solid #141432">
        <strong>Scoring Policy & Aggregation:</strong> Sessions evaluated via 6 calibrated dimensions with dynamic evidence-aware renormalization and non-additive critical score caps (<em>S = min(Cap_min, ∑ w_i_eff · S_i)</em>). Enterprise aggregation via volume-weighted harmonic mean (<em>H = W_total / ∑(w_i / S_i)</em>) using ${(expl.total_volume_bytes || 0).toLocaleString()} bytes as exposure proxy.
        ${expl.rationale || 'Penalizes critical security defects disproportionately to prevent gaps from being averaged away.'}
      </div>
    </div>
  </div>

  <!-- 3. Session Forensic Analysis & Telemetry -->
  <div class="section-title">3. Session Forensic Analysis &amp; Telemetry</div>
  ${sessionCards}

  <div class="footer">
    🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework &nbsp;·&nbsp; Grounded in RFC 9325, RFC 8314, RFC 8996 &amp; NIST SP 800-52r2.<br/>
    SIH-26 Demo &nbsp;·&nbsp; Authoritative forensic export generated for evidentiary audit and review.
  </div>
</div>
</body>
</html>`
}

export { buildHTMLReport }
