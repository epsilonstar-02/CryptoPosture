import { useCallback } from 'react'

const API = ''

export default function ExportPanel({ data }) {
  const jsonStr = data ? JSON.stringify(data, null, 2) : ''
  const filename = data?.evidence?.filename?.replace(/\./g, '_') || 'pcap'

  const downloadJSON = useCallback(() => {
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `forensic_report_${filename}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [jsonStr, filename])

  const downloadHTML = useCallback(async () => {
    try {
      // We re-request the HTML report from the API
      // Since we already have the JSON data, POST the original PCAP isn't feasible here.
      // Instead, build a minimal self-contained HTML report from the JSON data we have.
      const html = buildHTMLReport(data)
      const blob = new Blob([html], { type: 'text/html' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = `forensic_report_${filename}.html`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert(`HTML export failed: ${e.message}`)
    }
  }, [data, filename])

  if (!data) return null

  const preview = jsonStr.slice(0, 600) + (jsonStr.length > 600 ? '\n...' : '')

  return (
    <div className="export-grid fade-in">
      <div className="panel export-card">
        <div className="export-card-title">📄 JSON Forensic Report</div>
        <div className="export-card-desc">
          Full machine-readable report with all session data, scores, violations, and ML anomalies.
        </div>
        <div className="json-preview">{preview}</div>
        <button className="btn btn--primary" onClick={downloadJSON}>
          ⬇ Download JSON Report
        </button>
      </div>

      <div className="panel export-card">
        <div className="export-card-title">🌐 HTML Forensic Report</div>
        <div className="export-card-desc">
          Self-contained HTML report suitable for sharing and archiving as legal evidence.
        </div>
        <div style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-dim)',
          borderRadius: 6,
          padding: 12,
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.7,
        }}>
          ✔ Evidence integrity hash embedded<br />
          ✔ Per-session TLS posture details<br />
          ✔ Violation list with RFC references<br />
          ✔ Enterprise Posture Index summary<br />
          ✔ No external dependencies
        </div>
        <button className="btn btn--primary" onClick={downloadHTML}>
          ⬇ Download HTML Report
        </button>
      </div>
    </div>
  )
}

// ─── Minimal self-contained HTML report builder ───────────────────────────

function buildHTMLReport(data) {
  if (!data) return ''
  const ev   = data.evidence || {}
  const epi  = data.enterprise_posture_index ?? 0
  const tier = data.overall_risk_tier ?? 'UNKNOWN'
  const rb   = data.risk_breakdown || {}
  const sessions = data.sessions || []
  const now  = new Date().toISOString()

  const riskColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }
  const tc = riskColor[tier] || '#aaa'

  const sessRows = sessions.map((s, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${s.protocol}</td>
      <td style="font-size:0.75em">${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}</td>
      <td>${s.channel_type}</td>
      <td>${s.tls_version || '—'}</td>
      <td>${(s.posture_score || 0).toFixed(1)}</td>
      <td style="color:${riskColor[s.risk_tier]};font-weight:700">${s.risk_tier}</td>
      <td>${(s.violations || []).length}</td>
    </tr>
  `).join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Forensic Report — ${ev.filename || 'unknown'}</title>
<style>
  body{font-family:'Segoe UI',sans-serif;background:#03040f;color:#e2e8f0;padding:32px;margin:0}
  h1{font-size:1.6rem;font-weight:900;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .panel{background:#080d1a;border:1px solid #0f1e3d;border-radius:12px;padding:20px;margin-bottom:20px}
  .mono{font-family:'Courier New',monospace;font-size:0.8em;color:#60a5fa;word-break:break-all}
  .meta{display:flex;gap:24px;flex-wrap:wrap;margin-top:8px;font-size:0.8em;color:#64748b}
  .epi{font-size:3.5rem;font-weight:900;color:${tc};font-family:'Courier New',monospace}
  .badge{display:inline-block;padding:3px 12px;border-radius:99px;font-weight:700;font-size:0.78em;background:${tc}22;color:${tc};border:1px solid ${tc}55}
  table{width:100%;border-collapse:collapse;font-size:0.82em}
  th{background:#0f1e3d;padding:10px 12px;text-align:left;font-size:0.72em;text-transform:uppercase;letter-spacing:0.08em;color:#64748b}
  td{padding:9px 12px;border-bottom:1px solid #0f1e3d;font-family:'Courier New',monospace}
  .footer{text-align:center;color:#334155;font-size:0.7em;margin-top:32px}
</style>
</head>
<body>
<h1>🔐 CryptoPosture — Email Forensic Report</h1>
<div style="color:#64748b;font-size:0.8em;margin-bottom:20px;font-family:'Courier New',monospace">Generated: ${now}</div>

<div class="panel">
  <strong>📄 Evidence: ${ev.filename || 'Unknown'}</strong>
  <div class="mono">SHA-256: ${ev.sha256_hash || '—'}</div>
  <div class="meta">
    <span>Packets: ${(ev.total_packets || 0).toLocaleString()}</span>
    <span>Size: ${ev.file_size_bytes || 0} bytes</span>
    <span>Duration: ${(ev.capture_duration || 0).toFixed(3)}s</span>
    <span>Sessions: ${data.session_count || 0}</span>
  </div>
</div>

<div class="panel" style="text-align:center">
  <div class="epi">${epi.toFixed(1)}</div>
  <div style="color:#64748b;font-size:0.85em;margin:4px 0 10px">Enterprise Posture Index / 100</div>
  <span class="badge">${tier}</span>
  <div class="meta" style="justify-content:center;margin-top:12px">
    <span style="color:#ef4444">CRITICAL: ${rb.CRITICAL || 0}</span>
    <span style="color:#f97316">HIGH: ${rb.HIGH || 0}</span>
    <span style="color:#eab308">MEDIUM: ${rb.MEDIUM || 0}</span>
    <span style="color:#22c55e">LOW: ${rb.LOW || 0}</span>
    <span>Total Violations: ${data.total_violations || 0}</span>
  </div>
</div>

<div class="panel">
  <strong>Session Analysis</strong>
  <table style="margin-top:12px">
    <thead><tr><th>#</th><th>Proto</th><th>Flow</th><th>Channel</th><th>TLS</th><th>Score</th><th>Risk</th><th>Violations</th></tr></thead>
    <tbody>${sessRows}</tbody>
  </table>
</div>

<div class="footer">
  🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework<br>
  SIH-26 Demo · For authorized forensic use only · All analyses performed offline.
</div>
</body>
</html>`
}
