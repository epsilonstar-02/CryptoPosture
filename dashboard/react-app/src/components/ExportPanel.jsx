import { useCallback, useState } from 'react'

const API = ''

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

// ─── Self-contained HTML report builder ──────────────────────────────────────

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
  body{font-family:'Segoe UI',sans-serif;background:#050a0e;color:#e4f0ef;padding:32px;margin:0}
  h1{font-size:1.55rem;font-weight:900;color:#3dd8e8;letter-spacing:-0.04em}
  .panel{background:#091118;border:1px solid #162b36;border-radius:10px;padding:20px;margin-bottom:18px}
  .mono{font-family:'Courier New',monospace;font-size:0.78em;color:#3dd8e8;word-break:break-all}
  .meta{display:flex;gap:20px;flex-wrap:wrap;margin-top:8px;font-size:0.78em;color:#85a8aa}
  .epi{font-size:3.2rem;font-weight:900;color:${tc};font-family:'Courier New',monospace}
  .badge{display:inline-block;padding:2px 12px;border-radius:99px;font-weight:700;font-size:0.76em;background:${tc}18;color:${tc};border:1px solid ${tc}44}
  table{width:100%;border-collapse:collapse;font-size:0.8em}
  th{background:#0d1820;padding:9px 12px;text-align:left;font-size:0.68em;text-transform:uppercase;letter-spacing:0.1em;color:#85a8aa}
  td{padding:8px 12px;border-bottom:1px solid #162b36;font-family:'Courier New',monospace}
  .footer{text-align:center;color:#4c6a70;font-size:0.68em;margin-top:28px;font-family:'Courier New',monospace}
</style>
</head>
<body>
<h1>🔐 CryptoPosture — Email Forensic Report</h1>
<div style="color:#4c6a70;font-size:0.76em;margin-bottom:18px;font-family:'Courier New',monospace">Generated: ${now}</div>

<div class="panel">
  <strong>📄 Evidence: ${ev.filename || 'Unknown'}</strong>
  <div class="mono" style="margin-top:6px">SHA-256: ${ev.sha256_hash || '—'}</div>
  <div class="meta">
    <span>Packets: ${(ev.total_packets || 0).toLocaleString()}</span>
    <span>Size: ${ev.file_size_bytes || 0} bytes</span>
    <span>Duration: ${(ev.capture_duration || 0).toFixed(3)}s</span>
    <span>Sessions: ${data.session_count || 0}</span>
  </div>
</div>

<div class="panel" style="text-align:center">
  <div class="epi">${epi.toFixed(1)}</div>
  <div style="color:#85a8aa;font-size:0.82em;margin:4px 0 10px">Enterprise Posture Index / 100</div>
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
