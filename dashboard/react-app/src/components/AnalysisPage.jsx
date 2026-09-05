import { useState, useCallback } from 'react'
import PostureGauge from './PostureGauge.jsx'
import RiskMatrix from './RiskMatrix.jsx'
import SessionTable from './SessionTable.jsx'
import FindingsExplorer from './FindingsExplorer.jsx'
import EvidenceProvenancePanel from './EvidenceProvenancePanel.jsx'
import ExportPanel, { buildHTMLReport } from './ExportPanel.jsx'

function getTierClass(tier) {
  if (tier === 'CRITICAL') return 'kpi-value--critical'
  if (tier === 'HIGH')     return 'kpi-value--high'
  if (tier === 'MEDIUM')   return 'kpi-value--medium'
  return 'kpi-value--low'
}

function getScoreClass(score) {
  if (score >= 80) return 'kpi-value--green'
  if (score >= 55) return 'kpi-value--medium'
  if (score >= 30) return 'kpi-value--high'
  return 'kpi-value--critical'
}

function EnterpriseExplanationPanel({ explanation, policy, engineVersion, schemaVersion }) {
  if (!explanation) return null
  const expl = explanation
  const sessionContribs = expl.session_contributions || []

  return (
    <div className="panel audit-panel fade-in">
      <div className="audit-panel-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            ⚖ Enterprise Posture Index Audit & Aggregation Method
          </span>
          <span className="policy-badge">
            {policy?.id || 'crypto-posture-v1'} v{policy?.version || '1.0'}
          </span>
          <span className="engine-sub-badge">
            Engine v{engineVersion || '1.0.0'} · Schema v{schemaVersion || '2.0'}
          </span>
        </div>
      </div>

      <div className="audit-cards-grid">
        <div className="audit-card">
          <div className="audit-card-label">Mathematical Formula</div>
          <div className="audit-card-formula">
            H = W_total / ∑(w_i / S_i)
          </div>
          <div className="audit-card-desc">
            Volume-weighted harmonic mean across reconstructed sessions.
          </div>
        </div>

        <div className="audit-card">
          <div className="audit-card-label">Operational Exposure Weight</div>
          <div className="audit-card-value">
            {(expl.total_volume_bytes || 0).toLocaleString()} bytes
          </div>
          <div className="audit-card-desc">
            TCP byte volume serves as proxy for operational network exposure.
          </div>
        </div>

        <div className="audit-card">
          <div className="audit-card-label">Weakest-Link Principle</div>
          <div className="audit-card-desc" style={{ marginTop: 6 }}>
            {expl.rationale || 'Penalizes critical vulnerabilities disproportionately to ensure security gaps cannot be averaged away.'}
          </div>
        </div>
      </div>

      {sessionContribs.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontWeight: 600, fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: 10 }}>
            Per-Session Traffic Volume & Enterprise Score Contribution
          </div>
          <div className="audit-table-wrap">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Flow</th>
                  <th>Protocol</th>
                  <th>Byte Volume</th>
                  <th>Traffic %</th>
                  <th>Score</th>
                  <th>Risk Tier</th>
                </tr>
              </thead>
              <tbody>
                {sessionContribs.map((c, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-primary)' }}>{c.flow || c.session_id}</td>
                    <td style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{c.protocol}</td>
                    <td>{(c.byte_count || 0).toLocaleString()} B</td>
                    <td>{(c.volume_percent || 0).toFixed(1)}%</td>
                    <td style={{
                      fontWeight: 700,
                      color: c.posture_score >= 80 ? 'var(--risk-low)' : c.posture_score >= 55 ? 'var(--risk-medium)' : c.posture_score >= 30 ? 'var(--risk-high)' : 'var(--risk-critical)',
                    }}>
                      {c.posture_score?.toFixed(1)}
                    </td>
                    <td>
                      <span className={`risk-pill risk-pill--${c.risk_tier}`} style={{ fontSize: '0.55rem', padding: '1px 6px' }}>
                        {c.risk_tier}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default function AnalysisPage({ result, analysisMs, onToast }) {
  const [activeTab, setActiveTab] = useState('sessions')
  const [digestCopied, setDigestCopied] = useState(false)

  const ev = result?.evidence || {}
  const epi = result?.enterprise_posture_index ?? 0
  const tier = result?.overall_risk_tier ?? 'CRITICAL'
  const rb = result?.risk_breakdown || {}
  const vb = result?.violation_severity_breakdown || {}
  const sessions = result?.sessions || []
  const totalViolations = result?.total_violations ?? 0

  const formatBytes = (b) => {
    if (!b) return '0 B'
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / (1024 * 1024)).toFixed(2)} MB`
  }

  const shortHash = ev.sha256_hash
    ? `${ev.sha256_hash.slice(0, 10)}…${ev.sha256_hash.slice(-8)}`
    : '—'

  const copyDigest = useCallback(() => {
    if (!ev.sha256_hash) return
    navigator.clipboard.writeText(ev.sha256_hash).then(() => {
      setDigestCopied(true)
      onToast?.('SHA-256 Digest copied to clipboard.', 'success')
      setTimeout(() => setDigestCopied(false), 2000)
    })
  }, [ev.sha256_hash, onToast])

  const handleQuickDownloadHTML = useCallback(() => {
    try {
      const html = buildHTMLReport(result)
      const filename = ev.filename?.replace(/\./g, '_') || 'pcap'
      const blob = new Blob([html], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `forensic_report_${filename}.html`
      a.click()
      URL.revokeObjectURL(url)
      onToast?.('HTML forensic report downloaded.', 'success')
    } catch (e) {
      onToast?.(`HTML export failed: ${e.message}`, 'error')
    }
  }, [result, ev.filename, onToast])

  const handleQuickDownloadJSON = useCallback(() => {
    try {
      const jsonStr = JSON.stringify(result, null, 2)
      const filename = ev.filename?.replace(/\./g, '_') || 'pcap'
      const blob = new Blob([jsonStr], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `forensic_report_${filename}.json`
      a.click()
      URL.revokeObjectURL(url)
      onToast?.('JSON report downloaded.', 'success')
    } catch (e) {
      onToast?.(`JSON export failed: ${e.message}`, 'error')
    }
  }, [result, ev.filename, onToast])

  return (
    <div className="page-inner">
      {/* ── KPI Strip (Aligned at top of page container) ── */}
      <div className="kpi-strip fade-in">
        <div className="kpi-item">
          <div className="kpi-label">Posture Index</div>
          <div className={`kpi-value ${getScoreClass(epi)}`}>{epi.toFixed(1)}</div>
          <div className="kpi-sub">out of 100</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Risk Tier</div>
          <div className={`kpi-value kpi-value--${tier.toLowerCase()} ${getTierClass(tier)}`}>{tier}</div>
          <div className="kpi-sub">overall posture</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Sessions</div>
          <div className="kpi-value kpi-value--blue">{result.session_count ?? sessions.length}</div>
          <div className="kpi-sub">reconstructed</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Findings</div>
          <div className={`kpi-value ${totalViolations > 0 ? getTierClass(tier) : 'kpi-value--green'}`}>
            {totalViolations}
          </div>
          <div className="kpi-sub">RFC/NIST violations</div>
        </div>
        {analysisMs != null && (
          <div className="kpi-item">
            <div className="kpi-label">Analyzed In</div>
            <div className="kpi-value kpi-value--green">{analysisMs.toFixed(2)}s</div>
            <div className="kpi-sub">pipeline latency</div>
          </div>
        )}
      </div>

      {/* ── Header Bar with Action Buttons ── */}
      <div className="header-bar fade-in">
        <div className="header-bar-titles">
          <div className="kicker">
            <span className="kicker-dot" />
            ANALYSIS / CRYPTOGRAPHIC POSTURE · {result.scoring_policy?.id || 'crypto-posture-v1'} v{result.scoring_policy?.version || '1.0'}
          </div>
          <h1 className="page-title">Email Cryptographic Forensics</h1>
          <p className="page-subtitle">
            AI-Assisted Passive Network Forensics · NIST SP 800-52r2 · RFC 9325 · RFC 8314 · RFC 8996
          </p>
        </div>

        <div className="header-actions">
          <button
            type="button"
            className="btn-action-primary"
            onClick={handleQuickDownloadHTML}
            title="Download standalone forensic HTML report"
          >
            <span>⬇</span>
            <span>HTML Report</span>
          </button>
          <button
            type="button"
            className="btn-action-secondary"
            onClick={handleQuickDownloadJSON}
            title="Download machine-readable JSON data"
          >
            <span>⬇</span>
            <span>JSON</span>
          </button>
          <button
            type="button"
            className="btn-action-ghost"
            onClick={copyDigest}
            title="Copy SHA-256 evidence digest"
          >
            <span>{digestCopied ? '✓' : '⎘'}</span>
            <span>{digestCopied ? 'Copied' : 'Digest'}</span>
          </button>
          <div className="header-seal">
            <span>ENGINE</span>
            <b>v{result.forensic_engine_version || '1.0.0'}</b>
          </div>
        </div>
      </div>

      {/* ── Executive Command Deck (Equal Height Columns) ── */}
      <div className="command-deck-grid fade-in">
        {/* Deck Column 1: Posture Gauge */}
        <div className="command-deck-card">
          <div className="deck-card-header">
            <span className="deck-card-title">Cryptographic Posture Index</span>
            <span className={`risk-pill risk-pill--${tier}`}>{tier}</span>
          </div>
          <div className="deck-card-body deck-card-body--gauge">
            <PostureGauge score={epi} tier={tier} bare />
          </div>
        </div>

        {/* Deck Column 2: Risk & Severity Matrix */}
        <div className="command-deck-card">
          <div className="deck-card-header">
            <span className="deck-card-title">Threat & Finding Distribution</span>
            <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              {sessions.length} Flows Analyzed
            </span>
          </div>
          <div className="deck-card-body">
            <RiskMatrix
              breakdown={rb}
              totalViolations={totalViolations}
              sessionCount={result?.session_count ?? sessions.length}
              violationBreakdown={vb}
              bare
            />
          </div>
        </div>

        {/* Deck Column 3: Forensic Ingestion & Integrity Seal */}
        <div className="command-deck-card deck-card-evidence">
          <div className="deck-card-header">
            <span className="deck-card-title">Evidence Ingestion & Integrity</span>
            <span className={`integrity-badge${ev.is_tamper_free === false ? ' integrity-badge--tampered' : ''}`}>
              {ev.is_tamper_free === false ? '⚠ TAMPERED' : '✔ INTACT'}
            </span>
          </div>

          <div className="deck-evidence-body">
            <div className="deck-evidence-filename" title={ev.filename}>
              📄 {ev.filename || 'Unknown PCAP'}
            </div>

            <div className="deck-evidence-hashrow">
              <span className="deck-hash-label">SHA-256</span>
              <span
                className={`hash-chip${digestCopied ? ' hash-chip--copied' : ''}`}
                onClick={copyDigest}
                title="Click to copy SHA-256 digest"
              >
                {digestCopied ? '✓ Copied!' : shortHash}
              </span>
            </div>

            <div className="deck-stats-grid">
              <div className="deck-stat">
                <div className="deck-stat-label">Packets</div>
                <div className="deck-stat-val">{(ev.total_packets || 0).toLocaleString()}</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">File Size</div>
                <div className="deck-stat-val">{formatBytes(ev.file_size_bytes)}</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">Duration</div>
                <div className="deck-stat-val">{(ev.capture_duration || 0).toFixed(2)}s</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">Format</div>
                <div className="deck-stat-val" style={{ color: 'var(--accent-blue)' }}>{ev.capture_format || 'PCAP'}</div>
              </div>
            </div>

            {ev.evidence_id && (
              <div className="deck-evidence-id">
                <span>Evidence ID:</span> <strong>{ev.evidence_id}</strong>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="analysis-layout fade-in">
        {/* ── Sidebar Navigation ── */}
        <div className="analysis-sidebar">
          <button
            type="button"
            className={`workspace-tab${activeTab === 'sessions' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            <span className="workspace-tab-icon">🌐</span>
            <span>Network Sessions</span>
            <span className="workspace-tab-badge">{sessions.length}</span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'findings' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            <span className="workspace-tab-icon">🚨</span>
            <span>Policy Findings</span>
            <span className={`workspace-tab-badge ${totalViolations > 0 ? 'workspace-tab-badge--alert' : ''}`}>
              {totalViolations}
            </span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'audit' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <span className="workspace-tab-icon">⚖</span>
            <span>Posture Audit</span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'evidence' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('evidence')}
          >
            <span className="workspace-tab-icon">🧬</span>
            <span>Evidence & Lineage</span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'export' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('export')}
          >
            <span className="workspace-tab-icon">⬇</span>
            <span>Export Suite</span>
          </button>
        </div>

        {/* ── Active Content Area ── */}
        <div className="analysis-content">
          {activeTab === 'sessions' && (
            <div>
              <SessionTable sessions={sessions} />
            </div>
          )}

          {activeTab === 'findings' && (
            <div>
              <FindingsExplorer sessions={sessions} />
            </div>
          )}

          {activeTab === 'audit' && (
            <div>
              <EnterpriseExplanationPanel
                explanation={result?.enterprise_explanation}
                policy={result?.scoring_policy}
                engineVersion={result?.forensic_engine_version}
                schemaVersion={result?.schema_version}
              />
            </div>
          )}

          {activeTab === 'evidence' && (
            <div>
              <EvidenceProvenancePanel
                evidence={ev}
                sessions={sessions}
                result={result}
              />
            </div>
          )}

          {activeTab === 'export' && (
            <div>
              <ExportPanel data={result} onToast={onToast} />
            </div>
          )}
        </div>
      </div>

      {/* ── Page Footer ── */}
      <div className="footer">
        🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework
        for Enterprise Email Cryptographic Posture Assessment<br />
        SIH-26 Demo · For authorized forensic use only · All analyses performed offline.
      </div>
    </div>
  )
}
