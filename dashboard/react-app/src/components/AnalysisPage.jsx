import EvidenceBanner from './EvidenceBanner.jsx'
import PostureGauge   from './PostureGauge.jsx'
import RiskMatrix     from './RiskMatrix.jsx'
import SessionTable   from './SessionTable.jsx'
import ExportPanel    from './ExportPanel.jsx'

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

export default function AnalysisPage({ result, analysisMs, onToast }) {
  const ev       = result?.evidence || {}
  const epi      = result?.enterprise_posture_index ?? 0
  const tier     = result?.overall_risk_tier ?? 'CRITICAL'
  const rb       = result?.risk_breakdown || {}
  const sessions = result?.sessions || []

  return (
    <>
      {/* ── KPI Strip ── */}
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
          <div className="kpi-sub">analyzed</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Violations</div>
          <div className={`kpi-value ${(result.total_violations ?? 0) > 0 ? getTierClass(tier) : 'kpi-value--green'}`}>
            {result.total_violations ?? 0}
          </div>
          <div className="kpi-sub">total findings</div>
        </div>
        {analysisMs != null && (
          <div className="kpi-item">
            <div className="kpi-label">Analyzed in</div>
            <div className="kpi-value kpi-value--green">{analysisMs.toFixed(2)}s</div>
            <div className="kpi-sub">wall clock</div>
          </div>
        )}
      </div>

      {/* ── Page content ── */}
      <div className="page-inner">
        <div className="header-bar fade-in">
          <div>
            <div className="kicker"><span className="kicker-dot" /> ANALYSIS / CRYPTOGRAPHIC POSTURE</div>
            <h1 className="page-title">Email Cryptographic Forensics</h1>
          </div>
          <div className="header-seal"><span>CASE</span><b>ACTIVE</b></div>
        </div>
        <p className="page-subtitle">
          AI-Assisted Passive Network Forensics · NIST SP 800-52 · RFC 9325 · RFC 8314
        </p>

        {/* Evidence */}
        <EvidenceBanner evidence={ev} />

        {/* Posture + Risk */}
        <div className="posture-section">
          <PostureGauge score={epi} tier={tier} />
          <RiskMatrix
            breakdown={rb}
            totalViolations={result?.total_violations}
            sessionCount={result?.session_count}
          />
        </div>

        {/* Sessions */}
        <div className="section-header">
          <span className="section-title">Session Analysis</span>
          <div className="section-line" />
          <span className="section-count">
            {sessions.length} session{sessions.length !== 1 ? 's' : ''} · click row to expand
          </span>
        </div>
        <SessionTable sessions={sessions} />

        {/* Export */}
        <div className="section-header">
          <span className="section-title">Export Reports</span>
          <div className="section-line" />
        </div>
        <ExportPanel data={result} onToast={onToast} />

        <div className="footer">
          🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework
          for Enterprise Email Cryptographic Posture Assessment<br />
          SIH-26 Demo · For authorized forensic use only · All analyses performed offline.
        </div>
      </div>
    </>
  )
}
