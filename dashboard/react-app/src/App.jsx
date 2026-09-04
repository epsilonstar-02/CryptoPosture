import { useState, useEffect, useCallback } from 'react'
import Sidebar          from './components/Sidebar.jsx'
import LandingHero      from './components/LandingHero.jsx'
import EvidenceBanner   from './components/EvidenceBanner.jsx'
import PostureGauge     from './components/PostureGauge.jsx'
import RiskMatrix       from './components/RiskMatrix.jsx'
import SessionTable     from './components/SessionTable.jsx'
import ExportPanel      from './components/ExportPanel.jsx'
import LoadingOverlay   from './components/LoadingOverlay.jsx'

const API = ''

export default function App() {
  const [result,     setResult]     = useState(null)   // full API response
  const [loading,    setLoading]    = useState(false)
  const [apiStatus,  setApiStatus]  = useState('loading')
  const [analysisMs, setAnalysisMs] = useState(null)

  // API health check — must use a /api/* path so Vite proxies it to FastAPI.
  // Fetching '/' only hits the Vite dev server (returns HTML, not JSON).
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API}/api/samples`, { signal: AbortSignal.timeout(4000) })
        setApiStatus(res.ok ? 'online' : 'offline')
      } catch {
        setApiStatus('offline')
      }
    }
    check()
    const id = setInterval(check, 10000) // re-check every 10 s
    return () => clearInterval(id)
  }, [])

  const handleResult = useCallback((data, elapsedSec) => {
    setResult(data)
    if (elapsedSec != null) setAnalysisMs(elapsedSec)
  }, [])

  const handleLoading = useCallback((isLoading) => {
    setLoading(isLoading)
    if (isLoading) {
      setResult(null)
      setAnalysisMs(null)
      window.__analysisStart = performance.now()
    } else {
      const elapsed = window.__analysisStart
        ? (performance.now() - window.__analysisStart) / 1000
        : null
      setAnalysisMs(elapsed)
    }
  }, [])

  const ev   = result?.evidence || {}
  const epi  = result?.enterprise_posture_index ?? 0
  const tier = result?.overall_risk_tier ?? 'CRITICAL'
  const rb   = result?.risk_breakdown || {}
  const sessions = result?.sessions || []

  return (
    <div className="layout">
      <Sidebar
        onResult={handleResult}
        onLoading={handleLoading}
        loading={loading}
        apiStatus={apiStatus}
      />

      <main className="main-content">
        <LoadingOverlay visible={loading} />

        {!result ? (
          <LandingHero />
        ) : (
          <>
            {/* Page header */}
            <div className="header-bar fade-in">
              <h1 className="page-title">Email Cryptographic Forensics</h1>
            </div>
            <p className="page-subtitle">
              AI-Assisted Passive Network Forensics · NIST SP 800-52 · RFC 9325 · RFC 8314
            </p>

            {/* Evidence banner */}
            <EvidenceBanner evidence={ev} analysisTime={analysisMs} />

            {/* Posture + Risk */}
            <div className="posture-section">
              <PostureGauge score={epi} tier={tier} />
              <RiskMatrix
                breakdown={rb}
                totalViolations={result?.total_violations}
                sessionCount={result?.session_count}
              />
            </div>

            {/* Session table */}
            <div className="section-header">
              <span className="section-title">Session Analysis</span>
              <div className="section-line" />
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                {sessions.length} session{sessions.length !== 1 ? 's' : ''} · click row to expand
              </span>
            </div>
            <SessionTable sessions={sessions} />

            {/* Export */}
            <div className="section-header">
              <span className="section-title">Export Reports</span>
              <div className="section-line" />
            </div>
            <ExportPanel data={result} />

            {/* Footer */}
            <div className="footer">
              🔐 CryptoPosture · AI-Assisted Passive Network Forensic Framework for Enterprise Email Cryptographic Posture Assessment<br />
              SIH-26 Demo · For authorized forensic use only · All analyses performed offline, no data transmitted externally.
            </div>
          </>
        )}
      </main>
    </div>
  )
}
