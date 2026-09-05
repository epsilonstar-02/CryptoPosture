import { useState, useEffect, useCallback, useRef } from 'react'
import { Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom'
import LandingHero    from './components/LandingHero.jsx'
import AnalysisPage   from './components/AnalysisPage.jsx'
import LoadingOverlay from './components/LoadingOverlay.jsx'
import Toast, { useToast } from './components/Toast.jsx'

const API = ''

export default function App() {
  const [result,        setResult]        = useState(null)
  const [loading,       setLoading]       = useState(false)
  const [analysisError, setAnalysisError] = useState(false)
  const [apiStatus,     setApiStatus]     = useState('loading')
  const [sampleCount,   setSampleCount]   = useState(null)
  const [analysisMs,    setAnalysisMs]    = useState(null)
  const [lastAnalyzedAt, setLastAnalyzedAt] = useState(null)
  const { toasts, push, dismiss } = useToast()

  // Holds the finished API result until the overlay signals it's done
  const pendingRef = useRef(null)

  const navigate  = useNavigate()
  const location  = useLocation()

  /* ── API health-check (feeds the Telemetry card) ── */
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API}/api/samples`, { signal: AbortSignal.timeout(4000) })
        if (res.ok) {
          setApiStatus('online')
          const data = await res.json()
          const count = Array.isArray(data) ? data.length : (Array.isArray(data?.samples) ? data.samples.length : null)
          setSampleCount(count)
        } else {
          setApiStatus('offline')
        }
      } catch {
        setApiStatus('offline')
      }
    }
    check()
    const id = setInterval(check, 10000)
    return () => clearInterval(id)
  }, [])

  /* Called by LoadingOverlay once all steps + hold are complete */
  const handleOverlayDone = useCallback(() => {
    if (pendingRef.current) {
      setResult(pendingRef.current)
      setLastAnalyzedAt(new Date())
      setAnalysisMs((performance.now() - window.__analysisStart) / 1000)
      pendingRef.current = null
      setAnalysisError(false)
      navigate('/analysis')
    }
  }, [navigate])

  /* ── File upload ── */
  const runAnalysis = useCallback(async (formData) => {
    setLoading(true)
    setAnalysisError(false)
    setResult(null)
    setAnalysisMs(null)
    pendingRef.current = null
    window.__analysisStart = performance.now()
    try {
      const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: formData })
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      pendingRef.current = await res.json()   // stash — overlay will commit it
    } catch (e) {
      push(`Analysis failed: ${e.message}`, 'error')
      pendingRef.current = null
      setAnalysisError(true)
    } finally {
      setLoading(false)   // signals overlay to finish its steps then call onDone
    }
  }, [push])

  const handleFile = useCallback((file) => {
    if (!file) return
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      push('Please upload a .pcap or .pcapng file.', 'error')
      return
    }
    const fd = new FormData()
    fd.append('file', file)
    runAnalysis(fd)
  }, [runAnalysis, push])

  /* ── Sample PCAP ── */
  const handleSample = useCallback(async (name) => {
    setLoading(true)
    setAnalysisError(false)
    setResult(null)
    setAnalysisMs(null)
    pendingRef.current = null
    window.__analysisStart = performance.now()
    try {
      const res = await fetch(`${API}/api/samples/${name}/analyze`)
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      pendingRef.current = await res.json()   // stash — overlay will commit it
    } catch (e) {
      push(`Sample analysis failed: ${e.message}`, 'error')
      pendingRef.current = null
      setAnalysisError(true)
    } finally {
      setLoading(false)   // signals overlay to finish its steps then call onDone
    }
  }, [push])

  /* ── Start new case ── */
  const startNewCase = useCallback(() => {
    setResult(null)
    setAnalysisMs(null)
    setAnalysisError(false)
    navigate('/')
  }, [navigate])

  const ev = result?.evidence || {}
  const isAnalysisRoute = location.pathname === '/analysis'

  return (
    <div className="app-shell">
      {/* ── Top bar ── */}
      <header className="topbar">
        {/* Logo — always navigates home */}
        <Link to="/" className="topbar-brand" onClick={startNewCase}>
          <div className="topbar-mark">
            <img src="/assets/shield-check.svg" alt="" />
          </div>
          <span>Crypto<span>Posture</span></span>
        </Link>

        <div className="topbar-sep" />

        <div className="topbar-context">
          <span className="topbar-dot" />
          PASSIVE FORENSICS
          <i />
          EMAIL CRYPTOGRAPHY
        </div>

        {isAnalysisRoute && result && (
          <>
            <div className="topbar-sep" />
            <div className="topbar-breadcrumb">
              <span>Analysis</span>
              <span className="topbar-breadcrumb-sep">›</span>
              <span className="topbar-breadcrumb-file">{ev.filename || 'unknown'}</span>
            </div>
          </>
        )}

        <div className="topbar-actions">
          <span className={`api-state api-state--${apiStatus}`}>
            <b />
            {apiStatus === 'online' ? 'ONLINE' : apiStatus === 'loading' ? 'CONNECTING' : 'OFFLINE'}
          </span>
          {isAnalysisRoute && result && (
            <button className="new-case" onClick={startNewCase}>+ New case</button>
          )}
        </div>
      </header>

      <main className="main-content">
        <LoadingOverlay loading={loading} hasError={analysisError} onDone={handleOverlayDone} />

        <Routes>
          {/* Home / Landing page */}
          <Route
            path="/"
            element={
              <LandingHero
                onFile={handleFile}
                onSample={handleSample}
                loading={loading}
                apiStatus={apiStatus}
                sampleCount={sampleCount}
                lastAnalyzedAt={lastAnalyzedAt}
                lastResult={result}
              />
            }
          />

          {/* Analysis results page */}
          <Route
            path="/analysis"
            element={
              result ? (
                <AnalysisPage
                  result={result}
                  analysisMs={analysisMs}
                  onToast={push}
                />
              ) : (
                /* Guard: if someone navigates to /analysis without data, redirect home */
                <div className="page-inner" style={{ paddingTop: 60, textAlign: 'center' }}>
                  <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    No analysis in session. <Link to="/" style={{ color: 'var(--accent-blue)' }}>← Return home</Link>
                  </p>
                </div>
              )
            }
          />
        </Routes>
      </main>

      <Toast toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
