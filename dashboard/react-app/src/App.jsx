import { useState, useEffect, useCallback, useRef } from 'react'
import { Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom'
import LandingHero    from './components/LandingHero.jsx'
import AnalysisPage   from './components/AnalysisPage.jsx'
import LoadingOverlay from './components/LoadingOverlay.jsx'
import Toast, { useToast } from './components/Toast.jsx'
import AuthModal      from './components/AuthModal.jsx'
import HistoryDrawer  from './components/HistoryDrawer.jsx'

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

  // Authentication & History state
  const [token, setToken] = useState(() => localStorage.getItem('auth_token') || '')
  const [currentUser, setCurrentUser] = useState(null)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userMenuRef = useRef(null)

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

  /* ── Load authenticated user profile ── */
  useEffect(() => {
    if (!token) {
      setCurrentUser(null)
      return
    }
    fetch(`${API}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) {
          localStorage.removeItem('auth_token')
          setToken('')
          setCurrentUser(null)
          return null
        }
        return res.json()
      })
      .then((user) => {
        if (user) setCurrentUser(user)
      })
      .catch(() => {})
  }, [token])

  const handleAuthSuccess = useCallback((user, accessToken) => {
    setCurrentUser(user)
    setToken(accessToken)
  }, [])

  const handleLogout = useCallback(() => {
    localStorage.removeItem('auth_token')
    setToken('')
    setCurrentUser(null)
    setUserMenuOpen(false)
    push('Signed out successfully', 'info')
  }, [push])

  /* Close user dropdown when clicking outside or pressing Escape */
  useEffect(() => {
    if (!userMenuOpen) return
    const handleClickOutside = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setUserMenuOpen(false)
      }
    }
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setUserMenuOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [userMenuOpen])

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

  /* ── Load record directly from Investigation History ── */
  const handleLoadRecord = useCallback((recordSummary) => {
    setResult(recordSummary)
    setLastAnalyzedAt(new Date())
    setAnalysisMs(recordSummary?.meta?.processing_time_ms ? recordSummary.meta.processing_time_ms / 1000 : null)
    setAnalysisError(false)
    navigate('/analysis')
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
      const headers = {}
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: formData, headers })
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      pendingRef.current = await res.json()   // stash — overlay will commit it
    } catch (e) {
      push(`Analysis failed: ${e.message}`, 'error')
      pendingRef.current = null
      setAnalysisError(true)
    } finally {
      setLoading(false)   // signals overlay to finish its steps then call onDone
    }
  }, [token, push])

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
      const headers = {}
      if (token) headers['Authorization'] = `Bearer ${token}`
      const res = await fetch(`${API}/api/samples/${name}/analyze`, { headers })
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      pendingRef.current = await res.json()   // stash — overlay will commit it
    } catch (e) {
      push(`Sample analysis failed: ${e.message}`, 'error')
      pendingRef.current = null
      setAnalysisError(true)
    } finally {
      setLoading(false)   // signals overlay to finish its steps then call onDone
    }
  }, [token, push])

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

          <button
            type="button"
            className="btn-history-topbar"
            onClick={() => setHistoryOpen(true)}
            title="Open Investigation History"
          >
            🗄️ History
          </button>

          {isAnalysisRoute && result && (
            <button className="new-case" onClick={startNewCase}>+ New case</button>
          )}

          <div className="topbar-user-area" ref={userMenuRef}>
            {currentUser ? (
              <div className="user-menu-container">
                <button
                  type="button"
                  className={`user-badge-pill-btn ${userMenuOpen ? 'user-badge-pill-btn--open' : ''}`}
                  onClick={() => setUserMenuOpen((prev) => !prev)}
                  title={`Signed in as ${currentUser.username} (${currentUser.role})`}
                  aria-expanded={userMenuOpen}
                >
                  <span className="user-badge-avatar">👤</span>
                  <span className="user-badge-name">{currentUser.username}</span>
                  <span className={`user-role-tag user-role-tag--${currentUser.role === 'admin' ? 'admin' : currentUser.role === 'lead_analyst' ? 'lead' : currentUser.role === 'auditor' ? 'auditor' : 'analyst'}`}>
                    {currentUser.role}
                  </span>
                  <span className="user-badge-caret">{userMenuOpen ? '▲' : '▼'}</span>
                </button>

                {userMenuOpen && (
                  <div className="user-dropdown-menu fade-in">
                    <div className="user-dropdown-header">
                      <div className="user-dropdown-name">{currentUser.username}</div>
                      <div className="user-dropdown-email">{currentUser.email || 'Analyst Account'}</div>
                    </div>

                    <div className="user-dropdown-divider" />

                    <button
                      type="button"
                      className="user-dropdown-item"
                      onClick={() => {
                        setUserMenuOpen(false)
                        setHistoryOpen(true)
                      }}
                    >
                      <span className="user-dropdown-item-icon">🗄️</span>
                      <div className="user-dropdown-item-content">
                        <span className="user-dropdown-item-title">Investigation History</span>
                        <span className="user-dropdown-item-sub">View past PCAP analyses</span>
                      </div>
                    </button>

                    <div className="user-dropdown-divider" />

                    <button
                      type="button"
                      className="user-dropdown-item user-dropdown-item--danger"
                      onClick={() => {
                        setUserMenuOpen(false)
                        handleLogout()
                      }}
                    >
                      <span className="user-dropdown-item-icon">🚪</span>
                      <div className="user-dropdown-item-content">
                        <span className="user-dropdown-item-title">Sign Out</span>
                      </div>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <button
                type="button"
                className="btn-signin"
                onClick={() => setAuthModalOpen(true)}
              >
                🔑 Sign In
              </button>
            )}
          </div>
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

      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthSuccess={handleAuthSuccess}
        onToast={push}
      />

      <HistoryDrawer
        isOpen={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onLoadRecord={handleLoadRecord}
        currentUser={currentUser}
        token={token}
        onToast={push}
      />

      <Toast toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
