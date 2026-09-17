import { useState, useEffect, useCallback, useRef } from 'react'
import { Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom'
import LandingHero          from './components/LandingHero.jsx'
import AnalysisPage         from './components/AnalysisPage.jsx'
import LoadingOverlay       from './components/LoadingOverlay.jsx'
import Toast, { useToast }  from './components/Toast.jsx'
import AuthModal            from './components/AuthModal.jsx'
import HistoryDrawer        from './components/HistoryDrawer.jsx'
import AdminConsoleModal    from './components/AdminConsoleModal.jsx'
import AnalystWorkspaceModal from './components/AnalystWorkspaceModal.jsx'

const API = ''

const GLASS_PALETTES = [
  // Core Palettes
  { id: 'ember-slate',     name: 'Ember & Slate',     category: 'Classic', desc: 'Charcoal base & warm amber',   color: '#f59e0b' },
  { id: 'ocean-frost',     name: 'Ocean Frost',      category: 'Icy',     desc: 'Deep navy & electric cyan',    color: '#06b6d4' },
  { id: 'emerald-mist',    name: 'Emerald Mist',     category: 'Forest',  desc: 'Forest obsidian & jade gold',  color: '#10b981' },
  { id: 'warm-sunset',     name: 'Warm Sunset',      category: 'Vivid',   desc: 'Burgundy & sunset orange',     color: '#f97316' },
  { id: 'soft-bloom',      name: 'Soft Bloom',       category: 'Warm',    desc: 'Dark plum & violet orchid',    color: '#c084fc' },

  // Specialized Forensics & Security Palettes
  { id: 'cyber-sentinel',  name: 'Cyber Sentinel',   category: 'SOC',     desc: 'SOC midnight & electric cyan', color: '#00f0ff' },
  { id: 'quantum-kyber',   name: 'Quantum Kyber',    category: 'PQC',     desc: 'Post-quantum obsidian & teal', color: '#2dd4bf' },
  { id: 'zero-trust',      name: 'Zero Trust',       category: 'Threat',  desc: 'Vantablack & incident crimson',color: '#fb7185' },
  { id: 'deep-nebula',     name: 'Deep Nebula',      category: 'Space',   desc: 'Cosmic void & amethyst glow',  color: '#a855f7' },
  { id: 'aurora-borealis', name: 'Aurora Borealis',  category: 'Boreal',  desc: 'Arctic night & boreal emerald',color: '#34d399' },
]

const NEU_PALETTES = [
  // Canonical Light Soft UI (Ref: .agent/skills/neuromorphic/DESIGN.md & SKILL.md)
  { id: 'stone-lavender',  name: 'Stone Lavender',   category: 'Light',   desc: 'Canonical #e0e5ec & lavender accent', color: '#9b72cf' },
  { id: 'slate-mist',      name: 'Slate Mist',       category: 'Light',   desc: 'Technical cool slate & cyan/teal',   color: '#00b4d8' },
  { id: 'warm-linen',      name: 'Warm Linen',       category: 'Light',   desc: 'Tactile warm linen & amber gold',    color: '#e9a825' },

  // Stealth Dark Soft UI (Ref: .agent/skills/neuromorphic/DESIGN.md & SKILL.md)
  { id: 'midnight-soc',    name: 'Midnight SOC',     category: 'Dark',    desc: 'Charcoal #1e2228 & electric cyan',   color: '#00f0ff' },
  { id: 'graphite-kyber',  name: 'Graphite Kyber',   category: 'Dark',    desc: 'Deep graphite & matrix teal',        color: '#2dd4bf' },
  { id: 'zero-trust-neu',  name: 'Zero Trust Dark',  category: 'Dark',    desc: 'Incident obsidian & crimson rose',   color: '#fb7185' },
]

export default function App() {
  const [result,        setResult]        = useState(null)
  const [loading,       setLoading]       = useState(false)
  const [analysisError, setAnalysisError] = useState(false)
  const [apiStatus,     setApiStatus]     = useState('loading')
  const [sampleCount,   setSampleCount]   = useState(null)
  const [analysisMs,    setAnalysisMs]    = useState(null)
  const [lastAnalyzedAt, setLastAnalyzedAt] = useState(null)
  const { toasts, push, dismiss } = useToast()

  // UI Design System Style: 'neumorphic' (Soft UI) | 'glass' (Liquid Glass)
  const [uiStyle, setUiStyle] = useState(() => localStorage.getItem('ui_style') || 'neumorphic')

  // Theme & Palette state (persists per design style)
  const [neuPalette, setNeuPalette] = useState(() => localStorage.getItem('neu_palette') || 'stone-lavender')
  const [glassPalette, setGlassPalette] = useState(() => localStorage.getItem('glass_palette') || 'ember-slate')
  const [paletteMenuOpen, setPaletteMenuOpen] = useState(false)
  const paletteMenuRef = useRef(null)

  const activePalettes = uiStyle === 'neumorphic' ? NEU_PALETTES : GLASS_PALETTES
  const activePaletteId = uiStyle === 'neumorphic' ? neuPalette : glassPalette
  const activePaletteObj = activePalettes.find((p) => p.id === activePaletteId) || activePalettes[0]

  // Authentication & History state
  const [token, setToken] = useState(() => localStorage.getItem('auth_token') || '')
  const [currentUser, setCurrentUser] = useState(null)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [adminModalOpen, setAdminModalOpen] = useState(false)
  const [analystModalOpen, setAnalystModalOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userMenuRef = useRef(null)

  // Holds the finished API result until the overlay signals it's done
  const pendingRef = useRef(null)

  // Sync UI style to document element
  useEffect(() => {
    localStorage.setItem('ui_style', uiStyle)
    document.documentElement.setAttribute('data-style', uiStyle)
  }, [uiStyle])

  // Sync active palette to document element
  useEffect(() => {
    if (uiStyle === 'neumorphic') {
      localStorage.setItem('neu_palette', neuPalette)
      document.documentElement.setAttribute('data-theme', neuPalette)
    } else {
      localStorage.setItem('glass_palette', glassPalette)
      document.documentElement.setAttribute('data-theme', glassPalette)
    }
  }, [uiStyle, neuPalette, glassPalette])

  const handleSelectPalette = useCallback((id) => {
    if (uiStyle === 'neumorphic') {
      setNeuPalette(id)
    } else {
      setGlassPalette(id)
    }
    setPaletteMenuOpen(false)
    const target = (uiStyle === 'neumorphic' ? NEU_PALETTES : GLASS_PALETTES).find(p => p.id === id)
    push(`Switched to ${target?.name || id} palette`, 'info')
  }, [uiStyle, push])

  const handleStyleChange = useCallback((newStyle) => {
    setUiStyle(newStyle)
    push(`Activated ${newStyle === 'neumorphic' ? 'Soft UI (Neumorphism)' : 'Liquid Glass'} design system`, 'info')
  }, [push])

  // Close palette dropdown when clicking outside
  useEffect(() => {
    if (!paletteMenuOpen) return
    const handleClickOutside = (e) => {
      if (paletteMenuRef.current && !paletteMenuRef.current.contains(e.target)) {
        setPaletteMenuOpen(false)
      }
    }
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setPaletteMenuOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [paletteMenuOpen])

  const navigate  = useNavigate()
  const location  = useLocation()

  const scrollToPageTop = useCallback(() => {
    try {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
    } catch {
      window.scrollTo(0, 0)
    }
    if (document.documentElement) document.documentElement.scrollTop = 0
    if (document.body) document.body.scrollTop = 0
  }, [])

  // Automatically scroll to the very top whenever the route changes
  useEffect(() => {
    scrollToPageTop()
  }, [location.pathname, scrollToPageTop])

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
      scrollToPageTop()
      navigate('/analysis')
    }
  }, [navigate, scrollToPageTop])

  /* ── Load record directly from Investigation History ── */
  const handleLoadRecord = useCallback((recordSummary) => {
    setResult(recordSummary)
    setLastAnalyzedAt(new Date())
    setAnalysisMs(recordSummary?.meta?.processing_time_ms ? recordSummary.meta.processing_time_ms / 1000 : null)
    setAnalysisError(false)
    scrollToPageTop()
    navigate('/analysis')
  }, [navigate, scrollToPageTop])

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
    scrollToPageTop()
    navigate('/')
  }, [navigate, scrollToPageTop])

  const isAnalysisRoute = location.pathname === '/analysis'

  return (
    <div className="app-shell" data-style={uiStyle} data-theme={activePaletteId}>
      {/* ── Background Scene: Fixed organic blurred animated blobs (Glass mode only) ── */}
      {uiStyle === 'glass' && (
        <div className="bg-scene" aria-hidden="true">
          <div className="blob blob-1" />
          <div className="blob blob-2" />
          <div className="blob blob-3" />
        </div>
      )}

      {/* ── Top bar ── */}
      <header className="topbar glass-nav">
        {/* Left Zone: Brand & Primary Action */}
        <div className="topbar-left">
          <Link to="/" className="topbar-brand" onClick={startNewCase} title="CryptoPosture — Passive Network Forensics">
            <div className="topbar-mark">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
              </svg>
            </div>
            <span>Crypto<span>Posture</span></span>
          </Link>

          {/* Primary Quick Workflow Action */}
          {isAnalysisRoute && result && (
            <button type="button" className="btn-new-case" onClick={startNewCase} title="Start a new PCAP investigation">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              <span>New Case</span>
            </button>
          )}
        </div>

        {/* Right Zone: Organized Semantic Clusters */}
        <div className="topbar-actions">
          {/* Cluster 1: Investigation & Operations */}
          <div className="topbar-cluster topbar-cluster--tools">
            <button
              type="button"
              className="btn-history-topbar"
              onClick={() => setHistoryOpen(true)}
              title="Open Investigation History"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>
              <span>History</span>
            </button>

            {currentUser?.role === 'admin' && (
              <button
                type="button"
                className="btn-admin-topbar"
                onClick={() => setAdminModalOpen(true)}
                title="Open Admin Console"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                <span>Admin</span>
              </button>
            )}

            {currentUser && currentUser.role !== 'admin' && (
              <button
                type="button"
                className="btn-analyst-topbar"
                onClick={() => setAnalystModalOpen(true)}
                title="Open Analyst Operations Workspace"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                <span>Analyst</span>
              </button>
            )}
          </div>

          <div className="topbar-actions-sep" aria-hidden="true" />

          {/* Cluster 2: Design Appearance & Theme */}
          <div className="topbar-cluster topbar-cluster--appearance">

          {/* Style Mode Switcher: Soft UI vs Liquid Glass */}
          <div className="style-mode-switcher" role="group" aria-label="Design System Style">
            <button
              type="button"
              className={`style-mode-btn ${uiStyle === 'neumorphic' ? 'style-mode-btn--active' : ''}`}
              onClick={() => handleStyleChange('neumorphic')}
              title="Switch to tactile Neumorphic (Soft UI) mode"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 2a10 10 0 0 0 0 20Z" fill="currentColor" opacity="0.4" />
              </svg>
              <span>Soft UI</span>
            </button>
            <button
              type="button"
              className={`style-mode-btn ${uiStyle === 'glass' ? 'style-mode-btn--active' : ''}`}
              onClick={() => handleStyleChange('glass')}
              title="Switch to Liquid Glass frosted translucent mode"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
              </svg>
              <span>Glass</span>
            </button>
          </div>

          {/* Palette Selector Dropdown */}
          <div className="palette-menu-container" ref={paletteMenuRef}>
            <button
              type="button"
              className={`btn-palette-topbar ${paletteMenuOpen ? 'btn-palette-topbar--open' : ''}`}
              onClick={() => setPaletteMenuOpen((prev) => !prev)}
              title={`Theme Palette: ${activePaletteObj.name}`}
              aria-expanded={paletteMenuOpen}
            >
              <span
                className="palette-dot"
                style={{ background: activePaletteObj.color }}
              />
              <span className="palette-label">{activePaletteObj.name}</span>
              <span className="palette-caret">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ transform: paletteMenuOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s ease' }} aria-hidden="true">
                  <polyline points="6 9 12 15 18 9"/>
                </svg>
              </span>
            </button>

            {paletteMenuOpen && (
              <div className="glass-menu palette-dropdown fade-in">
                <div className="palette-dropdown-title">
                  {uiStyle === 'neumorphic' ? 'Soft UI Palettes' : 'Theme Palettes'} ({activePalettes.length})
                </div>
                <div className="palette-dropdown-scroll">
                  {activePalettes.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className={`palette-dropdown-item ${activePaletteId === p.id ? 'palette-dropdown-item--active' : ''}`}
                      onClick={() => handleSelectPalette(p.id)}
                    >
                      <span className="palette-color-swatch" style={{ background: p.color, boxShadow: `0 0 10px ${p.color}88` }} />
                      <div className="palette-item-text">
                        <span className="palette-item-name">
                          <span>{p.name}</span>
                          {p.category && <span className="palette-category-badge">{p.category}</span>}
                        </span>
                        <span className="palette-item-desc">{p.desc}</span>
                      </div>
                      {activePaletteId === p.id && (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p.color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          </div>

          <div className="topbar-actions-sep" aria-hidden="true" />

          {/* Cluster 3: System Status & User Profile */}
          <div className="topbar-cluster topbar-cluster--identity">
            <span className={`api-state api-state--${apiStatus}`} title={`API Telemetry: ${apiStatus.toUpperCase()}`}>
              <b />
              <span className="api-state-label">{apiStatus === 'online' ? 'ONLINE' : apiStatus === 'loading' ? 'SYNC' : 'OFFLINE'}</span>
            </span>

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
                  <span className="user-badge-avatar">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                  </span>
                  <span className="user-badge-name">{currentUser.username}</span>
                  <span className={`user-role-tag user-role-tag--${currentUser.role === 'admin' ? 'admin' : 'analyst'}`}>
                    {currentUser.role}
                  </span>
                  <span className="user-badge-caret">
                    {userMenuOpen
                      ? <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m18 15-6-6-6 6"/></svg>
                      : <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
                    }
                  </span>
                </button>

                {userMenuOpen && (
                  <div className="glass-menu user-dropdown-menu fade-in">
                    <div className="user-dropdown-header">
                      <div className="user-dropdown-name">{currentUser.username}</div>
                      <div className="user-dropdown-email">{currentUser.email || `${currentUser.role} account`}</div>
                    </div>

                    <div className="user-dropdown-divider" />

                    {/* Admin Console Item */}
                    {currentUser.role === 'admin' && (
                      <button
                        type="button"
                        className="user-dropdown-item"
                        onClick={() => {
                          setUserMenuOpen(false)
                          setAdminModalOpen(true)
                        }}
                      >
                        <span className="user-dropdown-item-icon">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                        </span>
                        <div className="user-dropdown-item-content">
                          <span className="user-dropdown-item-title">Admin Console</span>
                          <span className="user-dropdown-item-sub">User provisioning, audit logs, policy</span>
                        </div>
                      </button>
                    )}

                    {/* Analyst Workspace Item */}
                    <button
                      type="button"
                      className="user-dropdown-item"
                      onClick={() => {
                        setUserMenuOpen(false)
                        setAnalystModalOpen(true)
                      }}
                    >
                      <span className="user-dropdown-item-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                      </span>
                      <div className="user-dropdown-item-content">
                        <span className="user-dropdown-item-title">Analyst Workspace</span>
                        <span className="user-dropdown-item-sub">My cases, triage queue, metrics</span>
                      </div>
                    </button>

                    <button
                      type="button"
                      className="user-dropdown-item"
                      onClick={() => {
                        setUserMenuOpen(false)
                        setHistoryOpen(true)
                      }}
                    >
                      <span className="user-dropdown-item-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>
                      </span>
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
                      <span className="user-dropdown-item-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                      </span>
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
                title="Sign in as Analyst or Administrator"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
                <span>Sign In</span>
              </button>
            )}
            </div>
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
                  currentUser={currentUser}
                  token={token}
                  onTriageUpdated={(updatedTriage) => {
                    setResult((prev) => (prev ? { ...prev, triage: updatedTriage } : prev))
                  }}
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

      <AdminConsoleModal
        isOpen={adminModalOpen}
        onClose={() => setAdminModalOpen(false)}
        currentUser={currentUser}
        token={token}
        onToast={push}
      />

      <AnalystWorkspaceModal
        isOpen={analystModalOpen}
        onClose={() => setAnalystModalOpen(false)}
        currentUser={currentUser}
        token={token}
        onLoadRecord={handleLoadRecord}
        onToast={push}
      />

      <Toast toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
