import { useState, useEffect, useCallback } from 'react'

export default function HistoryDrawer({ isOpen, onClose, onLoadRecord, currentUser, token, onToast }) {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [selectedTier, setSelectedTier] = useState('ALL')
  const [selectedTriage, setSelectedTriage] = useState('ALL')
  const [onlyMine, setOnlyMine] = useState(false)
  const [loadingId, setLoadingId] = useState(null)

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (selectedTier !== 'ALL') params.append('risk_tier', selectedTier)
      if (selectedTriage !== 'ALL') params.append('triage_status', selectedTriage)
      if (onlyMine && currentUser) params.append('only_mine', 'true')
      if (search.trim()) params.append('search', search.trim())

      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const res = await fetch(`/api/history?${params.toString()}`, { headers })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setItems(data.items || [])
    } catch (e) {
      onToast(`Failed to load history: ${e.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [selectedTier, selectedTriage, onlyMine, currentUser, search, token, onToast])

  useEffect(() => {
    if (isOpen) {
      fetchHistory()
    }
  }, [isOpen, fetchHistory])

  // Close on ESC
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const handleLoad = async (recordId) => {
    setLoadingId(recordId)
    try {
      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const res = await fetch(`/api/history/${recordId}`, { headers })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const fullSummary = await res.json()
      onLoadRecord(fullSummary)
      onToast(`Loaded investigation: ${fullSummary?.evidence?.filename || recordId}`, 'success')
      onClose()
    } catch (err) {
      onToast(`Failed to load record: ${err.message}`, 'error')
    } finally {
      setLoadingId(null)
    }
  }

  const handleDelete = async (e, recordId, filename) => {
    e.stopPropagation()
    if (!window.confirm(`Delete persistent record for '${filename}'?`)) return

    try {
      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const res = await fetch(`/api/history/${recordId}`, {
        method: 'DELETE',
        headers,
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.detail?.message || `HTTP ${res.status}`)
      }
      onToast(`Record '${filename}' deleted`, 'info')
      setItems((prev) => prev.filter((it) => it.id !== recordId))
    } catch (err) {
      onToast(`Failed to delete record: ${err.message}`, 'error')
    }
  }

  if (!isOpen) return null

  const getTierClass = (tier) => {
    switch (tier?.toUpperCase()) {
      case 'CRITICAL': return 'tier-pill--critical'
      case 'HIGH':     return 'tier-pill--high'
      case 'MEDIUM':   return 'tier-pill--medium'
      case 'LOW':      return 'tier-pill--low'
      default:         return ''
    }
  }

  return (
    <div className="history-drawer-overlay" onClick={onClose}>
      <div className="history-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="history-drawer-header">
          <div className="history-drawer-title">
            <span className="history-drawer-icon" style={{ color: 'var(--accent-primary)', display: 'flex' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>
            </span>
            <div>
              <h3>Investigation History</h3>
              <p>Persistent forensic record store</p>
            </div>
          </div>
          <button className="history-drawer-close" onClick={onClose} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Filters */}
        <div className="history-drawer-controls">
          <div className="history-search-box">
            <input
              type="text"
              placeholder="Search filename or SHA-256..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          {/* Scope Toggle: All Team Cases vs My Cases */}
          {currentUser && (
            <div className="history-scope-toggle">
              <button
                type="button"
                className={`history-scope-btn ${!onlyMine ? 'history-scope-btn--active' : ''}`}
                onClick={() => setOnlyMine(false)}
              >
                All Team Captures
              </button>
              <button
                type="button"
                className={`history-scope-btn ${onlyMine ? 'history-scope-btn--active' : ''}`}
                onClick={() => setOnlyMine(true)}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 5, verticalAlign: -1 }}><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                My Investigations Only
              </button>
            </div>
          )}

          {/* Risk Tier Chips */}
          <div className="history-tier-chips">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((t) => (
              <button
                key={t}
                className={`history-tier-chip ${selectedTier === t ? 'history-tier-chip--active' : ''}`}
                onClick={() => setSelectedTier(t)}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Triage Status Filter */}
          <div style={{ marginTop: 8 }}>
            <select
              className="history-triage-select"
              value={selectedTriage}
              onChange={(e) => setSelectedTriage(e.target.value)}
            >
              <option value="ALL">All Triage Statuses</option>
              <option value="UNASSIGNED">Unassigned</option>
              <option value="UNDER_REVIEW">Under Review</option>
              <option value="FLAGGED_MALICIOUS">Flagged Malicious</option>
              <option value="COMPLIANT">Compliant</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>

        {/* List */}
        <div className="history-drawer-body">
          {loading ? (
            <div className="history-empty">Loading historical captures...</div>
          ) : items.length === 0 ? (
            <div className="history-empty">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--text-muted)', marginBottom: 8 }}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
              <p>No recorded investigations found.</p>
              <small>Upload a PCAP capture or run any sample scenario to automatically persist it here.</small>
            </div>
          ) : (
            items.map((item) => (
              <div
                key={item.id}
                className="history-item-card"
                onClick={() => handleLoad(item.id)}
              >
                <div className="history-item-top">
                  <span className="history-item-name" title={item.filename}>
                    {item.filename}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span className={`triage-tag triage-tag--${item.triage_status || 'UNASSIGNED'}`}>
                      {item.triage_status || 'UNASSIGNED'}
                    </span>
                    <span className={`history-tier-pill ${getTierClass(item.overall_risk_tier)}`}>
                      {item.overall_risk_tier} (EPI {item.enterprise_posture_index?.toFixed(1)})
                    </span>
                  </div>
                </div>

                <div className="history-item-meta">
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                    {item.created_at ? new Date(item.created_at).toLocaleString() : 'Recent'}
                  </span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    {item.session_count} flows
                  </span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                    {item.total_violations} violations
                  </span>
                  {item.username && (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                      {item.username}
                    </span>
                  )}
                </div>

                {item.tags && item.tags.length > 0 && (
                  <div style={{ display: 'flex', gap: 4, margin: '6px 0', flexWrap: 'wrap' }}>
                    {item.tags.map((tg, idx) => (
                      <span key={idx} className="case-tag-pill">#{tg}</span>
                    ))}
                  </div>
                )}

                <div className="history-item-sha" title={item.sha256}>
                  SHA256: {item.sha256 ? `${item.sha256.slice(0, 16)}...` : 'N/A'}
                </div>

                <div className="history-item-actions">
                  <button
                    className="history-load-btn"
                    disabled={loadingId === item.id}
                    onClick={(e) => {
                      e.stopPropagation()
                      handleLoad(item.id)
                    }}
                  >
                    {loadingId === item.id ? 'Loading...' : 'Open Investigation →'}
                  </button>

                  {(currentUser?.role === 'admin' || currentUser?.id === item.user_id) && (
                    <button
                      className="history-delete-btn"
                      title="Delete this capture record"
                      onClick={(e) => handleDelete(e, item.id, item.filename)}
                    >
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
