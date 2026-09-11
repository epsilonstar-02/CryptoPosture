import { useState, useEffect, useCallback } from 'react'

export default function HistoryDrawer({ isOpen, onClose, onLoadRecord, currentUser, token, onToast }) {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [selectedTier, setSelectedTier] = useState('ALL')
  const [loadingId, setLoadingId] = useState(null)

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (selectedTier !== 'ALL') params.append('risk_tier', selectedTier)
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
  }, [selectedTier, search, token, onToast])

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
            <span className="history-drawer-icon">🗄️</span>
            <div>
              <h3>Investigation History</h3>
              <p>Persistent forensic record store</p>
            </div>
          </div>
          <button className="history-drawer-close" onClick={onClose} aria-label="Close">
            ✕
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
        </div>

        {/* List */}
        <div className="history-drawer-body">
          {loading ? (
            <div className="history-empty">Loading historical captures...</div>
          ) : items.length === 0 ? (
            <div className="history-empty">
              <span>📂</span>
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
                  <span className={`history-tier-pill ${getTierClass(item.overall_risk_tier)}`}>
                    {item.overall_risk_tier} (EPI {item.enterprise_posture_index?.toFixed(1)})
                  </span>
                </div>

                <div className="history-item-meta">
                  <span>📅 {item.created_at ? new Date(item.created_at).toLocaleString() : 'Recent'}</span>
                  <span>⚡ {item.session_count} flows</span>
                  <span>🛡️ {item.total_violations} violations</span>
                  {item.username && <span>👤 {item.username}</span>}
                </div>

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
                      🗑️
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
