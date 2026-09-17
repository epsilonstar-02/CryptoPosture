import { useState, useEffect, useCallback } from 'react'

export default function AnalystWorkspaceModal({ isOpen, onClose, currentUser, token, onLoadRecord, onToast }) {
  const [workData, setWorkData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [filterStatus, setFilterStatus] = useState('ALL')
  const [loadingRecordId, setLoadingRecordId] = useState(null)

  const fetchWorkload = useCallback(async () => {
    if (!token) return
    setLoading(true)
    try {
      const res = await fetch('/api/analyst/my-work', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setWorkData(data)
    } catch (err) {
      onToast(`Failed to load analyst workload: ${err.message}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [token, onToast])

  useEffect(() => {
    if (isOpen) fetchWorkload()
  }, [isOpen, fetchWorkload])

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const handleOpenCase = async (recordId) => {
    setLoadingRecordId(recordId)
    try {
      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const res = await fetch(`/api/history/${recordId}`, { headers })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const fullData = await res.json()
      onLoadRecord(fullData)
      onToast(`Loaded investigation: ${fullData?.evidence?.filename || recordId}`, 'success')
      onClose()
    } catch (err) {
      onToast(`Failed to load record: ${err.message}`, 'error')
    } finally {
      setLoadingRecordId(null)
    }
  }

  if (!isOpen) return null

  const metrics = workData?.metrics || { total_assigned: 0, open_triage: 0, escalated: 0, resolved: 0 }
  const cases = workData?.recent_cases || []

  const filteredCases = cases.filter((c) => {
    if (filterStatus === 'ALL') return true
    if (filterStatus === 'PENDING') return c.triage_status === 'UNASSIGNED' || c.triage_status === 'UNDER_REVIEW'
    if (filterStatus === 'ESCALATED') return c.triage_status === 'FLAGGED_MALICIOUS'
    if (filterStatus === 'RESOLVED') return c.triage_status === 'RESOLVED' || c.triage_status === 'COMPLIANT'
    return true
  })

  return (
    <div className="admin-modal-overlay" onClick={onClose}>
      <div className="admin-modal-box analyst-workspace-box" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="admin-modal-header">
          <div className="admin-modal-title">
            <div className="analyst-badge-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
            </div>
            <div>
              <h3>Analyst Operations Hub</h3>
              <p>Forensic Case Management, Investigation Triage &amp; Assignment for <strong>{currentUser?.username}</strong></p>
            </div>
          </div>
          <button className="admin-modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        {/* Workload Metrics */}
        <div className="admin-modal-body">
          <div className="analyst-kpi-grid">
            <div className="analyst-kpi-card">
              <div className="analyst-kpi-num">{metrics.total_assigned}</div>
              <div className="analyst-kpi-lbl">Total Investigations</div>
            </div>
            <div className="analyst-kpi-card analyst-kpi-card--pending">
              <div className="analyst-kpi-num">{metrics.open_triage}</div>
              <div className="analyst-kpi-lbl">Pending Triage</div>
            </div>
            <div className="analyst-kpi-card analyst-kpi-card--escalated">
              <div className="analyst-kpi-num">{metrics.escalated}</div>
              <div className="analyst-kpi-lbl">Escalated Threats</div>
            </div>
            <div className="analyst-kpi-card analyst-kpi-card--resolved">
              <div className="analyst-kpi-num">{metrics.resolved}</div>
              <div className="analyst-kpi-lbl">Closed / Resolved</div>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="analyst-filter-bar">
            <div style={{ display: 'flex', gap: 6 }}>
              {['ALL', 'PENDING', 'ESCALATED', 'RESOLVED'].map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`analyst-filter-btn ${filterStatus === s ? 'analyst-filter-btn--active' : ''}`}
                  onClick={() => setFilterStatus(s)}
                >
                  {s}
                </button>
              ))}
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Showing {filteredCases.length} assigned capture{filteredCases.length === 1 ? '' : 's'}
            </span>
          </div>

          {/* Cases Table */}
          {loading ? (
            <div className="admin-loading-state">Loading your assigned cases...</div>
          ) : filteredCases.length === 0 ? (
            <div className="admin-empty-state">
              <span>🔍</span>
              <p>No investigations match this triage category.</p>
              <small>Upload a new capture or run a forensic analysis to start triaging.</small>
            </div>
          ) : (
            <div className="admin-table-wrap">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Capture Evidence</th>
                    <th>Analyzed At</th>
                    <th>EPI Posture</th>
                    <th>Risk Tier</th>
                    <th>Triage Verdict</th>
                    <th>Tags</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCases.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }} title={c.filename}>
                          {c.filename}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {c.sha256 ? `${c.sha256.slice(0, 16)}...` : c.id}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {c.created_at ? new Date(c.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td style={{
                        fontWeight: 700,
                        color: c.enterprise_posture_index >= 80 ? 'var(--risk-low)' : c.enterprise_posture_index >= 55 ? 'var(--risk-medium)' : c.enterprise_posture_index >= 30 ? 'var(--risk-high)' : 'var(--risk-critical)',
                      }}>
                        {c.enterprise_posture_index?.toFixed(1)}
                      </td>
                      <td>
                        <span className={`risk-pill risk-pill--${c.overall_risk_tier}`} style={{ fontSize: '0.65rem' }}>
                          {c.overall_risk_tier}
                        </span>
                      </td>
                      <td>
                        <span className={`triage-tag triage-tag--${c.triage_status}`}>
                          {c.triage_status || 'UNASSIGNED'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(c.tags || []).slice(0, 3).map((tg, i) => (
                            <span key={i} className="case-tag-pill">#{tg}</span>
                          ))}
                          {(c.tags || []).length > 3 && (
                            <span className="case-tag-pill">+{c.tags.length - 3}</span>
                          )}
                        </div>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn-admin-primary"
                          style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          disabled={loadingRecordId === c.id}
                          onClick={() => handleOpenCase(c.id)}
                        >
                          {loadingRecordId === c.id ? 'Loading...' : 'Open Case →'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
