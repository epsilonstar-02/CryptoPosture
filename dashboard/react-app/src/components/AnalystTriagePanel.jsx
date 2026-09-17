import { useState, useEffect } from 'react'

const TRIAGE_VERDICTS = [
  { id: 'UNASSIGNED', label: 'Unassigned', desc: 'No formal triage performed yet', color: 'neutral' },
  { id: 'UNDER_REVIEW', label: 'Under Review', desc: 'Active triage by forensic investigator', color: 'warning' },
  { id: 'FLAGGED_MALICIOUS', label: 'Flagged Malicious', desc: 'Active downgrade attack or critical flaw detected', color: 'critical' },
  { id: 'COMPLIANT', label: 'Compliant & Validated', desc: 'Conforms to RFC 8314/9325 standards', color: 'success' },
  { id: 'FALSE_POSITIVE', label: 'False Positive', desc: 'Benign anomaly / authorized legacy system', color: 'info' },
  { id: 'RESOLVED', label: 'Resolved / Remediated', desc: 'Remediation completed and verified', color: 'teal' },
]

export default function AnalystTriagePanel({ result, currentUser, token, onToast, onTriageUpdated }) {
  const analysisId = result?.meta?.analysis_id
  const triageMeta = result?.triage || {}

  const [verdict, setVerdict] = useState(triageMeta.status || 'UNASSIGNED')
  const [notes, setNotes] = useState(triageMeta.analyst_notes || '')
  const [tags, setTags] = useState(triageMeta.tags || [])
  const [tagInput, setTagInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [lastSavedAt, setLastSavedAt] = useState(null)

  useEffect(() => {
    if (result?.triage) {
      setVerdict(result.triage.status || 'UNASSIGNED')
      setNotes(result.triage.analyst_notes || '')
      setTags(result.triage.tags || [])
    }
  }, [result])

  const handleAddTag = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const clean = tagInput.trim().replace(/^#/, '')
      if (clean && !tags.includes(clean)) {
        setTags([...tags, clean])
      }
      setTagInput('')
    }
  }

  const handleRemoveTag = (tagToRemove) => {
    setTags(tags.filter((t) => t !== tagToRemove))
  }

  const handleSaveTriage = async () => {
    if (!analysisId) {
      onToast('No persistent analysis record ID found to attach triage.', 'error')
      return
    }
    if (!token) {
      onToast('Please sign in to save investigation triage and notes.', 'error')
      return
    }

    setSaving(true)
    try {
      const res = await fetch(`/api/history/${analysisId}/triage`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          triage_status: verdict,
          analyst_notes: notes,
          tags: tags,
          assigned_analyst: currentUser?.username || undefined,
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error(errData?.detail?.message || `HTTP ${res.status}`)
      }

      const updatedRecord = await res.json()
      setLastSavedAt(new Date())
      onToast(`Investigation signed off as '${verdict}'`, 'success')

      if (onTriageUpdated) {
        onTriageUpdated({
          status: updatedRecord.triage_status,
          analyst_notes: updatedRecord.analyst_notes,
          tags: updatedRecord.tags,
          assigned_analyst: updatedRecord.assigned_analyst,
        })
      }
    } catch (err) {
      onToast(`Failed to save triage: ${err.message}`, 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="panel audit-panel fade-in">
      {/* Header */}
      <div className="audit-panel-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
            Analyst Case Triage &amp; Digital Sign-Off Workbench
          </span>
          <span className={`triage-tag triage-tag--${verdict}`}>
            {verdict}
          </span>
          {currentUser && (
            <span className="analyst-active-badge">
              Active Investigator: <strong>@{currentUser.username}</strong> ({currentUser.role})
            </span>
          )}
        </div>
      </div>

      {!currentUser && (
        <div className="triage-auth-warning">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>You are viewing in anonymous mode. <strong>Sign in</strong> with an Analyst or Admin account to save notes, tag incident cases, and register official investigation verdicts.</span>
        </div>
      )}

      {/* Triage Verdict Selection Grid */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>
          1. Official Forensic Triage Verdict
        </div>
        <div className="triage-verdict-grid">
          {TRIAGE_VERDICTS.map((v) => {
            const isSelected = verdict === v.id
            return (
              <button
                key={v.id}
                type="button"
                className={`triage-verdict-card triage-verdict-card--${v.color} ${isSelected ? 'triage-verdict-card--selected' : ''}`}
                onClick={() => setVerdict(v.id)}
              >
                <div className="triage-verdict-top">
                  <span className="triage-verdict-radio">{isSelected ? '◉' : '○'}</span>
                  <span className="triage-verdict-name">{v.label}</span>
                </div>
                <div className="triage-verdict-desc">{v.desc}</div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Forensic Notes Editor */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            2. Investigator Observations &amp; Root-Cause Hypotheses
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Stored persistently in the cryptographic chain-of-custody database
          </span>
        </div>
        <textarea
          className="triage-notes-textarea"
          rows={6}
          placeholder="Record detailed analyst observations, threat actor hypotheses, affected email server hostnames, MITM indicators, or required firewall/mail server configuration changes..."
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
      </div>

      {/* Case Tags */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
          3. Incident &amp; Classification Tags
        </div>
        <div className="triage-tags-box">
          <div className="triage-tags-list">
            {tags.map((t) => (
              <span key={t} className="triage-tag-pill">
                #{t}
                <button type="button" onClick={() => handleRemoveTag(t)}>✕</button>
              </span>
            ))}
          </div>
          <input
            type="text"
            className="triage-tag-input"
            placeholder="Type tag and press Enter (e.g. STARTTLS-Strip, Incident-2026, Legacy-Exchange)..."
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={handleAddTag}
          />
        </div>
      </div>

      {/* Action Footer */}
      <div className="triage-footer-bar">
        <div>
          {lastSavedAt && (
            <span style={{ fontSize: '0.75rem', color: 'var(--risk-low)' }}>
              ✓ Saved &amp; signed off at {lastSavedAt.toLocaleTimeString()}
            </span>
          )}
        </div>
        <button
          type="button"
          className="btn-triage-signoff"
          disabled={saving || !currentUser}
          onClick={handleSaveTriage}
        >
          {saving ? 'Registering Verdict...' : '✍️ Sign Off Investigation & Save Verdict'}
        </button>
      </div>
    </div>
  )
}
