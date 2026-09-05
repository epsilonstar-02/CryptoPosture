import { useState, useMemo } from 'react'
import ViolationBadge from './ViolationBadge.jsx'

const SEV_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

export default function FindingsExplorer({ sessions = [] }) {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [categoryFilter, setCategoryFilter] = useState('ALL')
  const [expandedCodes, setExpandedCodes] = useState(new Set())

  // Aggregate all unique violations across sessions
  const { findings, categories, severityCounts } = useMemo(() => {
    const map = new Map()
    const cats = new Set()
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }

    sessions.forEach((s) => {
      (s.violations || []).forEach((v) => {
        const code = v.code || 'RULE-GEN-001'
        const key = `${code}::${v.category || 'GENERAL'}`
        const sev = (v.severity || 'MEDIUM').toUpperCase()

        if (!map.has(key)) {
          map.set(key, {
            code,
            severity: sev,
            category: v.category || 'General',
            description: v.description || 'Cryptographic policy violation observed.',
            remediation: v.remediation,
            reference: v.reference,
            mandate_level: v.mandate_level,
            affectedSessions: [],
          })
          if (v.category) cats.add(v.category)
          if (counts[sev] !== undefined) counts[sev]++
        }

        const finding = map.get(key)
        finding.affectedSessions.push({
          session_id: s.session_id,
          flow_id: s.flow_id || s.session_id,
          flow: `${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}`,
          protocol: s.protocol,
          channel_type: s.channel_type,
          posture_score: s.posture_score,
          risk_tier: s.risk_tier,
          evidence: v.evidence,
        })
      })
    })

    const list = Array.from(map.values()).sort((a, b) => {
      const ordA = SEV_ORDER[a.severity] ?? 99
      const ordB = SEV_ORDER[b.severity] ?? 99
      if (ordA !== ordB) return ordA - ordB
      return b.affectedSessions.length - a.affectedSessions.length
    })

    return {
      findings: list,
      categories: Array.from(cats).sort(),
      severityCounts: counts,
    }
  }, [sessions])

  // Filter findings based on search, severity, and category
  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase()
    return findings.filter((f) => {
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false
      if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false
      if (!q) return true

      const inCode = f.code.toLowerCase().includes(q)
      const inDesc = f.description.toLowerCase().includes(q)
      const inRemed = (f.remediation || '').toLowerCase().includes(q)
      const inCat = (f.category || '').toLowerCase().includes(q)
      const inRef = (f.reference || '').toLowerCase().includes(q)
      const inFlow = f.affectedSessions.some((s) =>
        s.flow.toLowerCase().includes(q) || s.protocol.toLowerCase().includes(q)
      )

      return inCode || inDesc || inRemed || inCat || inRef || inFlow
    })
  }, [findings, search, severityFilter, categoryFilter])

  const toggleExpand = (code) => {
    setExpandedCodes((prev) => {
      const next = new Set(prev)
      if (next.has(code)) next.delete(code)
      else next.add(code)
      return next
    })
  }

  const toggleExpandAll = () => {
    if (expandedCodes.size === filteredFindings.length) {
      setExpandedCodes(new Set())
    } else {
      setExpandedCodes(new Set(filteredFindings.map((f) => f.code)))
    }
  }

  if (findings.length === 0) {
    return (
      <div className="findings-empty-card fade-in">
        <div style={{ fontSize: '2.5rem', marginBottom: 10 }}>🛡️</div>
        <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--risk-low)' }}>
          Zero Cryptographic Violations Detected
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', maxWidth: 480, margin: '8px auto 0' }}>
          All inspected email flows fully comply with NIST SP 800-52r2, RFC 9325, and RFC 8314 security baselines. No weak ciphers, deprecated protocols, or invalid certificates were identified.
        </p>
      </div>
    )
  }

  return (
    <div className="findings-explorer-wrap fade-in">
      {/* ── Toolbar: Search & Filters ── */}
      <div className="findings-toolbar">
        <div className="findings-search-box">
          <span className="findings-search-icon">🔍</span>
          <input
            type="text"
            className="findings-search-input"
            placeholder="Search by rule code, keyword, remediation, or flow IP/port..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button
              className="findings-search-clear"
              onClick={() => setSearch('')}
              title="Clear search"
            >
              ✕
            </button>
          )}
        </div>

        <div className="findings-filter-row">
          {/* Severity Chips */}
          <div className="findings-chips-group">
            <button
              className={`filter-chip${severityFilter === 'ALL' ? ' filter-chip--active' : ''}`}
              onClick={() => setSeverityFilter('ALL')}
            >
              ALL <span style={{ opacity: 0.6, fontSize: '0.55rem' }}>{findings.length}</span>
            </button>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
              const count = severityCounts[sev] || 0
              if (count === 0 && severityFilter !== sev) return null
              return (
                <button
                  key={sev}
                  className={`filter-chip filter-chip--${sev}${severityFilter === sev ? ' filter-chip--active' : ''}`}
                  onClick={() => setSeverityFilter(sev)}
                >
                  <span className={`risk-dot risk-dot--${sev}`} />
                  {sev}
                  <span style={{ opacity: 0.7, fontSize: '0.55rem' }}>{count}</span>
                </button>
              )
            })}
          </div>

          {/* Category Dropdown/Chips */}
          {categories.length > 1 && (
            <div className="findings-category-group">
              <span style={{ fontSize: '0.62rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
                Category:
              </span>
              <select
                className="findings-category-select"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <option value="ALL">All Categories ({categories.length})</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            className="btn-text-action"
            onClick={toggleExpandAll}
            title="Expand or collapse all affected flows"
          >
            {expandedCodes.size === filteredFindings.length ? 'Collapse All Flows' : 'Expand All Flows'}
          </button>
        </div>
      </div>

      {/* ── Summary Counter ── */}
      <div className="findings-meta-bar">
        <span>
          Showing <strong>{filteredFindings.length}</strong> unique policy finding{filteredFindings.length !== 1 ? 's' : ''}
          {severityFilter !== 'ALL' && ` (${severityFilter})`}
          {categoryFilter !== 'ALL' && ` in ${categoryFilter}`}
        </span>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>
          Impacts {filteredFindings.reduce((acc, f) => acc + f.affectedSessions.length, 0)} session instances
        </span>
      </div>

      {/* ── Findings List ── */}
      <div className="findings-list">
        {filteredFindings.map((f) => {
          const isExpanded = expandedCodes.has(f.code)
          const sev = f.severity
          const mandate = f.mandate_level

          return (
            <div
              key={f.code}
              className={`finding-card finding-card--${sev} fade-in`}
            >
              <div className="finding-card-header">
                <div className="finding-card-badges">
                  <ViolationBadge severity={sev} />
                  <span className="finding-code-pill">[{f.code}]</span>
                  {mandate && (
                    <span
                      className={`mandate-badge ${
                        mandate.includes('MUST') ? 'mandate-badge--must-not' : 'mandate-badge--should'
                      }`}
                    >
                      {mandate}
                    </span>
                  )}
                  <span className="finding-category-pill">{f.category}</span>
                </div>

                <button
                  type="button"
                  className="finding-expand-btn"
                  onClick={() => toggleExpand(f.code)}
                >
                  <span className={`toggle-chevron${isExpanded ? ' toggle-chevron--open' : ''}`}>▶</span>
                  <span className="finding-flow-count-badge">
                    {f.affectedSessions.length} flow{f.affectedSessions.length !== 1 ? 's' : ''} affected
                  </span>
                </button>
              </div>

              {/* Description */}
              <div className="finding-desc">{f.description}</div>

              {/* Remediation Box */}
              {f.remediation && (
                <div className="finding-remediation-box">
                  <div className="finding-remediation-header">
                    <span style={{ fontSize: '0.75rem' }}>💡</span>
                    <span>Actionable Remediation Guidance</span>
                  </div>
                  <div className="finding-remediation-content">{f.remediation}</div>
                </div>
              )}

              {/* Standard Reference Link */}
              {f.reference && (
                <div className="finding-reference-row">
                  <span className="finding-ref-label">Standard Reference:</span>
                  {f.reference.startsWith('http') ? (
                    <a
                      href={f.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="finding-ref-link"
                    >
                      {f.reference} ↗
                    </a>
                  ) : (
                    <span className="finding-ref-code">{f.reference}</span>
                  )}
                </div>
              )}

              {/* Affected Flows Section */}
              {isExpanded && (
                <div className="finding-affected-section fade-in">
                  <div className="finding-affected-title">
                    Affected Network Flow Details ({f.affectedSessions.length})
                  </div>
                  <div className="finding-affected-grid">
                    {f.affectedSessions.map((aff, i) => (
                      <div key={i} className="finding-flow-chip">
                        <div className="finding-flow-header">
                          <span className="finding-flow-proto">{aff.protocol}</span>
                          <span className="finding-flow-addr">{aff.flow}</span>
                          <span className={`risk-pill risk-pill--${aff.risk_tier}`} style={{ fontSize: '0.52rem', padding: '1px 5px' }}>
                            {aff.posture_score?.toFixed(0)}
                          </span>
                        </div>
                        {aff.evidence && (
                          <div className="finding-flow-evidence">
                            {aff.evidence.observed && (
                              <div>
                                <span style={{ color: 'var(--text-muted)' }}>Observed: </span>
                                <span style={{ color: 'var(--risk-critical)' }}>{String(aff.evidence.observed)}</span>
                              </div>
                            )}
                            {aff.evidence.expected && (
                              <div>
                                <span style={{ color: 'var(--text-muted)' }}>Expected: </span>
                                <span style={{ color: 'var(--risk-low)' }}>{String(aff.evidence.expected)}</span>
                              </div>
                            )}
                            {aff.evidence.details && (
                              <div style={{ color: 'var(--text-secondary)' }}>{String(aff.evidence.details)}</div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
