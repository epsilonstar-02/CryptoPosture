import { useState, useMemo, Fragment } from 'react'
import SessionDetail from './SessionDetail.jsx'

const RISK_COLORS = {
  CRITICAL: 'var(--risk-critical)',
  HIGH:     'var(--risk-high)',
  MEDIUM:   'var(--risk-medium)',
  LOW:      'var(--risk-low)',
}

function scoreColor(v) {
  if (v >= 80) return 'var(--risk-low)'
  if (v >= 55) return 'var(--risk-medium)'
  if (v >= 30) return 'var(--risk-high)'
  return 'var(--risk-critical)'
}

const COLS = [
  { key: 'protocol',   label: 'Proto',    sortKey: 'protocol' },
  { key: 'flow',       label: 'Flow',     sortKey: null },
  { key: 'channel',    label: 'Channel',  sortKey: 'channel_type' },
  { key: 'tls',        label: 'TLS',      sortKey: 'tls_version' },
  { key: 'cipher',     label: 'Cipher',   sortKey: null },
  { key: 'score',      label: 'Score',    sortKey: 'posture_score' },
  { key: 'risk',       label: 'Risk',     sortKey: 'risk_tier' },
  { key: 'violations', label: 'Findings', sortKey: 'violations' },
  { key: 'chevron',    label: '',         sortKey: null },
]

const TIERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function SessionTable({ sessions = [] }) {
  const [expandedIdx, setExpandedIdx] = useState(null)
  const [sortKey, setSortKey] = useState('posture_score')
  const [sortDir, setSortDir] = useState('asc')
  const [tierFilter, setTierFilter] = useState('ALL')
  const [search, setSearch] = useState('')
  const [onlyOutliers, setOnlyOutliers] = useState(false)
  const [onlyPQC, setOnlyPQC] = useState(false)
  const [onlyWarnings, setOnlyWarnings] = useState(false)


  const handleSort = (key) => {
    if (!key) return
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const indexed = useMemo(() => {
    return sessions.map((s, i) => ({ ...s, idx: i }))
  }, [sessions])

  // Counts for filters
  const tierCounts = useMemo(() => {
    const counts = { ALL: indexed.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    indexed.forEach((s) => {
      if (counts[s.risk_tier] !== undefined) counts[s.risk_tier]++
    })
    return counts
  }, [indexed])

  const outlierCount = useMemo(() => indexed.filter((s) => s.ml_anomaly?.is_anomalous).length, [indexed])
  const pqcCount = useMemo(() => indexed.filter((s) => s.pqc_state === 1 || s.pqc_state === 2).length, [indexed])
  const warningCount = useMemo(
    () => indexed.filter((s) => (s.validation_warnings && s.validation_warnings.length > 0) || s.validation_status === 'WARNING').length,
    [indexed]
  )

  // Filter sessions
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()

    return indexed.filter((s) => {
      // Risk Tier Filter
      if (tierFilter !== 'ALL' && s.risk_tier !== tierFilter) return false

      // Feature toggles
      if (onlyOutliers && !s.ml_anomaly?.is_anomalous) return false
      if (onlyPQC && s.pqc_state !== 1 && s.pqc_state !== 2) return false
      if (onlyWarnings && (!s.validation_warnings || s.validation_warnings.length === 0) && s.validation_status !== 'WARNING') {
        return false
      }

      // Search Query
      if (!q) return true
      const flowStr = `${s.src_ip}:${s.src_port} ${s.dst_ip}:${s.dst_port}`.toLowerCase()
      const proto = (s.protocol || '').toLowerCase()
      const cipher = (s.cipher_suite || '').toLowerCase()
      const tls = (s.tls_version || '').toLowerCase()
      const sni = (s.sni || '').toLowerCase()
      const subject = (s.cert?.subject_cn || '').toLowerCase()
      const issuer = (s.cert?.issuer_cn || '').toLowerCase()
      const ja4 = (s.fingerprints?.ja4 || '').toLowerCase()
      const violationsMatch = (s.violations || []).some(
        (v) =>
          (v.code || '').toLowerCase().includes(q) ||
          (v.description || '').toLowerCase().includes(q)
      )

      return (
        flowStr.includes(q) ||
        proto.includes(q) ||
        cipher.includes(q) ||
        tls.includes(q) ||
        sni.includes(q) ||
        subject.includes(q) ||
        issuer.includes(q) ||
        ja4.includes(q) ||
        violationsMatch
      )
    })
  }, [indexed, tierFilter, onlyOutliers, onlyPQC, onlyWarnings, search])

  // Sort sessions
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let av, bv
      if (sortKey === 'violations') {
        av = (a.violations || []).length
        bv = (b.violations || []).length
      } else if (sortKey === 'is_anomalous') {
        av = a.ml_anomaly?.is_anomalous ? 1 : 0
        bv = b.ml_anomaly?.is_anomalous ? 1 : 0
      } else {
        av = a[sortKey] ?? ''
        bv = b[sortKey] ?? ''
      }
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [filtered, sortKey, sortDir])

  const toggleExpand = (idx) => setExpandedIdx((prev) => (prev === idx ? null : idx))

  const resetFilters = () => {
    setTierFilter('ALL')
    setSearch('')
    setOnlyOutliers(false)
    setOnlyPQC(false)
    setOnlyWarnings(false)
    setExpandedIdx(null)
  }

  const hasActiveFilters = tierFilter !== 'ALL' || search || onlyOutliers || onlyPQC || onlyWarnings
  
  if (!sessions || sessions.length === 0) {
    return (
      <div className="no-sessions fade-in">
        <div className="no-sessions-icon">📭</div>
        <div>No email sessions detected in this PCAP.</div>
        <div style={{ fontSize: '0.68rem', marginTop: 6, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Ensure the capture contains SMTP/IMAP/POP3 traffic on standard ports (25, 465, 587, 110, 995, 143, 993).
        </div>
      </div>
    )
  }

  return (
    <div className="session-table-container fade-in">
      {/* ── Filter Bar with Search & Toggles ── */}
      <div className="session-controls-card">
        {/* Row 1: Search & Counts */}
        <div className="session-search-row">
          <div className="findings-search-box" style={{ flex: 1 }}>
            <span className="findings-search-icon">🔍</span>
            <input
              type="text"
              className="findings-search-input"
              placeholder="Search flows by IP, port, protocol, cipher suite, SNI, certificate, or rule code..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setExpandedIdx(null)
              }}
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

          <div className="session-count-indicator">
            <strong>{sorted.length}</strong> of {sessions.length} sessions
          </div>
        </div>

        {/* Row 2: Filter Chips & Toggles */}
        <div className="session-chips-row">
          <div className="tier-chips-group">
            {TIERS.map((tier) => {
              const count = tierCounts[tier] || 0
              return (
                <button
                  key={tier}
                  className={`filter-chip filter-chip--${tier}${tierFilter === tier ? ' filter-chip--active' : ''}`}
                  onClick={() => {
                    setTierFilter(tier)
                    setExpandedIdx(null)
                  }}
                >
                  {tier !== 'ALL' && <span className={`risk-dot risk-dot--${tier}`} />}
                  {tier}
                  <span style={{ opacity: 0.65, fontSize: '0.55rem' }}>{count}</span>
                </button>
              )
            })}
          </div>

          <div className="filter-divider" />

          {/* Quick Toggles */}
          <div className="special-toggles-group">
            {outlierCount > 0 && (
              <button
                type="button"
                className={`toggle-chip${onlyOutliers ? ' toggle-chip--active-outlier' : ''}`}
                onClick={() => {
                  setOnlyOutliers((v) => !v)
                  setExpandedIdx(null)
                }}
                title="Show only sessions flagged as ML Isolation Forest outliers"
              >
                <span>⚡ Outliers</span>
                <span className="toggle-chip-count">{outlierCount}</span>
              </button>
            )}

            {pqcCount > 0 && (
              <button
                type="button"
                className={`toggle-chip${onlyPQC ? ' toggle-chip--active-pqc' : ''}`}
                onClick={() => {
                  setOnlyPQC((v) => !v)
                  setExpandedIdx(null)
                }}
                title="Show only sessions with Post-Quantum Cryptography (PQC) offered or negotiated"
              >
                <span>🛡 PQC Ready</span>
                <span className="toggle-chip-count">{pqcCount}</span>
              </button>
            )}

            {warningCount > 0 && (
              <button
                type="button"
                className={`toggle-chip${onlyWarnings ? ' toggle-chip--active-warning' : ''}`}
                onClick={() => {
                  setOnlyWarnings((v) => !v)
                  setExpandedIdx(null)
                }}
                title="Show sessions with cross-stage protocol semantic warnings"
              >
                <span>⚠ Discrepancies</span>
                <span className="toggle-chip-count">{warningCount}</span>
              </button>
            )}

            {hasActiveFilters && (
              <button
                type="button"
                className="btn-text-action"
                style={{ marginLeft: 6 }}
                onClick={resetFilters}
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Empty State when Filters Match Nothing ── */}
      {sorted.length === 0 ? (
        <div className="no-sessions fade-in" style={{ margin: '14px 0' }}>
          <div className="no-sessions-icon">🔍</div>
          <div>No sessions matched the active search and filter criteria.</div>
          <button
            type="button"
            className="btn-primary"
            style={{ marginTop: 12, padding: '6px 14px', fontSize: '0.72rem' }}
            onClick={resetFilters}
          >
            Clear All Filters
          </button>
        </div>
      ) : (
        /* ── Session Table ── */
        <div className="session-table-wrap fade-in">
          <table className="session-table">
            <thead>
              <tr>
                {COLS.map((c) => (
                  <th
                    key={c.key}
                    className={sortKey === c.sortKey ? 'sorted' : ''}
                    onClick={() => handleSort(c.sortKey)}
                    title={c.sortKey ? `Sort by ${c.label}` : undefined}
                  >
                    {c.label}
                    {sortKey === c.sortKey && (
                      <span style={{ marginLeft: 3, fontSize: '0.5rem' }}>
                        {sortDir === 'asc' ? '▲' : '▼'}
                      </span>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map((s) => {
                const isOpen = expandedIdx === s.idx
                const color = RISK_COLORS[s.risk_tier] || '#aaa'
                const ml = s.ml_anomaly || {}
                const violations = s.violations || []

                return (
                  <Fragment key={`group-${s.idx}`}>
                    <tr
                      className={`session-row-wrapper ${isOpen ? 'expanded' : ''}`}
                      onClick={() => toggleExpand(s.idx)}
                      title="Click row to inspect session telemetry, audit, and violations"
                    >
                    {/* Protocol */}
                    <td>
                      <span
                        style={{
                          background: 'rgba(61,216,232,0.08)',
                          border: '1px solid rgba(61,216,232,0.22)',
                          borderRadius: 4,
                          padding: '2px 7px',
                          fontSize: '0.64rem',
                          fontWeight: 700,
                          color: 'var(--accent-blue)',
                        }}
                      >
                        {s.protocol}
                      </span>
                    </td>

                    {/* Flow */}
                    <td className="td-flow" title={`${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}`}>
                      {s.validation_warnings && s.validation_warnings.length > 0 && (
                        <span
                          title={`Validation warning: ${s.validation_warnings[0]}`}
                          style={{ color: 'var(--risk-medium)', marginRight: 4, fontSize: '0.8rem' }}
                        >
                          ⚠
                        </span>
                      )}
                      {s.src_ip}:{s.src_port}&nbsp;→&nbsp;{s.dst_ip}:{s.dst_port}
                    </td>

                    {/* Channel */}
                    <td
                      style={{
                        color:
                          s.channel_type === 'Plaintext'
                            ? 'var(--risk-critical)'
                            : s.channel_type === 'STARTTLS'
                            ? 'var(--risk-medium)'
                            : 'var(--risk-low)',
                        fontWeight: 600,
                      }}
                    >
                      {s.channel_type}
                    </td>

                    {/* TLS */}
                    <td
                      style={{
                        color: !s.tls_version
                          ? 'var(--text-muted)'
                          : s.tls_version === 'TLS1.3'
                          ? 'var(--risk-low)'
                          : s.tls_version === 'TLS1.2'
                          ? 'var(--accent-blue)'
                          : 'var(--risk-critical)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span>{s.tls_version || '—'}</span>
                        {s.pqc_state === 2 && (
                          <span
                            style={{
                              fontSize: '0.52rem',
                              padding: '1px 4px',
                              borderRadius: 3,
                              background: 'rgba(80,233,177,0.15)',
                              color: 'var(--accent-green)',
                              fontWeight: 700,
                            }}
                            title="Hybrid Post-Quantum Cryptography Negotiated (Kyber / ML-KEM)"
                          >
                            PQC
                          </span>
                        )}
                        {s.pqc_state === 1 && (
                          <span
                            style={{
                              fontSize: '0.52rem',
                              padding: '1px 4px',
                              borderRadius: 3,
                              background: 'rgba(61,216,232,0.12)',
                              color: 'var(--accent-blue)',
                              fontWeight: 700,
                            }}
                            title="Post-Quantum Key Share Offered in ClientHello"
                          >
                            PQC?
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Cipher */}
                    <td
                      style={{
                        color: 'var(--text-secondary)',
                        maxWidth: 160,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                      title={s.cipher_suite || ''}
                    >
                      {s.cipher_suite ? s.cipher_suite.slice(0, 24) + (s.cipher_suite.length > 24 ? '…' : '') : '—'}
                    </td>

                    {/* Score */}
                    <td className="td-score" style={{ color: scoreColor(s.posture_score) }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span>{(s.posture_score || 0).toFixed(1)}</span>
                        {s.scoring_explanation?.critical_caps_applied?.length > 0 && (
                          <span
                            title={`Score capped at ${s.scoring_explanation.critical_caps_applied[0].cap_value}: ${s.scoring_explanation.critical_caps_applied[0].finding}`}
                            style={{ fontSize: '0.65rem', color: 'var(--risk-critical)', cursor: 'help' }}
                          >
                            🛑
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Risk Pill with ML Outlier and Confidence */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className={`risk-pill risk-pill--${s.risk_tier}`}>
                          <span className={`risk-dot risk-dot--${s.risk_tier}`} />
                          {s.risk_tier}
                          {ml.is_anomalous && (
                            <span title="Liu Anomaly Outlier Detected (s >= 0.65)" style={{ marginLeft: 2 }}>
                              ⚡
                            </span>
                          )}
                        </span>
                        {s.confidence && (
                          <span
                            style={{
                              fontSize: '0.56rem',
                              fontFamily: 'var(--font-mono)',
                              color:
                                s.confidence === 'HIGH'
                                  ? 'var(--risk-low)'
                                  : s.confidence === 'MEDIUM'
                                  ? 'var(--risk-medium)'
                                  : 'var(--risk-critical)',
                              opacity: 0.85,
                            }}
                            title={`Assessment Confidence: ${s.confidence}`}
                          >
                            {s.confidence[0]}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Violations */}
                    <td
                      style={{
                        color: violations.length > 0 ? color : 'var(--text-muted)',
                        fontWeight: violations.length > 0 ? 700 : 400,
                      }}
                    >
                      {violations.length > 0 ? `${violations.length} issue${violations.length > 1 ? 's' : ''}` : '—'}
                    </td>

                    {/* Expand Chevron */}
                    <td className="td-chevron">{isOpen ? '▼' : '▶'}</td>
                  </tr>

                  {isOpen && (
                    <tr key={`detail-${s.idx}`} className="session-detail-row">
                      <td colSpan={COLS.length}>
                        <SessionDetail session={s} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    )}
  </div>
)
}
