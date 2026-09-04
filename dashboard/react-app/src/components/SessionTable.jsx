import { useState, useMemo } from 'react'
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

const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function SessionTable({ sessions }) {
  const [expandedIdx, setExpandedIdx] = useState(null)
  const [sortKey,     setSortKey]     = useState('posture_score')
  const [sortDir,     setSortDir]     = useState('asc')
  const [filter,      setFilter]      = useState('ALL')

  if (!sessions || sessions.length === 0) {
    return (
      <div className="no-sessions fade-in">
        <div className="no-sessions-icon">📭</div>
        <div>No email sessions detected in this PCAP.</div>
        <div style={{ fontSize: '0.68rem', marginTop: 6, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Ensure the capture contains SMTP/IMAP/POP3 traffic on standard ports.
        </div>
      </div>
    )
  }

  const handleSort = (key) => {
    if (!key) return
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const indexed = sessions.map((s, i) => ({ ...s, idx: i }))

  const filtered = filter === 'ALL'
    ? indexed
    : indexed.filter(s => s.risk_tier === filter)

  const sorted = [...filtered].sort((a, b) => {
    let av, bv
    if (sortKey === 'violations')   { av = (a.violations||[]).length; bv = (b.violations||[]).length }
    else if (sortKey === 'is_anomalous') { av = a.ml_anomaly?.is_anomalous ? 1 : 0; bv = b.ml_anomaly?.is_anomalous ? 1 : 0 }
    else { av = a[sortKey] ?? ''; bv = b[sortKey] ?? '' }
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1 : -1
    return 0
  })

  const toggleExpand = (idx) => setExpandedIdx(prev => prev === idx ? null : idx)

  const tierCount = (tier) => indexed.filter(s => s.risk_tier === tier).length

  return (
    <>
      {/* Filter bar */}
      <div className="filter-bar fade-in">
        {FILTERS.map(f => (
          <button
            key={f}
            className={`filter-chip filter-chip--${f}${filter === f ? ' filter-chip--active' : ''}`}
            onClick={() => { setFilter(f); setExpandedIdx(null) }}
          >
            {f !== 'ALL' && <span className={`risk-dot risk-dot--${f}`} />}
            {f}
            {f !== 'ALL' && (
              <span style={{ opacity: 0.6, fontSize: '0.55rem' }}>{tierCount(f)}</span>
            )}
          </button>
        ))}
        <span className="filter-spacer" />
        <span className="filter-count">{sorted.length} / {sessions.length} shown</span>
      </div>

      <div className="session-table-wrap fade-in">
        <table className="session-table">
          <thead>
            <tr>
              {COLS.map(c => (
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
              const isOpen     = expandedIdx === s.idx
              const color      = RISK_COLORS[s.risk_tier] || '#aaa'
              const ml         = s.ml_anomaly || {}
              const violations = s.violations || []

              return (
                <>
                  <tr
                    key={`row-${s.idx}`}
                    className={isOpen ? 'expanded' : ''}
                    onClick={() => toggleExpand(s.idx)}
                    title="Click to expand session details"
                  >
                    {/* Protocol */}
                    <td>
                      <span style={{
                        background: 'rgba(61,216,232,0.08)',
                        border: '1px solid rgba(61,216,232,0.22)',
                        borderRadius: 4,
                        padding: '2px 7px',
                        fontSize: '0.64rem',
                        fontWeight: 700,
                        color: 'var(--accent-blue)',
                      }}>
                        {s.protocol}
                      </span>
                    </td>

                    {/* Flow */}
                    <td className="td-flow" title={`${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}`}>
                      {s.src_ip}:{s.src_port}&nbsp;→&nbsp;{s.dst_ip}:{s.dst_port}
                    </td>

                    {/* Channel */}
                    <td style={{
                      color: s.channel_type === 'Plaintext'    ? 'var(--risk-critical)'
                           : s.channel_type === 'STARTTLS'     ? 'var(--risk-medium)'
                           : 'var(--risk-low)',
                      fontWeight: 600,
                    }}>
                      {s.channel_type}
                    </td>

                    {/* TLS */}
                    <td style={{
                      color: !s.tls_version    ? 'var(--text-muted)'
                           : s.tls_version === 'TLS1.3' ? 'var(--risk-low)'
                           : s.tls_version === 'TLS1.2' ? 'var(--accent-blue)'
                           : 'var(--risk-critical)',
                    }}>
                      {s.tls_version || '—'}
                    </td>

                    {/* Cipher (truncated) */}
                    <td
                      style={{ color: 'var(--text-secondary)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis' }}
                      title={s.cipher_suite || ''}
                    >
                      {s.cipher_suite ? s.cipher_suite.slice(0, 24) + (s.cipher_suite.length > 24 ? '…' : '') : '—'}
                    </td>

                    {/* Score */}
                    <td className="td-score" style={{ color: scoreColor(s.posture_score) }}>
                      {(s.posture_score || 0).toFixed(1)}
                    </td>

                    {/* Risk pill — with ML anomaly indicator */}
                    <td>
                      <span className={`risk-pill risk-pill--${s.risk_tier}`}>
                        <span className={`risk-dot risk-dot--${s.risk_tier}`} />
                        {s.risk_tier}
                        {ml.is_anomalous && <span title="ML anomaly detected" style={{ marginLeft: 2 }}>⚡</span>}
                      </span>
                    </td>

                    {/* Violations */}
                    <td style={{
                      color: violations.length > 0 ? color : 'var(--text-muted)',
                      fontWeight: violations.length > 0 ? 700 : 400,
                    }}>
                      {violations.length > 0 ? `${violations.length} issue${violations.length > 1 ? 's' : ''}` : '—'}
                    </td>

                    {/* Expand chevron */}
                    <td className="td-chevron">▶</td>
                  </tr>

                  {isOpen && (
                    <tr key={`detail-${s.idx}`} className="session-detail-row">
                      <td colSpan={COLS.length}>
                        <SessionDetail session={s} />
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>
    </>
  )
}
