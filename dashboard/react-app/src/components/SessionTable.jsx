import { useState } from 'react'
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
  { key: '#',          label: '#',           sortKey: 'idx' },
  { key: 'protocol',   label: 'Proto',       sortKey: 'protocol' },
  { key: 'flow',       label: 'Flow',        sortKey: null },
  { key: 'channel',    label: 'Channel',     sortKey: 'channel_type' },
  { key: 'tls',        label: 'TLS',         sortKey: 'tls_version' },
  { key: 'cipher',     label: 'Cipher',      sortKey: null },
  { key: 'score',      label: 'Score',       sortKey: 'posture_score' },
  { key: 'risk',       label: 'Risk',        sortKey: 'risk_tier' },
  { key: 'violations', label: 'Violations',  sortKey: 'violations' },
  { key: 'ml',         label: 'ML Anomaly',  sortKey: 'is_anomalous' },
]

export default function SessionTable({ sessions }) {
  const [expandedIdx, setExpandedIdx] = useState(null)
  const [sortKey, setSortKey]         = useState('posture_score')
  const [sortDir, setSortDir]         = useState('asc')

  if (!sessions || sessions.length === 0) {
    return (
      <div className="no-sessions">
        <div style={{ fontSize: '2rem', marginBottom: 12 }}>📭</div>
        <div>No email sessions detected in this PCAP.</div>
        <div style={{ fontSize: '0.7rem', marginTop: 6, color: 'var(--text-muted)' }}>
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

  const sorted = [...sessions]
    .map((s, i) => ({ ...s, idx: i }))
    .sort((a, b) => {
      let av, bv
      if (sortKey === 'idx')           { av = a.idx;             bv = b.idx }
      else if (sortKey === 'violations') { av = (a.violations||[]).length; bv = (b.violations||[]).length }
      else if (sortKey === 'is_anomalous') { av = a.ml_anomaly?.is_anomalous ? 1 : 0; bv = b.ml_anomaly?.is_anomalous ? 1 : 0 }
      else { av = a[sortKey] ?? ''; bv = b[sortKey] ?? '' }
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })

  const toggleExpand = (idx) => setExpandedIdx(prev => prev === idx ? null : idx)

  return (
    <div className="session-table-wrap fade-in">
      <table className="session-table">
        <thead>
          <tr>
            {COLS.map(c => (
              <th
                key={c.key}
                className={sortKey === c.sortKey ? 'sorted' : ''}
                onClick={() => handleSort(c.sortKey)}
              >
                {c.label}
                {sortKey === c.sortKey && (
                  <span style={{ marginLeft: 4 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((s) => {
            const isOpen = expandedIdx === s.idx
            const color  = RISK_COLORS[s.risk_tier] || '#aaa'
            const ml     = s.ml_anomaly || {}
            const violations = s.violations || []

            return (
              <>
                <tr
                  key={`row-${s.idx}`}
                  className={isOpen ? 'expanded' : ''}
                  onClick={() => toggleExpand(s.idx)}
                >
                  <td style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{s.idx + 1}</td>
                  <td>
                    <span style={{
                      background: 'rgba(59,130,246,0.1)',
                      border: '1px solid rgba(59,130,246,0.25)',
                      borderRadius: 4,
                      padding: '2px 7px',
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      color: 'var(--accent-blue)',
                    }}>
                      {s.protocol}
                    </span>
                  </td>
                  <td className="td-flow">
                    {s.src_ip}:{s.src_port}&nbsp;→&nbsp;{s.dst_ip}:{s.dst_port}
                  </td>
                  <td style={{ color: s.channel_type === 'Plaintext' ? 'var(--risk-critical)' : s.channel_type === 'STARTTLS' ? 'var(--risk-medium)' : 'var(--risk-low)', fontWeight: 600 }}>
                    {s.channel_type}
                  </td>
                  <td style={{ color: !s.tls_version ? 'var(--text-muted)' : s.tls_version === 'TLS1.3' ? 'var(--risk-low)' : s.tls_version === 'TLS1.2' ? 'var(--accent-blue)' : 'var(--risk-critical)' }}>
                    {s.tls_version || '—'}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {s.cipher_suite ? s.cipher_suite.slice(0, 28) + (s.cipher_suite.length > 28 ? '…' : '') : '—'}
                  </td>
                  <td className="td-score" style={{ color: scoreColor(s.posture_score) }}>
                    {(s.posture_score || 0).toFixed(1)}
                  </td>
                  <td>
                    <span className={`risk-pill risk-pill--${s.risk_tier}`}>{s.risk_tier}</span>
                  </td>
                  <td style={{ color: violations.length > 0 ? color : 'var(--text-muted)', fontWeight: violations.length > 0 ? 700 : 400 }}>
                    {violations.length > 0 ? `⚠ ${violations.length}` : '—'}
                  </td>
                  <td style={{ color: ml.is_anomalous ? 'var(--risk-critical)' : 'var(--text-muted)', fontWeight: ml.is_anomalous ? 700 : 400 }}>
                    {ml.is_anomalous ? '⚡ YES' : '—'}
                  </td>
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
  )
}
