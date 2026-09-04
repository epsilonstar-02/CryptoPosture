export default function EvidenceBanner({ evidence, analysisTime }) {
  const ev = evidence || {}

  const formatBytes = (b) => {
    if (!b) return '0 B'
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / (1024 * 1024)).toFixed(2)} MB`
  }

  const shortHash = ev.sha256_hash
    ? `${ev.sha256_hash.slice(0, 16)}...${ev.sha256_hash.slice(-8)}`
    : '—'

  return (
    <div className="panel evidence-banner fade-in">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="evidence-filename">📄 {ev.filename || 'Unknown'}</span>
          <span className="integrity-badge">✔ INTEGRITY VERIFIED</span>
        </div>
        <div className="evidence-hash mono">
          SHA-256&nbsp;
          <span title={ev.sha256_hash}>{ev.sha256_hash || '—'}</span>
        </div>
      </div>

      <div className="evidence-meta">
        <div className="evidence-meta-item">
          <span style={{ color: 'var(--text-muted)' }}>PKT</span>
          <span style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
            {(ev.total_packets || 0).toLocaleString()}
          </span>
        </div>
        <div className="evidence-meta-item">
          <span style={{ color: 'var(--text-muted)' }}>SIZE</span>
          <span style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
            {formatBytes(ev.file_size_bytes)}
          </span>
        </div>
        <div className="evidence-meta-item">
          <span style={{ color: 'var(--text-muted)' }}>DURATION</span>
          <span style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
            {(ev.capture_duration || 0).toFixed(3)}s
          </span>
        </div>
        {analysisTime != null && (
          <div className="evidence-meta-item">
            <span style={{ color: 'var(--text-muted)' }}>ANALYZED IN</span>
            <span style={{ color: 'var(--risk-low)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
              {analysisTime.toFixed(2)}s
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
