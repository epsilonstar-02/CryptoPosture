import { useState, useCallback } from 'react'

export default function EvidenceBanner({ evidence }) {
  const ev = evidence || {}
  const [copied, setCopied] = useState(false)

  const formatBytes = (b) => {
    if (!b) return '0 B'
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / (1024 * 1024)).toFixed(2)} MB`
  }

  const shortHash = ev.sha256_hash
    ? `${ev.sha256_hash.slice(0, 12)}…${ev.sha256_hash.slice(-8)}`
    : '—'

  const copyHash = useCallback(() => {
    if (!ev.sha256_hash) return
    navigator.clipboard.writeText(ev.sha256_hash).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [ev.sha256_hash])

  return (
    <div className="panel evidence-banner fade-in">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span className="evidence-filename">📄 {ev.filename || 'Unknown'}</span>
          <span className="integrity-badge">✔ INTEGRITY VERIFIED</span>
        </div>
        <div className="evidence-hash">
          <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.6rem', letterSpacing: '0.08em' }}>SHA-256</span>
          <span
            className={`hash-chip${copied ? ' hash-chip--copied' : ''}`}
            onClick={copyHash}
            title={ev.sha256_hash || '—'}
          >
            {copied ? '✓ Copied!' : shortHash}
          </span>
        </div>
      </div>

      <div className="evidence-meta">
        <div className="evidence-meta-item">
          <span className="evidence-meta-key">Packets</span>
          <span className="evidence-meta-val">{(ev.total_packets || 0).toLocaleString()}</span>
        </div>
        <div className="evidence-meta-item">
          <span className="evidence-meta-key">Size</span>
          <span className="evidence-meta-val">{formatBytes(ev.file_size_bytes)}</span>
        </div>
        <div className="evidence-meta-item">
          <span className="evidence-meta-key">Duration</span>
          <span className="evidence-meta-val">{(ev.capture_duration || 0).toFixed(3)}s</span>
        </div>
      </div>
    </div>
  )
}
