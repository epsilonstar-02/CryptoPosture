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
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span className="evidence-filename" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            {ev.filename || 'Unknown'}
          </span>
          <span className={`integrity-badge${ev.is_tamper_free === false ? ' integrity-badge--tampered' : ''}`}>
            {ev.is_tamper_free === false ? (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                TAMPER DETECTED
              </>
            ) : (
              <>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
                INTEGRITY VERIFIED
              </>
            )}
          </span>
          {ev.evidence_id && (
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.65rem',
              color: 'var(--accent-blue)',
              background: 'rgba(61,216,232,0.08)',
              padding: '2px 7px',
              borderRadius: 4,
              border: '1px solid rgba(61,216,232,0.2)',
            }}>
              ID: {ev.evidence_id}
            </span>
          )}
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
          {ev.ingestion_timestamp && (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem', marginLeft: 8 }}>
              Ingested: {new Date(ev.ingestion_timestamp).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      <div className="evidence-meta">
        <div className="evidence-meta-item">
          <span className="evidence-meta-key">Format</span>
          <span className="evidence-meta-val" style={{ color: 'var(--accent-blue)' }}>{ev.capture_format || 'PCAP'}</span>
        </div>
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
        {ev.link_layer_type && (
          <div className="evidence-meta-item">
            <span className="evidence-meta-key">Link Layer</span>
            <span className="evidence-meta-val" style={{ fontSize: '0.75rem' }}>{ev.link_layer_type}</span>
          </div>
        )}
      </div>
    </div>
  )
}
