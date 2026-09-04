import { useState, useCallback, useRef } from 'react'

const API = '' // proxied via vite to localhost:8000

const SAMPLES = [
  { name: 'clean_implicit_tls',          label: 'Clean Implicit TLS',           tier: 'LOW',      emoji: '✅', desc: 'IMAPS TLS 1.3, ECDHE, AES-256-GCM' },
  { name: 'weak_cipher_starttls',         label: 'Weak Cipher STARTTLS',         tier: 'HIGH',     emoji: '⚠️', desc: 'SMTP TLS 1.0, 3DES — deprecated' },
  { name: 'stripped_starttls_plaintext',  label: 'STARTTLS Stripped (MITM)',      tier: 'CRITICAL', emoji: '🚨', desc: 'Full plaintext fallback' },
  { name: 'expired_cert_implicit_tls',    label: 'Expired Cert Implicit TLS',    tier: 'HIGH',     emoji: '⚠️', desc: 'TLS 1.2 + expired X.509' },
  { name: 'buffer_injection_attack',      label: 'Buffer Injection Attack',       tier: 'CRITICAL', emoji: '💀', desc: 'Poddebniak et al. USENIX \'21' },
]

export default function Sidebar({ onResult, onLoading, loading, apiStatus }) {
  const [dragging, setDragging] = useState(false)
  const [generating, setGenerating] = useState(false)
  const fileRef = useRef()

  const runAnalysis = useCallback(async (formData) => {
    onLoading(true)
    try {
      const res = await fetch(`${API}/api/analyze`, { method: 'POST', body: formData })
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      const data = await res.json()
      onResult(data)
    } catch (e) {
      alert(`Analysis failed: ${e.message}`)
    } finally {
      onLoading(false)
    }
  }, [onLoading, onResult])

  const handleFile = useCallback((file) => {
    if (!file) return
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      alert('Please upload a .pcap or .pcapng file.')
      return
    }
    const fd = new FormData()
    fd.append('file', file)
    runAnalysis(fd)
  }, [runAnalysis])

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    handleFile(e.dataTransfer.files[0])
  }, [handleFile])

  const handleSample = useCallback(async (name) => {
    onLoading(true)
    try {
      const res = await fetch(`${API}/api/samples/${name}/analyze`)
      if (!res.ok) throw new Error(`Server error: ${res.status}`)
      const data = await res.json()
      onResult(data)
    } catch (e) {
      alert(`Sample analysis failed: ${e.message}`)
    } finally {
      onLoading(false)
    }
  }, [onLoading, onResult])

  const handleRegenerate = useCallback(async () => {
    setGenerating(true)
    try {
      await fetch(`${API}/api/samples/generate`, { method: 'POST' })
    } catch (e) {
      alert(`Regeneration failed: ${e.message}`)
    } finally {
      setGenerating(false)
    }
  }, [])

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <span className="sidebar-brand-icon">🔐</span>
        <div className="sidebar-brand-title">CryptoPosture</div>
        <div className="sidebar-brand-sub">Email Forensic Framework</div>
      </div>

      {/* API Status */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border-dim)' }}>
        <div style={{ display: 'flex', alignItems: 'center', fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
          <span className={`status-dot status-dot--${apiStatus}`} />
          {apiStatus === 'online' ? 'API ONLINE' : apiStatus === 'loading' ? 'CONNECTING...' : 'API OFFLINE'}
        </div>
      </div>

      {/* Upload */}
      <div className="sidebar-section">
        <div className="sidebar-label">📁 Upload PCAP</div>
        <div
          className={`upload-zone${dragging ? ' upload-zone--drag' : ''}`}
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".pcap,.pcapng"
            onChange={e => handleFile(e.target.files[0])}
            style={{ display: 'none' }}
          />
          <div className="upload-icon">📂</div>
          <div className="upload-label">Drop PCAP here or click to browse</div>
          <div className="upload-hint">.pcap / .pcapng accepted</div>
        </div>
      </div>

      {/* Demo Samples */}
      <div className="sidebar-section">
        <div className="sidebar-label">🧪 Demo Scenarios</div>
        {SAMPLES.map(s => (
          <button
            key={s.name}
            className="sample-btn"
            disabled={loading}
            onClick={() => handleSample(s.name)}
          >
            <span style={{ fontSize: '1.1rem', flexShrink: 0 }}>{s.emoji}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="sample-btn-label">{s.label}</div>
              <div className="sample-btn-desc">{s.desc}</div>
            </div>
            <span className={`risk-pill risk-pill--${s.tier}`}>{s.tier}</span>
          </button>
        ))}
      </div>

      {/* Regenerate */}
      <div className="sidebar-section">
        <button className="btn btn--ghost" onClick={handleRegenerate} disabled={generating || loading}>
          {generating ? '⏳ Generating...' : '🔄 Regenerate PCAPs'}
        </button>
      </div>

      {/* Footer */}
      <div style={{ marginTop: 'auto', padding: '16px 20px', borderTop: '1px solid var(--border-dim)', textAlign: 'center' }}>
        <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
          SIH-26 Demo<br />
          Passive Network Forensics<br />
          NIST SP 800-52 · RFC 9325
        </div>
      </div>
    </aside>
  )
}
