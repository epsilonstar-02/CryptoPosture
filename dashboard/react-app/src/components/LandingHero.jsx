import { useRef, useState, useEffect } from 'react'

const SAMPLES = [
  { name: 'clean_implicit_tls',          label: 'Clean implicit TLS',    tier: 'LOW',      meta: 'IMAPS · TLS 1.3 · ECDHE',       desc: 'Baseline healthy session' },
  { name: 'weak_cipher_starttls',        label: 'Weak cipher STARTTLS',  tier: 'HIGH',     meta: 'SMTP · TLS 1.0 · 3DES',         desc: 'Deprecated cipher negotiated' },
  { name: 'stripped_starttls_plaintext', label: 'STARTTLS stripped',     tier: 'CRITICAL', meta: 'SMTP · plaintext fallback',      desc: 'Downgrade to plaintext' },
  { name: 'expired_cert_implicit_tls',   label: 'Expired certificate',   tier: 'HIGH',     meta: 'IMAPS · expired X.509',         desc: 'Certificate validity failure' },
  { name: 'buffer_injection_attack',     label: 'Buffer injection',      tier: 'CRITICAL', meta: 'TLS · response injection',       desc: 'Active attack pattern' },
]

const FEATURE_CARDS = [
  {
    index: '01 / CAPTURE SCOPE',
    title: 'What this sees',
    accent: 'blue',
    items: [
      'SMTP / IMAP / POP3 traffic',
      'TLS handshake parameters',
      'X.509 certificate health',
      'STARTTLS negotiation flow',
      'Buffer injection attacks',
      'JA4 / JA4S / JA4X fingerprints',
    ],
  },
  {
    index: '02 / RISK ENGINE',
    title: 'How it scores',
    accent: 'violet',
    items: [
      'TLS Version — weight 0.25',
      'Cipher Suite — weight 0.20',
      'Certificate Health — 0.20',
      'STARTTLS Transition — 0.15',
      'Forward Secrecy — 0.10',
      'Protocol Context — 0.10',
    ],
  },
  {
    index: '03 / BASELINES',
    title: 'What it validates',
    accent: 'green',
    items: [
      'NIST SP 800-52 Rev. 2',
      'RFC 9325 / BCP 195',
      'RFC 8314 (Implicit TLS)',
      'RFC 8996 (TLS deprecation)',
      'RFC 3207 (STARTTLS)',
      "Poddebniak et al. USENIX '21",
    ],
  },
]

function formatRelativeTime(date) {
  if (!date) return null
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 60)  return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}

export default function LandingHero({ onFile, onSample, loading, apiStatus, sampleCount, lastAnalyzedAt, lastResult }) {
  const fileRef  = useRef()
  const sandboxRef = useRef()
  const [dragging, setDragging] = useState(false)
  const [relTime, setRelTime]   = useState(null)
  const [engineState, setEngineState] = useState('STANDBY')

  /* keep relative time ticking */
  useEffect(() => {
    setRelTime(formatRelativeTime(lastAnalyzedAt))
    const id = setInterval(() => setRelTime(formatRelativeTime(lastAnalyzedAt)), 15000)
    return () => clearInterval(id)
  }, [lastAnalyzedAt])

  /* mirror loading → engine state */
  useEffect(() => {
    if (loading)             setEngineState('PROCESSING')
    else if (lastAnalyzedAt) setEngineState('COMPLETE')
    else                     setEngineState('STANDBY')
  }, [loading, lastAnalyzedAt])

  const receive = file => onFile(file)

  const scrollToSandbox = () => {
    sandboxRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="landing-hero">

      <div className="hero-eyebrow">
        <span className="kicker-dot" />
        FORENSIC OPERATIONS CONSOLE
        <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>v1.0.0</span>
      </div>

      <div className="hero-command-grid">
        {/* ── Left: intro + drop zone ── */}
        <section className="hero-intro">
          <div className="hero-icon-wrap">
            <img className="hero-icon" src="/assets/radar.svg" alt="" />
          </div>

          <h1 className="hero-title">
            Ready to inspect<br />
            <em>the invisible.</em>
          </h1>

          <p className="hero-sub">
            Ingest a capture to reconstruct encrypted mail traffic, expose
            cryptographic drift, and preserve an evidence-grade chain of custody.
          </p>

          {/* Big drop zone */}
          <div
            className={`case-intake${dragging ? ' case-intake--drag' : ''}`}
            onClick={() => fileRef.current?.click()}
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); receive(e.dataTransfer.files[0]) }}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={e => receive(e.target.files[0])}
            />
            <div className="intake-icon-big">⌁</div>
            <div className="intake-title">Open evidence capture</div>
            <div className="intake-sub">Drop PCAP / PCAPNG · or click to browse</div>
            <div className="intake-arrow">→ Supports .pcap and .pcapng</div>
          </div>

          <div className="hero-status-row">
            <span><b>01</b> Capture intake</span><i />
            <span><b>02</b> Protocol reconstruction</span><i />
            <span><b>03</b> Risk intelligence</span>
          </div>

          {/* Scroll CTA */}
          <button className="scroll-to-sandbox-cta" onClick={scrollToSandbox} type="button">
            <span>↓ Explore demo scenarios</span>
          </button>
        </section>

        {/* ── Right: LIVE TELEMETRY (real data) ── */}
        <aside className="hero-terminal panel">
          <div className="terminal-top">
            <span>LIVE TELEMETRY</span>
            <div className="terminal-dots"><i /><i /><i /></div>
          </div>

          {/* Radar rings — now show engine state via colour */}
          <div className={`terminal-rings terminal-rings--${engineState.toLowerCase()}`}>
            <span /><span /><span />
            <b>◈</b>
          </div>

          {/* Engine state */}
          <div className="terminal-stat">
            <span>ANALYSIS ENGINE</span>
            <strong className={`engine-state--${engineState.toLowerCase()}`}>{engineState}</strong>
          </div>

          {/* Real telemetry rows */}
          <div className="telemetry-rows">
            <div className="telemetry-row">
              <span className="telemetry-key">API STATUS</span>
              <span className={`telemetry-val telemetry-val--${apiStatus}`}>
                <i className="telemetry-dot" />
                {apiStatus === 'online' ? 'ONLINE' : apiStatus === 'loading' ? 'CONNECTING…' : 'OFFLINE'}
              </span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-key">SAMPLE PCAPS</span>
              <span className="telemetry-val">
                {sampleCount != null ? `${sampleCount} LOADED` : '—'}
              </span>
            </div>
            <div className="telemetry-row">
              <span className="telemetry-key">LAST ANALYSIS</span>
              <span className="telemetry-val">
                {relTime ?? '—'}
              </span>
            </div>
            {lastResult && (
              <>
                <div className="telemetry-row">
                  <span className="telemetry-key">RISK TIER</span>
                  <span className={`telemetry-val telemetry-val--tier-${(lastResult.overall_risk_tier ?? 'LOW').toLowerCase()}`}>
                    {lastResult.overall_risk_tier ?? '—'}
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">POSTURE INDEX</span>
                  <span className="telemetry-val">
                    {(lastResult.enterprise_posture_index ?? 0).toFixed(1)} / 100
                  </span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">SESSIONS</span>
                  <span className="telemetry-val">{lastResult.session_count ?? '—'} ANALYZED</span>
                </div>
                <div className="telemetry-row">
                  <span className="telemetry-key">VIOLATIONS</span>
                  <span className="telemetry-val">{lastResult.total_violations ?? 0} FOUND</span>
                </div>
              </>
            )}
          </div>

          {/* Activity bars */}
          <div className="terminal-bars">
            {Array.from({ length: 14 }).map((_, i) => <i key={i} />)}
          </div>
        </aside>
      </div>

      {/* ── WHAT WE ANALYSE — feature cards (promoted) ── */}
      <section className="feature-section">
        <div className="feature-section-head">
          <div className="hero-eyebrow">CAPABILITIES</div>
          <h2 className="feature-section-title">What we analyse</h2>
          <p className="feature-section-sub">
            Every PCAP is processed through three analytical lenses — capture scope, risk scoring, and standards compliance.
          </p>
        </div>
        <div className="hero-cards">
          {FEATURE_CARDS.map(card => (
            <div key={card.index} className={`panel hero-card hero-card--${card.accent}`}>
              <div className="hero-card-index">{card.index}</div>
              <div className="hero-card-title">{card.title}</div>
              {card.items.map(item => (
                <div key={item} className="hero-card-item">{item}</div>
              ))}
            </div>
          ))}
        </div>
      </section>

      {/* ── SANDBOX — Demo scenario library ── */}
      <section className="demo-library" ref={sandboxRef}>
        <div className="demo-library-head">
          <div>
            <div className="hero-eyebrow demo-eyebrow">
              <span className="sandbox-badge">SANDBOX</span>
              CURATED PCAPS
            </div>
            <h2>Explore a known scenario</h2>
          </div>
          <p>Useful for understanding analysis output before opening your own evidence.<br />
            <span className="demo-click-hint">↙ Click any card to instantly run that scenario</span>
          </p>
        </div>

        <div className="demo-grid">
          {SAMPLES.map((sample, index) => (
            <button
              key={sample.name}
              className={`demo-card demo-card--${sample.tier.toLowerCase()}`}
              disabled={loading}
              onClick={() => onSample(sample.name)}
              title={`Run scenario: ${sample.label}`}
              aria-label={`Load demo PCAP: ${sample.label} (${sample.tier} risk)`}
            >
              <span className="demo-number">0{index + 1}</span>
              <span className={`risk-pill risk-pill--${sample.tier}`}>
                <span className={`risk-dot risk-dot--${sample.tier}`} />
                {sample.tier}
              </span>
              <strong>{sample.label}</strong>
              <small>{sample.meta}</small>
              <span className="demo-desc">{sample.desc}</span>
              <span className="demo-run">Run scenario <b>→</b></span>

              {/* Play overlay on hover */}
              <span className="demo-play-overlay" aria-hidden="true">▶</span>
            </button>
          ))}
        </div>
      </section>

    </div>
  )
}
