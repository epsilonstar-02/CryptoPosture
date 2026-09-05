import { useRef, useState, useEffect } from 'react'

const SAMPLES = [
  // Tier 1: Deterministic Synthetic Fixtures
  { name: 'clean_implicit_tls',          tierCategory: 'tier1', tierNum: 'T1', label: 'Clean implicit TLS',    tier: 'LOW',      meta: 'IMAPS · TLS 1.3 · ECDHE',       desc: 'Baseline healthy session (score ~100)' },
  { name: 'weak_cipher_starttls',        tierCategory: 'tier1', tierNum: 'T1', label: 'Weak cipher STARTTLS',  tier: 'HIGH',     meta: 'SMTP · TLS 1.0 · 3DES',         desc: 'Deprecated cipher negotiated (score ~30–55)' },
  { name: 'stripped_starttls_plaintext', tierCategory: 'tier1', tierNum: 'T1', label: 'STARTTLS stripped',     tier: 'CRITICAL', meta: 'SMTP · plaintext fallback',      desc: 'MITM downgrade to plaintext (score 0)' },
  { name: 'expired_cert_implicit_tls',   tierCategory: 'tier1', tierNum: 'T1', label: 'Expired certificate',   tier: 'HIGH',     meta: 'IMAPS · expired X.509',         desc: 'Certificate validity failure (score ~40–65)' },
  { name: 'buffer_injection_attack',     tierCategory: 'tier1', tierNum: 'T1', label: 'Buffer injection',      tier: 'CRITICAL', meta: 'TLS · response injection',       desc: 'Poddebniak et al. USENIX (score <= 15)' },

  // Tier 2: Real Mail-Server Lab Captures
  { name: 'postfix_submission_tls13',    tierCategory: 'tier2', tierNum: 'T2', label: 'Postfix Submission',    tier: 'LOW',      meta: 'Port 587 · TLS 1.3 · PQC Ready',desc: 'Authentic Postfix submission handshake' },
  { name: 'dovecot_imaps_tls12',         tierCategory: 'tier2', tierNum: 'T2', label: 'Dovecot IMAPS',         tier: 'LOW',      meta: 'Port 993 · TLS 1.2 · ECDHE',    desc: 'Authentic Dovecot enterprise mailbox access' },
  { name: 'sendmail_opportunistic_starttls', tierCategory: 'tier2', tierNum: 'T2', label: 'Sendmail STARTTLS', tier: 'MEDIUM',   meta: 'Port 25 · Opportunistic STARTTLS', desc: 'Authentic inter-MTA mail exchange' },

  // Tier 3: Adversarial & Edge-Case Captures
  { name: 'cert_sni_mismatch',           tierCategory: 'tier3', tierNum: 'T3', label: 'Cert SNI Mismatch',     tier: 'HIGH',     meta: 'TLS 1.2 · Hostname Mismatch',   desc: 'Server certificate CN does not match SNI' },
  { name: 'cert_weak_rsa1024',           tierCategory: 'tier3', tierNum: 'T3', label: 'Weak RSA 1024-bit',     tier: 'HIGH',     meta: 'TLS 1.2 · Sub-2048-bit Key',    desc: 'Deprecated 1024-bit RSA certificate key' },
  { name: 'tcp_fragmented_client_hello', tierCategory: 'tier3', tierNum: 'T3', label: 'TCP Fragmented Hello',  tier: 'LOW',      meta: 'TLS 1.3 · Multi-segment TCP',   desc: 'ClientHello split across fragmented segments' },
  { name: 'tcp_retransmission_duplicates', tierCategory: 'tier3', tierNum: 'T3', label: 'TCP Retransmissions', tier: 'LOW',     meta: 'TLS 1.3 · Duplicate Segments',  desc: 'Network retransmissions deduplicated' },
  { name: 'out_of_order_tcp_segments',   tierCategory: 'tier3', tierNum: 'T3', label: 'Out-of-Order TCP',      tier: 'MEDIUM',   meta: 'TLS 1.2 · Segment Reordering',  desc: 'TCP segments delivered out of order' },
  { name: 'malformed_tls_record_length', tierCategory: 'tier3', tierNum: 'T3', label: 'Malformed TLS Record',  tier: 'CRITICAL', meta: 'TLS Record Layer Anomaly',      desc: 'Truncated record length field in stream' },
  { name: 'incomplete_tls_handshake_rst', tierCategory: 'tier3', tierNum: 'T3', label: 'Incomplete Handshake RST', tier: 'HIGH', meta: 'TCP RST during handshake',     desc: 'Connection torn down before Finished message' },
]

const FEATURE_CARDS = [
  {
    index: '01 / CAPTURE SCOPE',
    title: 'What this sees',
    accent: 'blue',
    items: [
      'SMTP / IMAP / POP3 traffic',
      'TLS 1.2 & TLS 1.3 stateful handshakes',
      'X.509 certificate chains & SAN verification',
      'STARTTLS downgrade & stripping detection',
      'Buffer injection attacks (Poddebniak et al.)',
      'JA4 / JA4S / JA4X fingerprints & PQC flags',
    ],
  },
  {
    index: '02 / RISK ENGINE',
    title: 'How it scores (crypto-posture-v1)',
    accent: 'violet',
    items: [
      'TLS Version — weight 25%',
      'Cipher Suite — weight 20%',
      'Certificate Health — weight 20%',
      'STARTTLS Transition — weight 15%',
      'Forward Secrecy — weight 10%',
      'Protocol Context — weight 10%',
    ],
  },
  {
    index: '03 / BASELINES',
    title: 'What it validates',
    accent: 'green',
    items: [
      'RFC 9325 / BCP 195 (TLS 1.3/1.2)',
      'RFC 8996 (TLS 1.0/1.1 Deprecation)',
      'RFC 8314 (Cleartext Obsolete / Implicit TLS)',
      'NIST SP 800-52 Rev. 2 (TLS Guidance)',
      'NIST SP 800-57 (Key Management Strength)',
      "Poddebniak et al. USENIX '21 (Buffer Injection)",
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
  const [activeTier, setActiveTier]   = useState('all')

  const visibleSamples = activeTier === 'all'
    ? SAMPLES
    : SAMPLES.filter(s => s.tierCategory === activeTier)

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
              CURATED EVIDENCE BENCHMARK (15 PCAPS)
            </div>
            <h2>Explore a known scenario</h2>
          </div>
          <p>Ground-truth benchmark corpus across three forensic tiers.<br />
            <span className="demo-click-hint">↙ Click any card to run deep packet inspection</span>
          </p>
        </div>

        {/* Tier filter tabs */}
        <div className="filter-bar" style={{ marginBottom: 16 }}>
          {[
            { id: 'all', label: 'All PCAPs', count: SAMPLES.length },
            { id: 'tier1', label: 'Tier 1: Synthetic Fixtures', count: 5 },
            { id: 'tier2', label: 'Tier 2: Real Lab Captures', count: 3 },
            { id: 'tier3', label: 'Tier 3: Adversarial Edge Cases', count: 7 },
          ].map(t => (
            <button
              key={t.id}
              className={`filter-chip${activeTier === t.id ? ' filter-chip--active' : ''}`}
              onClick={() => setActiveTier(t.id)}
            >
              {t.label} <span style={{ opacity: 0.6, fontSize: '0.62rem', marginLeft: 4 }}>({t.count})</span>
            </button>
          ))}
        </div>

        <div className="demo-grid">
          {visibleSamples.map((sample, index) => (
            <button
              key={sample.name}
              className={`demo-card demo-card--${sample.tier.toLowerCase()}`}
              disabled={loading}
              onClick={() => onSample(sample.name)}
              title={`Run scenario: ${sample.label}`}
              aria-label={`Load demo PCAP: ${sample.label} (${sample.tier} risk)`}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span className="demo-number" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--accent-blue)' }}>
                  {sample.tierNum} · {String(index + 1).padStart(2, '0')}
                </span>
                <span className={`risk-pill risk-pill--${sample.tier}`} style={{ fontSize: '0.6rem', padding: '2px 8px' }}>
                  <span className={`risk-dot risk-dot--${sample.tier}`} />
                  {sample.tier}
                </span>
              </div>
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
