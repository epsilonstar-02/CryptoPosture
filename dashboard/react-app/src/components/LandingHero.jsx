export default function LandingHero() {
  return (
    <div className="landing-hero">
      <div className="hero-pulse">
        <span className="hero-icon">🔐</span>
      </div>

      <h1 className="hero-title">Awaiting Target Acquisition</h1>
      <p className="hero-sub">
        Upload a PCAP/PCAPNG capture or select a demo scenario from the sidebar to begin forensic analysis.
      </p>

      <div className="hero-cards">
        <div className="panel hero-card">
          <div className="hero-card-title">🔬 What This Analyzes</div>
          {[
            'SMTP / IMAP / POP3 traffic',
            'TLS handshake parameters',
            'X.509 certificate health',
            'STARTTLS negotiation flow',
            'Buffer injection attacks',
            'JA4/JA4S/JA4X fingerprints',
          ].map(item => (
            <div key={item} className="hero-card-item">{item}</div>
          ))}
        </div>

        <div className="panel hero-card">
          <div className="hero-card-title">📊 Scoring Model</div>
          {[
            'TLS Version — weight 0.25',
            'Cipher Suite — weight 0.20',
            'Certificate Health — 0.20',
            'STARTTLS Transition — 0.15',
            'Forward Secrecy — 0.10',
            'Protocol Context — 0.10',
          ].map(item => (
            <div key={item} className="hero-card-item">{item}</div>
          ))}
        </div>

        <div className="panel hero-card">
          <div className="hero-card-title">⚙️ Standards Checked</div>
          {[
            'NIST SP 800-52 Rev. 2',
            'RFC 9325 / BCP 195',
            'RFC 8314 (Implicit TLS)',
            'RFC 8996 (TLS deprecation)',
            'RFC 3207 (STARTTLS)',
            'Poddebniak et al. USENIX \'21',
          ].map(item => (
            <div key={item} className="hero-card-item">{item}</div>
          ))}
        </div>
      </div>
    </div>
  )
}
