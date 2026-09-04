export default function LoadingOverlay({ visible }) {
  if (!visible) return null

  const bars = Array.from({ length: 14 }, (_, i) => i)

  return (
    <div className="loading-overlay">
      <div className="loading-radar">
        <div className="radar-sweep" />
        <div className="radar-dot" />
      </div>

      <div className="loading-title">FORENSIC ANALYSIS IN PROGRESS</div>
      <div className="loading-subtitle">Running cryptographic pipeline...</div>

      <div className="loading-bars">
        {bars.map(i => (
          <div
            key={i}
            className="loading-bar"
            style={{
              animationDelay: `${i * 0.06}s`,
              opacity: 0.4 + (i % 4) * 0.15,
            }}
          />
        ))}
      </div>

      <div style={{
        marginTop: 20,
        fontFamily: 'var(--font-mono)',
        fontSize: '0.65rem',
        color: 'var(--text-muted)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
      }}>
        {[
          '▸ Parsing PCAP frames...',
          '▸ Reconstructing TCP sessions...',
          '▸ Extracting TLS handshakes...',
          '▸ Scoring cryptographic posture...',
        ].map((line, i) => (
          <div
            key={i}
            style={{
              color: 'var(--accent-blue)',
              animation: `blink ${1.2 + i * 0.3}s step-end infinite`,
            }}
          >
            {line}
          </div>
        ))}
      </div>
    </div>
  )
}
