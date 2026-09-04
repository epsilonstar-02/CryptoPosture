import { useEffect, useRef, useState } from 'react'

const TIERS = [
  { key: 'CRITICAL', icon: '🔴', label: 'Critical' },
  { key: 'HIGH',     icon: '🟠', label: 'High' },
  { key: 'MEDIUM',   icon: '🟡', label: 'Medium' },
  { key: 'LOW',      icon: '🟢', label: 'Low' },
]

function AnimatedCount({ target }) {
  const [display, setDisplay] = useState(0)
  const frameRef = useRef()

  useEffect(() => {
    const duration = 800
    const startTime = performance.now()
    const startVal  = 0

    const step = (now) => {
      const t = Math.min((now - startTime) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 2)
      setDisplay(Math.round(startVal + (target - startVal) * eased))
      if (t < 1) frameRef.current = requestAnimationFrame(step)
    }
    frameRef.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frameRef.current)
  }, [target])

  return <>{display}</>
}

export default function RiskMatrix({ breakdown, totalViolations, sessionCount }) {
  const rb = breakdown || {}

  return (
    <div className="panel risk-matrix fade-in">
      {TIERS.map(({ key, icon, label }) => (
        <div key={key} className={`risk-card risk-card--${key}`}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="risk-card-icon">{icon}</span>
            <span className={`risk-pill risk-pill--${key}`}>{key}</span>
          </div>
          <div className={`risk-card-count risk-card-count--${key}`}>
            <AnimatedCount target={rb[key] ?? 0} />
          </div>
          <div className="risk-card-label">{label} Sessions</div>
        </div>
      ))}

      {/* Summary row */}
      <div style={{
        gridColumn: '1 / -1',
        display: 'flex',
        gap: 16,
        padding: '10px 2px 0',
        borderTop: '1px solid var(--border-dim)',
        marginTop: 4,
      }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>Total Violations</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            <AnimatedCount target={totalViolations ?? 0} />
          </div>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '0.62rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 2 }}>Sessions Analyzed</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
            <AnimatedCount target={sessionCount ?? 0} />
          </div>
        </div>
      </div>
    </div>
  )
}
