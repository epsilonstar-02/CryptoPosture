import { useEffect, useRef, useState } from 'react'

const TIERS = [
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH',     label: 'High' },
  { key: 'MEDIUM',   label: 'Medium' },
  { key: 'LOW',      label: 'Low' },
]

function AnimatedCount({ target }) {
  const [display, setDisplay] = useState(0)
  const frameRef = useRef()

  useEffect(() => {
    const duration = 800
    const startTime = performance.now()

    const step = (now) => {
      const t = Math.min((now - startTime) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 2)
      setDisplay(Math.round(eased * target))
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
      {TIERS.map(({ key, label }) => (
        <div key={key} className={`risk-card risk-card--${key}`}>
          <div className="risk-card-header">
            <span className="risk-card-label">{label}</span>
            <span className={`risk-dot risk-dot--${key}`} />
          </div>
          <div className={`risk-card-count risk-card-count--${key}`}>
            <AnimatedCount target={rb[key] ?? 0} />
          </div>
          <span className={`risk-pill risk-pill--${key}`} style={{ alignSelf: 'flex-start', fontSize: '0.56rem' }}>
            {key}
          </span>
        </div>
      ))}

      <div className="risk-matrix-footer">
        <div className="risk-matrix-stat">
          <div className="risk-matrix-stat-label">Violations</div>
          <div className="risk-matrix-stat-value" style={{ color: 'var(--text-primary)' }}>
            <AnimatedCount target={totalViolations ?? 0} />
          </div>
        </div>
        <div className="risk-matrix-stat">
          <div className="risk-matrix-stat-label">Sessions</div>
          <div className="risk-matrix-stat-value" style={{ color: 'var(--accent-blue)' }}>
            <AnimatedCount target={sessionCount ?? 0} />
          </div>
        </div>
      </div>
    </div>
  )
}
