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

function TierIcon({ tier }) {
  if (tier === 'CRITICAL') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    )
  }
  if (tier === 'HIGH') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    )
  }
  if (tier === 'MEDIUM') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
    )
  }
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )
}

export default function RiskMatrix({ breakdown, totalViolations, sessionCount, violationBreakdown, bare = false }) {
  const rb = breakdown || {}
  const vb = violationBreakdown || {}

  const sevColors = {
    CRITICAL: 'var(--risk-critical)',
    HIGH:     'var(--risk-high)',
    MEDIUM:   'var(--risk-medium)',
    LOW:      'var(--risk-low)',
    INFO:     'var(--accent-blue)',
  }

  const totalSessions = sessionCount || Object.values(rb).reduce((acc, v) => acc + (Number(v) || 0), 0) || 1

  return (
    <div className={`${bare ? 'risk-matrix risk-matrix--bare' : 'panel risk-matrix'} fade-in`}>
      {TIERS.map(({ key, label }) => {
        const count = rb[key] ?? 0
        const pct = totalSessions > 0 ? Math.round((count / totalSessions) * 100) : 0
        const isIdle = count === 0

        return (
          <div key={key} className={`risk-card risk-card--${key} ${isIdle ? 'risk-card--idle' : ''}`}>
            <div className="risk-card-header">
              <div className="risk-card-title-group">
                <span className="risk-card-icon">
                  <TierIcon tier={key} />
                </span>
                <span className="risk-card-label">{label}</span>
              </div>
              <span className={`risk-dot risk-dot--${key} ${isIdle ? 'risk-dot--idle' : ''}`} />
            </div>

            <div className="risk-card-body-content">
              <div className="risk-card-metric-row">
                <div className={`risk-card-count risk-card-count--${key}`}>
                  <AnimatedCount target={count} />
                </div>
                <div className="risk-card-stat-meta">
                  <span className="risk-card-unit">sessions</span>
                  <span className="risk-card-pct">{pct}%</span>
                </div>
              </div>

              <div className="risk-card-bar-track">
                <div
                  className={`risk-card-bar-fill risk-card-bar-fill--${key}`}
                  style={{ width: `${count > 0 ? Math.max(pct, 8) : 0}%` }}
                />
              </div>
            </div>
          </div>
        )
      })}

      <div className="risk-matrix-footer">
        <div className="risk-matrix-stat">
          <div className="risk-matrix-stat-label">Total Findings</div>
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
        {Object.keys(vb).length > 0 && (
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', marginLeft: 'auto' }}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => vb[sev] ? (
              <span key={sev} style={{
                fontSize: '0.62rem',
                fontFamily: 'var(--font-mono)',
                padding: '2px 6px',
                borderRadius: 4,
                background: 'rgba(255,255,255,0.04)',
                border: `1px solid ${sevColors[sev]}44`,
                color: sevColors[sev],
              }}>
                {sev.slice(0, 4)}: {vb[sev]}
              </span>
            ) : null)}
          </div>
        )}
      </div>
    </div>
  )
}
