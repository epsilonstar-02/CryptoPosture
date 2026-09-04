import { useEffect, useRef } from 'react'

const SCORE_COLORS = {
  high:   '#22c55e',
  medium: '#eab308',
  low:    '#f97316',
  crit:   '#ef4444',
}

function getColor(score) {
  if (score >= 80) return SCORE_COLORS.high
  if (score >= 55) return SCORE_COLORS.medium
  if (score >= 30) return SCORE_COLORS.low
  return SCORE_COLORS.crit
}

export default function PostureGauge({ score, tier }) {
  const canvasRef = useRef(null)
  const animRef   = useRef(null)
  const curRef    = useRef(0)

  const safeScore = typeof score === 'number' ? score : 0
  const color = getColor(safeScore)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const size = canvas.width
    const cx = size / 2, cy = size / 2
    const r  = size * 0.38
    const lw = size * 0.055

    const startAngle = Math.PI * 0.75
    const fullArc    = Math.PI * 1.5

    const draw = (val) => {
      ctx.clearRect(0, 0, size, size)

      // Track
      ctx.beginPath()
      ctx.arc(cx, cy, r, startAngle, startAngle + fullArc)
      ctx.strokeStyle = 'rgba(255,255,255,0.05)'
      ctx.lineWidth = lw
      ctx.lineCap = 'round'
      ctx.stroke()

      // Fill arc
      const progress = (val / 100) * fullArc
      ctx.beginPath()
      ctx.arc(cx, cy, r, startAngle, startAngle + progress)
      ctx.strokeStyle = color
      ctx.lineWidth = lw
      ctx.lineCap = 'round'
      ctx.shadowColor = color
      ctx.shadowBlur = 18
      ctx.stroke()
      ctx.shadowBlur = 0

      // Score text
      ctx.fillStyle = color
      ctx.font = `bold ${size * 0.22}px 'JetBrains Mono', monospace`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(Math.round(val), cx, cy - size * 0.04)

      // /100
      ctx.fillStyle = 'rgba(255,255,255,0.25)'
      ctx.font = `${size * 0.08}px 'Inter', sans-serif`
      ctx.fillText('/100', cx, cy + size * 0.14)
    }

    // Animate
    if (animRef.current) cancelAnimationFrame(animRef.current)
    const target = safeScore
    const start  = curRef.current
    const duration = 1200
    const startTime = performance.now()

    const step = (now) => {
      const t = Math.min((now - startTime) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      const val = start + (target - start) * eased
      curRef.current = val
      draw(val)
      if (t < 1) animRef.current = requestAnimationFrame(step)
    }
    animRef.current = requestAnimationFrame(step)

    return () => { if (animRef.current) cancelAnimationFrame(animRef.current) }
  }, [safeScore, color])

  return (
    <div className="panel panel--glow gauge-panel">
      <canvas ref={canvasRef} width={220} height={220} style={{ maxWidth: '100%' }} />
      <div className="gauge-label">Enterprise Posture Index</div>
      <div className="gauge-tier">
        <span className={`risk-pill risk-pill--${tier}`} style={{ fontSize: '0.8rem', padding: '4px 14px' }}>
          {tier}
        </span>
      </div>
    </div>
  )
}
