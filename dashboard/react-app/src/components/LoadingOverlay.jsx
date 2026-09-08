import { useState, useEffect, useRef } from 'react'

const STEPS = [
  'Verifying capture integrity & SHA-256 chain of custody',
  'Reconstructing TCP streams & STARTTLS state transitions',
  'Parsing TLS records, ciphers & X.509 certificate chains',
  'Evaluating deterministic RFC & NIST SP 800-52r2 policies',
  'Executing standards-informed scoring & critical score caps',
  'Detecting unsupervised outliers (Liu et al. Isolation Forest)',
]

const STEP_SUBTITLES = [
  'Verifying capture integrity & SHA-256 chain of custody…',
  'Reconstructing TCP streams & STARTTLS state transitions…',
  'Parsing TLS records, ciphers & X.509 certificate chains…',
  'Evaluating deterministic RFC & NIST SP 800-52r2 policies…',
  'Executing standards-informed scoring & critical score caps…',
  'Detecting unsupervised outliers (Liu et al. Isolation Forest)…',
]

const COMPLETE_HOLD = 600 // ms to show "ANALYSIS COMPLETE" before navigating

/**
 * Multi-phase time scaling curve:
 * - 0s - 2.5s (0% -> 36%): Initial capture verification & TCP stream reassembly
 * - 2.5s - 6s (36% -> 65%): TLS records, ciphers & RFC policy checks
 * - 6s - 12s  (65% -> 84%): Scoring engine & critical caps
 * - 12s - 25s (84% -> 92%): Isolation Forest outlier detection & finalization
 * - > 25s     (92% -> 98%): Smooth asymptotic creep that never freezes or gets stuck
 */
function calculateRunningProgress(elapsedSec) {
  if (elapsedSec <= 2.5) {
    return (elapsedSec / 2.5) * 36
  }
  if (elapsedSec <= 6) {
    return 36 + ((elapsedSec - 2.5) / 3.5) * 29
  }
  if (elapsedSec <= 12) {
    return 65 + ((elapsedSec - 6) / 6) * 19
  }
  if (elapsedSec <= 25) {
    return 84 + ((elapsedSec - 12) / 13) * 8
  }
  return 92 + 6 * (1 - Math.exp(-(elapsedSec - 25) / 25))
}

function getActiveStepIndex(progress) {
  if (progress < 18) return 0
  if (progress < 36) return 1
  if (progress < 54) return 2
  if (progress < 70) return 3
  if (progress < 84) return 4
  return 5
}

/**
 * Props:
 *  - loading   {bool}  — true while the API fetch is running
 *  - hasError  {bool}  — true if an error occurred, aborts overlay immediately
 *  - onDone    {fn}    — called after all steps finish + brief hold (triggers page navigation)
 */
export default function LoadingOverlay({ loading, hasError, onDone }) {
  const [phase, setPhase]                   = useState('idle') // 'idle' | 'running' | 'complete'
  const [progress, setProgress]             = useState(0)
  const [elapsed, setElapsed]               = useState(0)
  const [finalElapsed, setFinalElapsed]     = useState('0.0')
  const [activeStep, setActiveStep]         = useState(0)
  const [completedSteps, setCompletedSteps] = useState([])

  const tickerRef     = useRef(null)
  const timersRef     = useRef([])
  const startMsRef    = useRef(0)
  const activeStepRef = useRef(0)
  const onDoneRef     = useRef(onDone)

  useEffect(() => {
    onDoneRef.current = onDone
  }, [onDone])

  const clearAllTimers = () => {
    if (tickerRef.current) {
      clearInterval(tickerRef.current)
      tickerRef.current = null
    }
    timersRef.current.forEach(t => {
      clearTimeout(t)
      clearInterval(t)
    })
    timersRef.current = []
  }

  // Cleanup on unmount
  useEffect(() => () => clearAllTimers(), [])

  // Abort immediately on error
  useEffect(() => {
    if (hasError) {
      clearAllTimers()
      setPhase('idle')
      setProgress(0)
      setActiveStep(0)
      setCompletedSteps([])
    }
  }, [hasError])

  // Handle loading start (when loading transitions to true)
  useEffect(() => {
    if (loading) {
      clearAllTimers()
      const startTime = performance.now()
      startMsRef.current = startTime
      activeStepRef.current = 0

      setPhase('running')
      setProgress(0)
      setElapsed(0)
      setActiveStep(0)
      setCompletedSteps([])

      tickerRef.current = setInterval(() => {
        const now = performance.now()
        const elapsedSec = (now - startTime) / 1000
        setElapsed(elapsedSec)

        const p = calculateRunningProgress(elapsedSec)
        setProgress(p)

        const step = getActiveStepIndex(p)
        setActiveStep(step)
        activeStepRef.current = step

        // Steps up to step - 1 are completed. Step 5 stays active and is NOT completed while loading!
        setCompletedSteps(Array.from({ length: step }, (_, i) => i))
      }, 50)
    }
  }, [loading])

  // Handle API completion (when loading transitions from true to false without error)
  useEffect(() => {
    if (phase === 'running' && !loading && !hasError) {
      if (tickerRef.current) {
        clearInterval(tickerRef.current)
        tickerRef.current = null
      }

      const totalElapsedSec = Math.max(0.1, (performance.now() - startMsRef.current) / 1000)
      const formattedElapsed = totalElapsedSec.toFixed(1)
      setFinalElapsed(formattedElapsed)
      setElapsed(totalElapsedSec)
      setProgress(100)

      // Cascade any remaining steps to completed in rapid sequence
      const startIdx = activeStepRef.current
      const remaining = []
      for (let i = startIdx; i < STEPS.length; i++) {
        remaining.push(i)
      }
      if (remaining.length === 0) {
        remaining.push(STEPS.length - 1)
      }

      let stepDelay = 0
      remaining.forEach((stepIdx, idx) => {
        stepDelay = (idx + 1) * 45
        const t = setTimeout(() => {
          setActiveStep(stepIdx)
          setCompletedSteps(prev => (prev.includes(stepIdx) ? prev : [...prev, stepIdx]))
        }, stepDelay)
        timersRef.current.push(t)
      })

      const completeTimer = setTimeout(() => {
        setCompletedSteps(STEPS.map((_, i) => i))
        setPhase('complete')

        const exitTimer = setTimeout(() => {
          setPhase('idle')
          setProgress(0)
          setCompletedSteps([])
          setActiveStep(0)
          onDoneRef.current?.()
        }, COMPLETE_HOLD)
        timersRef.current.push(exitTimer)
      }, stepDelay + 50)

      timersRef.current.push(completeTimer)
    }
  }, [loading, phase, hasError])

  if (phase === 'idle') return null

  const isComplete = phase === 'complete'

  return (
    <div className="loading-overlay">
      <div className={`loading-radar${isComplete ? ' loading-radar--complete' : ''}`}>
        <div className="radar-sweep" />
        <div className="radar-dot" />
      </div>

      <div className="loading-progress">
        <div
          className={`loading-progress-bar${isComplete ? ' loading-progress-bar--complete' : ''}`}
          style={{ width: `${isComplete ? 100 : Math.min(99, Math.max(0, progress))}%` }}
        />
      </div>

      <div className="loading-progress-meta">
        <span className="loading-progress-pct">{isComplete ? '100%' : `${Math.floor(progress)}%`}</span>
        <span className="loading-progress-time">{isComplete ? `${finalElapsed}s` : `${elapsed.toFixed(1)}s`}</span>
      </div>

      <div className={`loading-title${isComplete ? ' loading-title--complete' : ''}`}>
        {isComplete ? 'ANALYSIS COMPLETE' : 'FORENSIC ANALYSIS IN PROGRESS'}
      </div>
      <div className="loading-subtitle">
        {isComplete
          ? `Finalized in ${finalElapsed}s — report ready`
          : `${STEP_SUBTITLES[activeStep] || 'Running deep packet inspection…'} (${elapsed.toFixed(1)}s)`}
      </div>

      <div className="loading-steps">
        {STEPS.map((step, i) => {
          const isDone   = isComplete || completedSteps.includes(i)
          const isActive = !isComplete && activeStep === i && !isDone
          return (
            <div
              key={step}
              className={`loading-step${isDone ? ' loading-step--done' : isActive ? ' loading-step--active' : ''}`}
            >
              <span className="loading-step-icon">
                {isDone ? '✓' : isActive ? '▶' : '○'}
              </span>
              {step}{isActive ? '…' : ''}
            </div>
          )
        })}
      </div>
    </div>
  )
}
