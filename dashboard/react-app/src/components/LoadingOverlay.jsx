import { useState, useEffect, useRef } from 'react'

const STEPS = [
  'Parsing PCAP frames',
  'Reconstructing TCP sessions',
  'Extracting TLS handshakes',
  'Scoring cryptographic posture',
]

const STEP_DURATION = 450    // ms spent on each step (~1.8s total for 4 steps)
const COMPLETE_HOLD  = 650    // ms to show "ANALYSIS COMPLETE" before navigating

/**
 * Props:
 *  - loading   {bool}  — true while the API fetch is running
 *  - hasError  {bool}  — true if an error occurred, aborts overlay immediately
 *  - onDone    {fn}    — called after all steps finish + brief hold (triggers page navigation)
 */
export default function LoadingOverlay({ loading, hasError, onDone }) {
  const [phase, setPhase]           = useState('idle')   // 'idle' | 'running' | 'complete'
  const [activeStep, setActiveStep] = useState(0)
  const [completedSteps, setCompletedSteps] = useState([])

  const apiDoneRef    = useRef(false)
  const stepsDoneRef  = useRef(false)
  const timersRef     = useRef([])
  const onDoneRef     = useRef(onDone)
  onDoneRef.current   = onDone

  const clearTimers = () => {
    timersRef.current.forEach(clearTimeout)
    timersRef.current = []
  }

  // Cleanup on unmount
  useEffect(() => () => clearTimers(), [])

  // Abort immediately on error
  useEffect(() => {
    if (hasError) {
      clearTimers()
      setPhase('idle')
      setActiveStep(0)
      setCompletedSteps([])
    }
  }, [hasError])

  const finishPipeline = () => {
    setPhase('complete')
    const t = setTimeout(() => {
      setPhase('idle')
      setActiveStep(0)
      setCompletedSteps([])
      onDoneRef.current?.()
    }, COMPLETE_HOLD)
    timersRef.current.push(t)
  }

  // Handle loading start (when loading transitions to true)
  useEffect(() => {
    if (loading) {
      clearTimers()
      apiDoneRef.current   = false
      stepsDoneRef.current = false
      setActiveStep(0)
      setCompletedSteps([])
      setPhase('running')

      // Schedule Step 1
      timersRef.current.push(setTimeout(() => {
        setCompletedSteps(prev => [...prev, 0])
        setActiveStep(1)
      }, STEP_DURATION))

      // Schedule Step 2
      timersRef.current.push(setTimeout(() => {
        setCompletedSteps(prev => [...prev, 1])
        setActiveStep(2)
      }, STEP_DURATION * 2))

      // Schedule Step 3
      timersRef.current.push(setTimeout(() => {
        setCompletedSteps(prev => [...prev, 2])
        setActiveStep(3)
      }, STEP_DURATION * 3))

      // Schedule Step 4 completion
      timersRef.current.push(setTimeout(() => {
        setCompletedSteps([0, 1, 2, 3])
        stepsDoneRef.current = true

        // If backend API has already responded, finish immediately
        if (apiDoneRef.current) {
          finishPipeline()
        }
      }, STEP_DURATION * 4))
    }
  }, [loading])

  // Handle API completion (when loading transitions from true to false)
  useEffect(() => {
    if (phase === 'running' && !loading) {
      apiDoneRef.current = true
      // If all 4 step animations have already finished, finish now!
      if (stepsDoneRef.current) {
        finishPipeline()
      }
      // If step animations are still ticking, DO NOT cancel them!
      // Step 4's timer will see apiDoneRef.current === true and trigger finishPipeline().
    }
  }, [loading, phase])

  if (phase === 'idle') return null

  const isComplete = phase === 'complete'

  return (
    <div className="loading-overlay">
      <div className={`loading-radar${isComplete ? ' loading-radar--complete' : ''}`}>
        <div className="radar-sweep" />
        <div className="radar-dot" />
      </div>

      <div className="loading-progress">
        <div className={`loading-progress-bar${isComplete ? ' loading-progress-bar--complete' : ''}`} />
      </div>

      <div className={`loading-title${isComplete ? ' loading-title--complete' : ''}`}>
        {isComplete ? 'ANALYSIS COMPLETE' : 'FORENSIC ANALYSIS IN PROGRESS'}
      </div>
      <div className="loading-subtitle">
        {isComplete ? 'Finalizing cryptographic report…' : 'Running deep packet inspection…'}
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
