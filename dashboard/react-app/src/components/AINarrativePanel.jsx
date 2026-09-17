import { useState, useEffect } from 'react'

// ── SVG icon atoms ──────────────────────────────────────────────────────────

function IconSparkles({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M12 3v2M12 19v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M3 12h2M19 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      <circle cx="12" cy="12" r="4" />
    </svg>
  )
}

function IconRefresh({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
      <path d="M3 21v-5h5" />
    </svg>
  )
}

function IconCopy({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
      <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
    </svg>
  )
}

function IconCheck({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

function IconAlertTriangle({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  )
}

// ── Section parser: split "SECTION TITLE\nprose..." blocks ─────────────────

const SECTION_TITLES = [
  'EXECUTIVE SUMMARY',
  'CRITICAL FINDINGS',
  'RISK NARRATIVE',
  'RECOMMENDED REMEDIATIONS',
]

function parseNarrativeSections(text) {
  if (!text) return []
  const sections = []
  let remaining = text.trim()

  for (let i = 0; i < SECTION_TITLES.length; i++) {
    const title = SECTION_TITLES[i]
    const idx = remaining.indexOf(title)
    if (idx === -1) continue

    // Find next section start
    let nextIdx = remaining.length
    for (let j = i + 1; j < SECTION_TITLES.length; j++) {
      const ni = remaining.indexOf(SECTION_TITLES[j], idx + title.length)
      if (ni !== -1 && ni < nextIdx) nextIdx = ni
    }

    const body = remaining.slice(idx + title.length, nextIdx).trim()
    sections.push({ title, body })
  }

  // Fallback: no known section titles found, show raw
  if (sections.length === 0 && text.trim()) {
    sections.push({ title: 'NARRATIVE', body: text.trim() })
  }

  return sections
}

const SECTION_ACCENTS = {
  'EXECUTIVE SUMMARY':       'var(--accent-blue)',
  'CRITICAL FINDINGS':       'var(--risk-critical)',
  'RISK NARRATIVE':          'var(--risk-high)',
  'RECOMMENDED REMEDIATIONS': 'var(--risk-low)',
  'NARRATIVE':               'var(--accent-blue)',
}

// ── Skeleton loader ────────────────────────────────────────────────────────

function NarrativeSkeleton() {
  return (
    <div className="narrative-skeleton" aria-label="Generating narrative…">
      {[90, 75, 85, 60, 80].map((w, i) => (
        <div
          key={i}
          className="narrative-skeleton-line"
          style={{ width: `${w}%`, animationDelay: `${i * 0.1}s` }}
        />
      ))}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────

export default function AINarrativePanel({ result, onToast }) {
  const [copied, setCopied] = useState(false)
  const [regenerating, setRegenerating] = useState(false)
  const [localNarrative, setLocalNarrative] = useState(null)

  // Reset local state if a new analysis result is loaded
  useEffect(() => {
    setLocalNarrative(null)
  }, [result])

  // Active narrative prefers locally regenerated data over initial result payload
  const activeNarrative = localNarrative || result?.ai_narrative || {}
  const activeText = activeNarrative.narrative || ''
  // If narrative text was generated, treat it as successful and clear any skipped/error banner
  const activeSkipped = activeText ? null : (activeNarrative.skipped_reason || null)
  const activeModel = activeNarrative.model || 'gemini-2.5-flash'
  const activeGeneratedAt = activeNarrative.generated_at || null
  const activeTokenUsage = activeNarrative.token_usage || null
  const activeErrorDetail = activeNarrative.error_detail || null

  const sections = parseNarrativeSections(activeText)

  const handleCopy = () => {
    if (!activeText) return
    navigator.clipboard.writeText(activeText).then(() => {
      setCopied(true)
      onToast?.('Narrative copied to clipboard.', 'success')
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const handleRegenerate = async () => {
    if (regenerating) return
    setRegenerating(true)
    try {
      const res = await fetch('/api/narrative', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
      })
      if (!res.ok) throw new Error(`Server error ${res.status}`)
      const data = await res.json()
      const newNarrative = data.ai_narrative || {}
      setLocalNarrative(newNarrative)
      if (result) {
        result.ai_narrative = newNarrative
      }
      if (newNarrative.skipped_reason) {
        onToast?.(`Narrative generation skipped: ${newNarrative.skipped_reason}`, 'warning')
      } else {
        onToast?.('Narrative regenerated.', 'success')
      }
    } catch (e) {
      onToast?.(`Regeneration failed: ${e.message}`, 'error')
    } finally {
      setRegenerating(false)
    }
  }

  return (
    <div className="panel narrative-panel fade-in">
      {/* ── Header ── */}
      <div className="narrative-header">
        <div className="narrative-header-left">
          <span className="narrative-header-icon">
            <IconSparkles size={18} />
          </span>
          <div>
            <div className="narrative-header-title">AI Executive Summary</div>
            <div className="narrative-header-sub">
              Generated by <span className="narrative-model-badge">{activeModel}</span>
              {activeGeneratedAt && (
                <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>
                  · {new Date(activeGeneratedAt).toLocaleTimeString()}
                </span>
              )}
              {activeTokenUsage?.total_tokens && (
                <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>
                  · {activeTokenUsage.total_tokens.toLocaleString()} tokens
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="narrative-header-actions">
          {activeText && (
            <button
              type="button"
              className="narrative-action-btn"
              onClick={handleCopy}
              title="Copy narrative to clipboard"
            >
              {copied ? <IconCheck size={13} /> : <IconCopy size={13} />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          )}
          <button
            type="button"
            className={`narrative-action-btn${regenerating ? ' narrative-action-btn--spinning' : ''}`}
            onClick={handleRegenerate}
            disabled={regenerating}
            title="Regenerate narrative via Gemini"
          >
            <IconRefresh size={13} className={regenerating ? 'spinning' : ''} />
            <span>{regenerating ? 'Generating…' : 'Regenerate'}</span>
          </button>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="narrative-body">
        {regenerating && !activeText && <NarrativeSkeleton />}

        {!regenerating && !activeText && activeSkipped && (
          <div className="narrative-skipped">
            <IconAlertTriangle size={15} />
            <div>
              <div className="narrative-skipped-title">
                {activeSkipped === 'NO_API_KEY'
                  ? 'API key not configured'
                  : activeSkipped === 'API_ERROR'
                  ? 'LLM API error'
                  : `Narrative unavailable (${activeSkipped})`}
              </div>
              <div className="narrative-skipped-sub">
                {activeSkipped === 'NO_API_KEY'
                  ? 'Set GEMINI_API_KEY or GOOGLE_API_KEY in your server environment to enable AI-generated summaries.'
                  : activeErrorDetail || 'The narrative could not be generated for this analysis.'}
              </div>
              {activeSkipped === 'NO_API_KEY' && (
                <code className="narrative-env-hint">export GEMINI_API_KEY=your-key-here</code>
              )}
            </div>
          </div>
        )}

        {!regenerating && activeText && sections.map((sec, i) => (
          <div key={sec.title} className="narrative-section" style={{ animationDelay: `${i * 0.07}s` }}>
            <div
              className="narrative-section-title"
              style={{ color: SECTION_ACCENTS[sec.title] || 'var(--accent-blue)' }}
            >
              {sec.title}
            </div>
            <p className="narrative-section-body">{sec.body}</p>
          </div>
        ))}

        {regenerating && activeText && (
          <>
            {sections.map((sec, i) => (
              <div key={sec.title} className="narrative-section narrative-section--faded" style={{ animationDelay: `${i * 0.07}s` }}>
                <div className="narrative-section-title" style={{ color: SECTION_ACCENTS[sec.title] }}>
                  {sec.title}
                </div>
                <p className="narrative-section-body">{sec.body}</p>
              </div>
            ))}
            <NarrativeSkeleton />
          </>
        )}
      </div>

      {/* ── Footer disclaimer ── */}
      <div className="narrative-footer">
        <IconSparkles size={11} />
        AI-generated summary based on deterministic forensic findings. Verify all claims against raw session data.
      </div>
    </div>
  )
}
