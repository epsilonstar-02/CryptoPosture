import { useState } from 'react'
import ViolationBadge from './ViolationBadge.jsx'
import ComponentScoreChart from './ComponentScoreChart.jsx'

function scoreColor(v) {
  if (v >= 80) return '#22c55e'
  if (v >= 55) return '#eab308'
  if (v >= 30) return '#f97316'
  return '#ef4444'
}

function ScoreBars({ scores }) {
  const cs = scores || {}
  const items = [
    { label: 'TLS Ver',     key: 'tls_version' },
    { label: 'Cipher',      key: 'cipher_suite' },
    { label: 'Cert Health', key: 'cert_health' },
    { label: 'STARTTLS',    key: 'starttls_transition' },
    { label: 'Fwd Sec',     key: 'forward_secrecy' },
    { label: 'Proto',       key: 'protocol_context' },
  ]

  return (
    <div className="score-bars">
      {items.map(({ label, key }) => {
        const val = cs[key] ?? 0
        const color = scoreColor(val)
        return (
          <div key={key} className="score-bar-item">
            <div className="score-bar-label">{label}</div>
            <div className="score-bar-track">
              <div
                className="score-bar-fill"
                style={{ height: `${val}%`, background: `linear-gradient(180deg, ${color}88, ${color})` }}
              />
            </div>
            <div className="score-bar-val" style={{ color }}>{val.toFixed(0)}</div>
          </div>
        )
      })}
    </div>
  )
}

function ScoringExplanationPanel({ explanation }) {
  if (!explanation) return null
  const expl = explanation
  const caps = expl.critical_caps_applied || []
  const components = expl.components || []
  const conf = expl.overall_confidence || 'HIGH'
  const confColor = conf === 'HIGH' ? 'var(--risk-low)' : conf === 'MEDIUM' ? 'var(--risk-medium)' : 'var(--risk-critical)'

  const statusColors = {
    PASS: { color: 'var(--risk-low)', bg: 'var(--risk-low-bg)', border: 'rgba(34,197,94,0.3)' },
    DEGRADED: { color: 'var(--risk-medium)', bg: 'var(--risk-medium-bg)', border: 'rgba(234,179,8,0.3)' },
    VIOLATION: { color: 'var(--risk-critical)', bg: 'var(--risk-critical-bg)', border: 'rgba(239,68,68,0.3)' },
    INCONCLUSIVE: { color: '#60a5fa', bg: 'rgba(96,165,250,0.1)', border: 'rgba(96,165,250,0.3)' },
    NOT_APPLICABLE: { color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.1)' },
  }

  const nameMap = {
    tls_version: 'TLS Version',
    cipher_suite: 'Cipher Suite',
    cert_health: 'Certificate Health',
    starttls_transition: 'STARTTLS Transition',
    forward_secrecy: 'Forward Secrecy',
    protocol_context: 'Protocol Context',
  }

  const completeness = expl.evidence_completeness_ratio ?? 1.0
  const isRenormalized = completeness > 0 && completeness < 0.999
  const renormScore = expl.renormalized_quality_score ?? expl.quality_score ?? expl.final_score
  const rawQuality = expl.quality_score ?? renormScore
  const finalScore = expl.final_score ?? renormScore
  const assessedCount = expl.assessed_component_count ?? components.filter(c => ['PASS', 'DEGRADED', 'VIOLATION'].includes(c.assessment)).length

  return (
    <div style={{
      background: 'var(--bg-panel)',
      border: '1px solid var(--border-dim)',
      borderRadius: 8,
      padding: '16px 18px',
      marginBottom: 16,
    }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Cryptographic Posture Scoring Engine (Evidence-Aware Audit)
          </span>
          <span style={{
            fontSize: '0.65rem',
            padding: '2px 6px',
            borderRadius: 4,
            background: 'rgba(61,216,232,0.1)',
            color: 'var(--accent-blue)',
            fontFamily: 'var(--font-mono)',
          }}>
            {expl.policy_id} v{expl.policy_version}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{
            fontSize: '0.65rem',
            padding: '2px 8px',
            borderRadius: 4,
            background: completeness >= 0.8 ? 'rgba(34,197,94,0.1)' : 'rgba(234,179,8,0.1)',
            color: completeness >= 0.8 ? 'var(--risk-low)' : 'var(--risk-medium)',
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            border: `1px solid ${completeness >= 0.8 ? 'rgba(34,197,94,0.25)' : 'rgba(234,179,8,0.25)'}`,
          }}>
            {(completeness * 100).toFixed(0)}% EVIDENCE ASSESSED ({assessedCount}/6 DIMENSIONS)
          </span>
          <div style={{ fontSize: '0.72rem', color: confColor, fontWeight: 600 }}>
            Confidence: <strong>{conf}</strong>
          </div>
        </div>
      </div>

      {/* Step-by-Step Scoring Reconciliation Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
        gap: 8,
        background: 'rgba(0,0,0,0.25)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 6,
        padding: '10px 12px',
        marginBottom: 14,
        fontSize: '0.72rem',
      }}>
        <div>
          <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.62rem', letterSpacing: '0.05em' }}>
            1. Raw Base Sum
          </span>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
            {rawQuality?.toFixed(1)} <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.64rem', color: 'var(--text-muted)' }}>Static policy weights sum</div>
        </div>

        <div>
          <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.62rem', letterSpacing: '0.05em' }}>
            2. Renormalized Quality Score
          </span>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 700, color: isRenormalized ? 'var(--accent-cyan)' : 'var(--text-primary)', marginTop: 2 }}>
            {renormScore?.toFixed(1)} <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.64rem', color: isRenormalized ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
            {isRenormalized ? `Dynamic scaled over ${assessedCount} assessed` : 'Full 100% evidence coverage'}
          </div>
        </div>

        <div>
          <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.62rem', letterSpacing: '0.05em' }}>
            3. Critical Floor / Cap
          </span>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.88rem',
            fontWeight: 700,
            color: caps.length > 0 ? 'var(--risk-critical)' : 'var(--risk-low)',
            marginTop: 2,
          }}>
            {caps.length > 0 ? `CAPPED @ ${Math.min(...caps.map(c => c.cap_value)).toFixed(1)}` : 'NONE APPLIED'}
          </div>
          <div style={{ fontSize: '0.64rem', color: 'var(--text-muted)' }}>
            {caps.length > 0 ? `${caps[0].finding}` : 'Non-punitive; no severe breach'}
          </div>
        </div>

        <div>
          <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.62rem', letterSpacing: '0.05em' }}>
            4. Final Posture Index
          </span>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.88rem',
            fontWeight: 800,
            color: finalScore >= 80 ? 'var(--risk-low)' : finalScore >= 55 ? 'var(--risk-medium)' : finalScore >= 30 ? 'var(--risk-high)' : 'var(--risk-critical)',
            marginTop: 2,
          }}>
            {finalScore?.toFixed(1)} <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>/ 100 · {expl.risk_tier}</span>
          </div>
          <div style={{ fontSize: '0.64rem', color: 'var(--text-muted)' }}>min(QualityScore, CriticalCap)</div>
        </div>
      </div>

      {/* Evidence Note Banner if incomplete */}
      {expl.evidence_note && (
        <div style={{
          background: isRenormalized ? 'rgba(61,216,232,0.06)' : 'rgba(255,255,255,0.02)',
          borderLeft: `3px solid ${isRenormalized ? 'var(--accent-cyan)' : 'var(--accent-blue)'}`,
          borderRadius: 4,
          padding: '8px 12px',
          marginBottom: 12,
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
        }}>
          <strong style={{ color: isRenormalized ? 'var(--accent-cyan)' : 'var(--accent-blue)' }}>Evidence Completeness Rationale:</strong> {expl.evidence_note}
        </div>
      )}

      {/* Critical Caps Banner */}
      {caps.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          {caps.map((cap, idx) => (
            <div key={idx} style={{
              background: 'rgba(239,68,68,0.12)',
              borderLeft: '4px solid var(--risk-critical)',
              borderRadius: 4,
              padding: '8px 12px',
              marginBottom: 6,
              fontSize: '0.76rem',
            }}>
              <div style={{ color: 'var(--risk-critical)', fontWeight: 700 }}>
                ⚠ CRITICAL SCORE CEILING: Capped at {cap.cap_value?.toFixed(1)}/100
              </div>
              <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>
                <strong>{cap.finding}</strong> — {cap.reason}
              </div>
              {cap.reference && (
                <div style={{ color: 'var(--accent-cyan)', fontSize: '0.7rem', marginTop: 2 }}>
                  Standard reference: {cap.reference}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Component Dimensions Breakdown */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {components.map((c, i) => {
          const style = statusColors[c.assessment] || statusColors.PASS
          const isAssessed = ['PASS', 'DEGRADED', 'VIOLATION'].includes(c.assessment)
          const baseWeight = c.weight
          const effectiveWeight = c.effective_weight ?? (isAssessed && completeness > 0 ? (c.weight / completeness) : 0)
          const effectiveContrib = c.effective_contribution ?? (c.component_score * effectiveWeight)
          const isWeightAdjusted = isAssessed && Math.abs(effectiveWeight - baseWeight) > 0.001

          return (
            <div key={i} style={{
              display: 'flex',
              flexDirection: 'column',
              padding: '10px 12px',
              background: 'rgba(255,255,255,0.02)',
              borderRadius: 6,
              border: '1px solid rgba(255,255,255,0.04)',
              fontSize: '0.75rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4, flexWrap: 'wrap', gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {nameMap[c.component] || c.component}
                  </span>
                  <span style={{
                    padding: '1px 6px',
                    borderRadius: 3,
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    background: style.bg,
                    color: style.color,
                    border: `1px solid ${style.border}`,
                  }}>
                    {c.assessment}
                  </span>
                </div>

                {/* Mathematical Formula Representation */}
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                  {isAssessed ? (
                    <>
                      <span style={{ color: 'var(--text-muted)' }}>
                        {c.component_score?.toFixed(0)} ×&nbsp;
                        {isWeightAdjusted ? (
                          <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }} title={`Renormalized from base ${(baseWeight * 100).toFixed(0)}% due to ${(completeness * 100).toFixed(0)}% evidence completeness`}>
                            {(effectiveWeight * 100).toFixed(1)}% <small style={{ color: 'var(--text-muted)' }}>(base {(baseWeight * 100).toFixed(0)}%)</small>
                          </span>
                        ) : (
                          <span>{(baseWeight * 100).toFixed(0)}%</span>
                        )}
                        &nbsp;=
                      </span>
                      <strong style={{ color: 'var(--text-primary)' }}>
                        +{effectiveContrib?.toFixed(1)}
                      </strong>
                    </>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>
                      0.0 <span style={{ color: '#60a5fa' }}>(base {(baseWeight * 100).toFixed(0)}% excluded from score)</span>
                    </span>
                  )}
                </div>
              </div>

              <div style={{ color: 'var(--text-secondary)', fontSize: '0.72rem', marginTop: 2 }}>
                <span style={{ color: 'var(--text-muted)' }}>Observed:</span> <code style={{ color: 'var(--accent-cyan)' }}>{c.observed}</code> — {c.reason}
              </div>

              {c.references && c.references.length > 0 && (
                <div style={{ color: 'var(--accent-blue)', fontSize: '0.68rem', marginTop: 2 }}>
                  Standard basis: {c.references.join(', ')}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function CertificateChainPanel({ certChain, leafCert }) {
  const chain = (certChain && certChain.length > 0) ? certChain : (leafCert?.subject_cn ? [leafCert] : [])
  if (chain.length === 0) {
    return (
      <div className="empty-subpanel">
        No X.509 certificate data present in this session.
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          X.509 Certificate Hierarchy ({chain.length} Certificates in Chain)
        </span>
        <span style={{
          fontSize: '0.65rem',
          fontFamily: 'var(--font-mono)',
          color: 'var(--accent-violet)',
          background: 'rgba(109,124,255,0.1)',
          padding: '2px 8px',
          borderRadius: 4,
          border: '1px solid rgba(109,124,255,0.25)',
        }}>
          {chain.length > 1 ? 'Full Trust Path' : 'Single Leaf Cert'}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {chain.map((c, i) => {
          const isLeaf = i === 0
          const role = isLeaf ? 'End-Entity (Leaf Certificate)' : (i === chain.length - 1 && chain.length > 1) ? 'Root Certificate Authority' : `Intermediate CA #${i}`
          const valColor = c.validity === 'Valid' ? 'var(--risk-low)' : c.validity === 'Expired' ? 'var(--risk-critical)' : 'var(--risk-medium)'

          return (
            <div key={i} style={{
              background: 'var(--bg-panel)',
              border: '1px solid var(--border-dim)',
              borderRadius: 8,
              padding: '12px 14px',
              fontSize: '0.74rem',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, flexWrap: 'wrap', gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{
                    fontWeight: 700,
                    color: isLeaf ? 'var(--accent-cyan)' : 'var(--accent-violet)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                    background: isLeaf ? 'rgba(61,216,232,0.1)' : 'rgba(109,124,255,0.1)',
                    padding: '2px 6px',
                    borderRadius: 4,
                  }}>
                    {role}
                  </span>
                  <strong style={{ color: 'var(--text-primary)' }}>{c.subject_cn || 'Unknown Subject'}</strong>
                </div>
                <span style={{
                  fontSize: '0.62rem',
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: `${valColor}18`,
                  color: valColor,
                  fontWeight: 700,
                  border: `1px solid ${valColor}44`,
                }}>
                  {c.validity || 'Unknown'}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 8, color: 'var(--text-secondary)', fontSize: '0.7rem' }}>
                <div>Issuer: <span style={{ color: 'var(--text-primary)' }}>{c.issuer_cn || '—'}</span></div>
                <div>Key: <span style={{ color: c.key_length_bits >= 2048 ? 'var(--risk-low)' : 'var(--risk-critical)', fontWeight: 600 }}>{c.key_length_bits ? `${c.key_length_bits} bits` : '—'}</span></div>
                <div>Signature: <span style={{ color: /sha1/i.test(c.signature_algorithm || '') ? 'var(--risk-critical)' : 'var(--text-primary)', fontWeight: /sha1/i.test(c.signature_algorithm || '') ? 700 : 400 }}>{c.signature_algorithm || '—'}</span></div>
                <div>Expires: <span style={{ color: 'var(--text-primary)' }}>{c.not_after ? c.not_after.slice(0, 10) : '—'}</span></div>
                {c.sha256_fingerprint && (
                  <div style={{ gridColumn: '1 / -1', fontFamily: 'var(--font-mono)', fontSize: '0.64rem', color: 'var(--text-muted)' }}>
                    SHA-256: <span style={{ color: 'var(--accent-blue)' }}>{c.sha256_fingerprint}</span>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ForensicLineageView({ session }) {
  const facts = session?.facts || {}
  const stages = session?.stage_results || {}
  const stageKeys = Object.keys(stages)

  const stageStatusColors = {
    PASS: { color: 'var(--risk-low)', bg: 'rgba(34,197,94,0.12)' },
    COMPLETED: { color: 'var(--risk-low)', bg: 'rgba(34,197,94,0.12)' },
    WARNING: { color: 'var(--risk-medium)', bg: 'rgba(234,179,8,0.12)' },
    ERROR: { color: 'var(--risk-critical)', bg: 'rgba(239,68,68,0.12)' },
    INCONCLUSIVE: { color: 'var(--accent-blue)', bg: 'rgba(61,216,232,0.12)' },
    SKIPPED: { color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)' },
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
        <span style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Forensic Evidence Lineage & Flow Reconstruction Records
        </span>
        <span style={{
          fontSize: '0.65rem',
          padding: '2px 8px',
          borderRadius: 4,
          background: 'rgba(61,216,232,0.1)',
          color: 'var(--accent-blue)',
          fontFamily: 'var(--font-mono)',
        }}>
          Flow ID: {session?.flow_id || session?.session_id || '—'}
        </span>
      </div>

      {/* Stage verification list */}
      {stageKeys.length > 0 && (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, fontSize: '0.72rem' }}>
            Pipeline Stage Verification Records
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
            {stageKeys.map((k) => {
              const s = stages[k]
              const status = (s.status || 'COMPLETED').toUpperCase()
              const style = stageStatusColors[status] || stageStatusColors.COMPLETED
              return (
                <div key={k} style={{
                  padding: '10px 12px',
                  borderRadius: 6,
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 12,
                  minWidth: 0,
                  overflow: 'hidden',
                }}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                      fontSize: '0.74rem',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }} title={s.stage_name || k}>
                      {s.stage_name || k}
                    </div>
                    {s.diagnostics && s.diagnostics.length > 0 && (
                      <div style={{
                        color: 'var(--risk-medium)',
                        fontSize: '0.66rem',
                        marginTop: 4,
                        lineHeight: 1.35,
                        wordBreak: 'break-word',
                      }} title={s.diagnostics[0]}>
                        {s.diagnostics[0]}
                      </div>
                    )}
                  </div>
                  <span style={{
                    fontSize: '0.62rem',
                    fontFamily: 'var(--font-mono)',
                    padding: '2px 6px',
                    borderRadius: 3,
                    background: style.bg,
                    color: style.color,
                    fontWeight: 700,
                    flexShrink: 0,
                    whiteSpace: 'nowrap',
                  }}>
                    {status}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Structured facts breakdown */}
      {Object.keys(facts).length > 0 && (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6, fontSize: '0.72rem' }}>
            Reconstructed Forensic Lineage Facts (Normalized Session Object)
          </div>
          <pre style={{
            background: 'rgba(0,0,0,0.5)',
            border: '1px solid var(--border-dim)',
            borderRadius: 6,
            padding: 12,
            fontSize: '0.68rem',
            color: 'var(--accent-blue)',
            overflowX: 'auto',
            maxHeight: 260,
          }}>
            {JSON.stringify(facts, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function DetailRow({ label, value, valueClass }) {
  return (
    <div className="detail-row">
      <span className="detail-key">{label}</span>
      <span className={`detail-val ${valueClass || ''}`}>{value || '—'}</span>
    </div>
  )
}

function SectionLabel({ children }) {
  return (
    <div style={{
      fontSize: '0.6rem',
      fontWeight: 700,
      letterSpacing: '0.12em',
      textTransform: 'uppercase',
      color: 'var(--text-muted)',
      marginBottom: 10,
      display: 'flex',
      alignItems: 'center',
      gap: 7,
    }}>
      <span style={{
        width: 12, height: 12,
        borderRadius: 2,
        background: 'rgba(61,216,232,0.15)',
        border: '1px solid rgba(61,216,232,0.3)',
        display: 'inline-block',
        flexShrink: 0,
      }} />
      {children}
    </div>
  )
}

export default function SessionDetail({ session }) {
  const [activeSubTab, setActiveSubTab] = useState('crypto')
  const [openEvidence, setOpenEvidence] = useState({})
  if (!session) return null

  const s = session
  const cert = s.cert || {}
  const fp = s.fingerprints || {}
  const ml = s.ml_anomaly || {}
  const violations = s.violations || []
  const cs = s.component_scores || {}
  const features = ml.unusual_characteristics || ml.top_features || {}
  const chainLength = (s.cert_chain && s.cert_chain.length > 0) ? s.cert_chain.length : (cert.subject_cn ? 1 : 0)

  const certValColor = cert.validity === 'Valid' ? 'detail-val--green'
    : cert.validity === 'Expired' ? 'detail-val--red'
    : 'detail-val--yellow'

  const tlsVerColor = (v) => {
    if (!v) return 'detail-val--dim'
    if (v === 'TLS1.3') return 'detail-val--green'
    if (v === 'TLS1.2') return 'detail-val--blue'
    return 'detail-val--red'
  }

  const channelColor = (c) => {
    if (c === 'Plaintext') return 'detail-val--red'
    if (c === 'STARTTLS') return 'detail-val--yellow'
    if (c === 'Implicit TLS') return 'detail-val--green'
    return ''
  }

  const pqcLabel = s.pqc_state === 2
    ? 'Hybrid PQC (Negotiated)'
    : s.pqc_state === 1
    ? 'PQC Offered (Classical)'
    : 'Classical Only'

  const maxFeatureVal = Math.max(...Object.values(features).map((v) => Math.abs(Number(v))), 1)

  const toggleEvidence = (idx) => {
    setOpenEvidence((prev) => ({ ...prev, [idx]: !prev[idx] }))
  }

  return (
    <div className="session-detail-inner fade-in">
      {/* ── Cross-Stage Validation Warning ── */}
      {((s.validation_warnings && s.validation_warnings.length > 0) || (s.validation_status && s.validation_status !== 'VALID')) && (
        <div style={{
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 8,
          padding: '10px 14px',
          marginBottom: 14,
          fontSize: '0.76rem',
        }}>
          <div style={{ color: 'var(--risk-critical)', fontWeight: 700, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>⚠ Cross-Stage Protocol Semantic Discrepancy</span>
            <span style={{ fontSize: '0.64rem', fontFamily: 'var(--font-mono)', padding: '1px 5px', borderRadius: 3, background: 'rgba(239,68,68,0.2)' }}>
              {s.validation_status || 'WARNING'}
            </span>
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-secondary)' }}>
            {(s.validation_warnings || []).map((w, idx) => (
              <li key={idx} style={{ marginTop: 2 }}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Sub-Tab Segment Control ── */}
      <div className="subtab-bar">
        <button
          type="button"
          className={`subtab-btn${activeSubTab === 'crypto' ? ' subtab-btn--active' : ''}`}
          onClick={() => setActiveSubTab('crypto')}
        >
          🔐 Parameters & Crypto
        </button>

        <button
          type="button"
          className={`subtab-btn${activeSubTab === 'scoring' ? ' subtab-btn--active' : ''}`}
          onClick={() => setActiveSubTab('scoring')}
        >
          ⚖ Scoring Audit ({s.posture_score?.toFixed(0)})
        </button>

        <button
          type="button"
          className={`subtab-btn${activeSubTab === 'violations' ? ' subtab-btn--active' : ''}`}
          onClick={() => setActiveSubTab('violations')}
        >
          🚨 Violations ({violations.length})
        </button>

        {chainLength > 0 && (
          <button
            type="button"
            className={`subtab-btn${activeSubTab === 'certs' ? ' subtab-btn--active' : ''}`}
            onClick={() => setActiveSubTab('certs')}
          >
            📜 Cert Chain ({chainLength})
          </button>
        )}

        <button
          type="button"
          className={`subtab-btn${activeSubTab === 'ml' ? ' subtab-btn--active' : ''}`}
          onClick={() => setActiveSubTab('ml')}
        >
          ⚡ ML Outlier {ml.is_anomalous && '(!)'}
        </button>

        <button
          type="button"
          className={`subtab-btn${activeSubTab === 'lineage' ? ' subtab-btn--active' : ''}`}
          onClick={() => setActiveSubTab('lineage')}
        >
          🧬 Lineage & Stages
        </button>
      </div>

      {/* ── Sub-Tab Content ── */}
      <div className="subtab-content">
        {/* TAB 1: Parameters & Crypto */}
        {activeSubTab === 'crypto' && (
          <div className="session-detail-grid fade-in">
            {/* TLS Parameters */}
            <div className="detail-card">
              <div className="detail-card-title">
                <span className="detail-card-title-dot" />
                TLS Parameters
              </div>
              <DetailRow label="Channel"         value={s.channel_type}    valueClass={channelColor(s.channel_type)} />
              <DetailRow label="STARTTLS Status" value={s.starttls_status} valueClass={s.starttls_status === 'Stripped' ? 'detail-val--red' : ''} />
              <DetailRow label="TLS Version"     value={s.tls_version}     valueClass={tlsVerColor(s.tls_version)} />
              <DetailRow label="Cipher Suite"    value={s.cipher_suite ? s.cipher_suite.slice(0, 34) : null} />
              <DetailRow label="Key Exchange"    value={s.key_exchange}    valueClass={s.key_exchange === 'ECDHE' ? 'detail-val--green' : s.key_exchange === 'RSA' ? 'detail-val--yellow' : ''} />
              <DetailRow label="SNI"             value={s.sni}             valueClass="detail-val--blue" />
              <DetailRow label="Protocol"        value={s.protocol} />
              <DetailRow label="Flow"            value={`${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}`} />
            </div>

            {/* Certificate Summary */}
            <div className="detail-card">
              <div className="detail-card-title">
                <span className="detail-card-title-dot" style={{ background: 'var(--accent-violet)', boxShadow: '0 0 6px var(--accent-violet)' }} />
                X.509 Certificate
              </div>
              <DetailRow label="Validity"   value={cert.validity}            valueClass={certValColor} />
              <DetailRow label="Key Size"   value={cert.key_length_bits ? `${cert.key_length_bits} bits` : null}
                         valueClass={cert.key_length_bits >= 2048 ? 'detail-val--green' : 'detail-val--red'} />
              <DetailRow label="Sig Algo"   value={cert.signature_algorithm} valueClass={/sha1/i.test(cert.signature_algorithm || '') ? 'detail-val--red' : ''} />
              <DetailRow label="Subject CN" value={cert.subject_cn} />
              <DetailRow label="Issuer CN"  value={cert.issuer_cn} />
              <DetailRow label="Not After"  value={cert.not_after ? cert.not_after.slice(0, 10) : null}
                         valueClass={cert.validity === 'Expired' ? 'detail-val--red' : 'detail-val--green'} />
              <DetailRow label="Self-Signed" value={cert.is_self_signed ? 'YES ⚠' : 'No'}
                         valueClass={cert.is_self_signed ? 'detail-val--red' : 'detail-val--green'} />
              <DetailRow label="Pre-TLS Bytes" value={s.bytes_pre_tls > 0 ? `${s.bytes_pre_tls} B` : '0'} valueClass={s.bytes_pre_tls > 0 ? 'detail-val--yellow' : 'detail-val--green'} />
            </div>

            {/* Fingerprints & ML */}
            <div className="detail-card">
              <div className="detail-card-title">
                <span className="detail-card-title-dot" style={{ background: 'var(--accent-green)', boxShadow: '0 0 6px var(--accent-green)' }} />
                Fingerprints & ML
              </div>
              <DetailRow label="JA4"    value={fp.ja4}  valueClass="detail-val--blue" />
              <DetailRow label="JA4S"   value={fp.ja4s} valueClass="detail-val--blue" />
              <DetailRow label="JA4X"   value={fp.ja4x} valueClass="detail-val--blue" />
              <DetailRow label="Capture Outlier" value={ml.is_anomalous ? '⚡ YES' : (ml.status === 'INSUFFICIENT_BASELINE' ? '<5 SESSIONS' : 'No')} valueClass={ml.is_anomalous ? 'detail-val--red' : 'detail-val--green'} />
              <DetailRow label="Liu Anomaly Score" value={ml.anomaly_score != null ? ml.anomaly_score.toFixed(4) : (ml.status === 'INSUFFICIENT_BASELINE' ? '— (<5 baseline)' : '—')} />
              <DetailRow label="Buffer Inject" value={s.buffer_injection_detected ? '⚠ DETECTED' : 'No'} valueClass={s.buffer_injection_detected ? 'detail-val--red' : 'detail-val--green'} />
              <DetailRow label="PQC State"     value={pqcLabel} valueClass={s.pqc_state === 2 ? 'detail-val--green' : s.pqc_state === 1 ? 'detail-val--blue' : ''} />
              <DetailRow label="Packets"       value={s.packet_count} />
            </div>
          </div>
        )}

        {/* TAB 2: Scoring Audit */}
        {activeSubTab === 'scoring' && (
          <div className="fade-in">
            <div style={{ marginBottom: 16 }}>
              <SectionLabel>Component Score Radar & Health Distribution</SectionLabel>
              <div className="chart-section">
                <ComponentScoreChart scores={cs} />
                <div style={{ flex: 1 }}>
                  <ScoreBars scores={cs} />
                </div>
              </div>
            </div>

            {s.scoring_explanation && (
              <ScoringExplanationPanel explanation={s.scoring_explanation} />
            )}
          </div>
        )}

        {/* TAB 3: Violations */}
        {activeSubTab === 'violations' && (
          <div className="fade-in">
            {violations.length === 0 ? (
              <div style={{ padding: '14px 18px', background: 'var(--risk-low-bg)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 6, fontSize: '0.8rem', color: 'var(--risk-low)' }}>
                ✅ <strong>Compliant Session:</strong> Zero policy violations detected. This flow satisfies all RFC and NIST baseline mandates.
              </div>
            ) : (
              <div className="violations-list">
                {violations.map((v, i) => {
                  const hasEvidence = v.evidence && Object.keys(v.evidence).length > 0
                  const isEvOpen = openEvidence[i]

                  return (
                    <div key={i} className={`violation-item violation-item--${v.severity}`}>
                      <div className="violation-accent" />
                      <div className="violation-inner">
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                          <ViolationBadge severity={v.severity} />
                          <div className="violation-body" style={{ flex: 1 }}>
                            <div className="violation-desc">
                              <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-primary)' }}>
                                [{v.code}]
                              </strong>
                              {v.mandate_level && (
                                <span style={{
                                  marginLeft: 6,
                                  fontSize: '0.6rem',
                                  fontFamily: 'var(--font-mono)',
                                  padding: '1px 5px',
                                  borderRadius: 3,
                                  background: v.mandate_level.includes('MUST') ? 'rgba(239,68,68,0.15)' : 'rgba(234,179,8,0.15)',
                                  color: v.mandate_level.includes('MUST') ? 'var(--risk-critical)' : 'var(--risk-medium)',
                                  border: `1px solid ${v.mandate_level.includes('MUST') ? 'rgba(239,68,68,0.3)' : 'rgba(234,179,8,0.3)'}`,
                                }}>
                                  {v.mandate_level}
                                </span>
                              )}
                              {v.category && (
                                <span style={{ marginLeft: 6, fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                                  · {v.category}
                                </span>
                              )}
                              <div style={{ marginTop: 3 }}>{v.description}</div>
                            </div>

                            {v.remediation && (
                              <div style={{
                                marginTop: 6,
                                padding: '6px 10px',
                                borderRadius: 4,
                                background: 'rgba(61,216,232,0.05)',
                                borderLeft: '3px solid var(--accent-cyan)',
                                fontSize: '0.7rem',
                                color: 'var(--text-primary)',
                              }}>
                                <strong style={{ color: 'var(--accent-cyan)' }}>Remediation:</strong> {v.remediation}
                              </div>
                            )}

                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 6, flexWrap: 'wrap', gap: 8 }}>
                              {v.reference && (
                                <div className="violation-ref">
                                  Ref:&nbsp;
                                  {v.reference.startsWith('http') ? (
                                    <a href={v.reference} target="_blank" rel="noopener noreferrer">{v.reference}</a>
                                  ) : v.reference}
                                </div>
                              )}

                              {hasEvidence && (
                                <button
                                  type="button"
                                  onClick={() => toggleEvidence(i)}
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    color: 'var(--accent-blue)',
                                    fontSize: '0.68rem',
                                    cursor: 'pointer',
                                    padding: 0,
                                    textDecoration: 'underline',
                                  }}
                                >
                                  {isEvOpen ? 'Hide observed evidence' : 'Inspect observed evidence →'}
                                </button>
                              )}
                            </div>

                            {hasEvidence && isEvOpen && (
                              <div style={{
                                marginTop: 8,
                                padding: 8,
                                background: 'rgba(0,0,0,0.3)',
                                borderRadius: 4,
                                border: '1px solid rgba(255,255,255,0.06)',
                                fontSize: '0.68rem',
                                fontFamily: 'var(--font-mono)',
                              }}>
                                {v.evidence.observed && (
                                  <div><span style={{ color: 'var(--text-muted)' }}>Observed:</span> <span style={{ color: 'var(--risk-critical)' }}>{String(v.evidence.observed)}</span></div>
                                )}
                                {v.evidence.expected && (
                                  <div><span style={{ color: 'var(--text-muted)' }}>Expected:</span> <span style={{ color: 'var(--risk-low)' }}>{String(v.evidence.expected)}</span></div>
                                )}
                                {v.evidence.details && (
                                  <div><span style={{ color: 'var(--text-muted)' }}>Details:</span> {String(v.evidence.details)}</div>
                                )}
                                {v.evidence.stream_id && (
                                  <div><span style={{ color: 'var(--text-muted)' }}>Stream:</span> {String(v.evidence.stream_id)}</div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 4: Cert Chain */}
        {activeSubTab === 'certs' && (
          <div className="fade-in">
            <CertificateChainPanel certChain={s.cert_chain} leafCert={cert} />
          </div>
        )}

        {/* TAB 5: ML Outlier */}
        {activeSubTab === 'ml' && (
          <div className="fade-in">
            {ml.status === 'INSUFFICIENT_BASELINE' && (
              <div style={{
                padding: '12px 16px',
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 6,
                fontSize: '0.74rem',
                color: 'var(--text-secondary)',
                marginBottom: 16,
              }}>
                ℹ️ <strong>Unsupervised Outlier Detection Baseline:</strong> Capture contains fewer than 5 sessions. Capture-relative Isolation Forest anomaly scoring was skipped to prevent unrepresentative false alarms on small sample sizes.
              </div>
            )}

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: 12,
              marginBottom: 16,
            }}>
              <div style={{ background: 'var(--bg-panel)', padding: 12, borderRadius: 6, border: '1px solid var(--border-dim)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem', textTransform: 'uppercase' }}>Liu Anomaly Outlier Status</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: ml.is_anomalous ? 'var(--risk-critical)' : 'var(--risk-low)', marginTop: 4 }}>
                  {ml.is_anomalous ? '⚡ ANOMALOUS OUTLIER' : 'NORMAL BEHAVIOR'}
                </div>
              </div>

              <div style={{ background: 'var(--bg-panel)', padding: 12, borderRadius: 6, border: '1px solid var(--border-dim)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem', textTransform: 'uppercase' }}>Isolation Forest Score</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                  {ml.anomaly_score != null ? ml.anomaly_score.toFixed(4) : '—'}
                </div>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Threshold &ge; 0.65 indicates anomaly</div>
              </div>

              <div style={{ background: 'var(--bg-panel)', padding: 12, borderRadius: 6, border: '1px solid var(--border-dim)' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem', textTransform: 'uppercase' }}>Contamination Target</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                  0.10 (10%)
                </div>
              </div>
            </div>

            {Object.keys(features).length > 0 && (
              <div>
                <SectionLabel>Statistical Divergence (Z-Score Relative to Capture Population)</SectionLabel>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
                  Descriptive feature variance relative to peer sessions in this capture. Higher deviations identify the statistical characteristics causing isolation.
                </div>
                <table className="ml-table">
                  <thead>
                    <tr><th>Feature</th><th>Z-Score</th><th>Deviation</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(features).map(([feat, val]) => {
                      const abs = Math.abs(Number(val))
                      const barColor = abs > 2 ? 'var(--risk-critical)' : abs > 1 ? 'var(--risk-high)' : 'var(--text-secondary)'
                      const pct = Math.min((abs / maxFeatureVal) * 100, 100)
                      return (
                        <tr key={feat}>
                          <td>{feat}</td>
                          <td style={{ color: barColor }}>
                            {typeof val === 'number' ? val.toFixed(4) : val}
                          </td>
                          <td>
                            <div className="ml-bar-wrap">
                              <div className="ml-bar-track">
                                <div className="ml-bar-fill" style={{ width: `${pct}%`, background: barColor }} />
                              </div>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TAB 6: Lineage & Stages */}
        {activeSubTab === 'lineage' && (
          <div className="fade-in">
            <ForensicLineageView session={s} />
          </div>
        )}
      </div>
    </div>
  )
}
