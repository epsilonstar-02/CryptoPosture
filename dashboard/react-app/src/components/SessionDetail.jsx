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
  if (!session) return null
  const s    = session
  const cert = s.cert || {}
  const fp   = s.fingerprints || {}
  const ml   = s.ml_anomaly || {}
  const violations = s.violations || []
  const cs   = s.component_scores || {}
  const features = ml.top_features || {}

  const certValColor = cert.validity === 'Valid'   ? 'detail-val--green'
    : cert.validity === 'Expired' ? 'detail-val--red'
    : 'detail-val--yellow'

  const tlsVerColor = (v) => {
    if (!v)              return 'detail-val--dim'
    if (v === 'TLS1.3')  return 'detail-val--green'
    if (v === 'TLS1.2')  return 'detail-val--blue'
    return 'detail-val--red'
  }

  const channelColor = (c) => {
    if (c === 'Plaintext')    return 'detail-val--red'
    if (c === 'STARTTLS')     return 'detail-val--yellow'
    if (c === 'Implicit TLS') return 'detail-val--green'
    return ''
  }

  const maxFeatureVal = Math.max(...Object.values(features).map(v => Math.abs(Number(v))), 1)

  return (
    <div className="session-detail-inner">
      {/* 3-col grid */}
      <div className="session-detail-grid">
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

        {/* Certificate */}
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
          <DetailRow label="ML Anomaly"    value={ml.is_anomalous ? '⚡ YES' : 'No'}   valueClass={ml.is_anomalous ? 'detail-val--red' : 'detail-val--green'} />
          <DetailRow label="Anomaly Score" value={ml.anomaly_score != null ? ml.anomaly_score.toFixed(4) : null} />
          <DetailRow label="Buffer Inject" value={s.buffer_injection_detected ? '⚠ DETECTED' : 'No'} valueClass={s.buffer_injection_detected ? 'detail-val--red' : 'detail-val--green'} />
          <DetailRow label="PQC State"     value={['Classical', 'PQC Offered', 'Hybrid PQC'][s.pqc_state] || 'Classical'} />
          <DetailRow label="Packets"       value={s.packet_count} />
        </div>
      </div>

      {/* Score visualization */}
      <div style={{ marginBottom: 16 }}>
        <SectionLabel>Component Score Breakdown</SectionLabel>
        <div className="chart-section">
          <ComponentScoreChart scores={cs} />
          <div style={{ flex: 1 }}>
            <ScoreBars scores={cs} />
          </div>
        </div>
      </div>

      {/* Violations */}
      <div style={{ marginBottom: ml.is_anomalous ? 16 : 0 }}>
        <SectionLabel>
          Violations&nbsp;
          <span style={{ color: violations.length > 0 ? 'var(--risk-critical)' : 'var(--accent-green)', fontVariantNumeric: 'tabular-nums' }}>
            ({violations.length})
          </span>
        </SectionLabel>
        {violations.length === 0 ? (
          <div style={{ padding: '10px 14px', background: 'var(--risk-low-bg)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 6, fontSize: '0.76rem', color: 'var(--risk-low)' }}>
            ✅ No violations detected for this session.
          </div>
        ) : (
          <div className="violations-list">
            {violations.map((v, i) => (
              <div key={i} className={`violation-item violation-item--${v.severity}`}>
                <div className="violation-accent" />
                <div className="violation-inner">
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    <ViolationBadge severity={v.severity} />
                    <div className="violation-body">
                      <div className="violation-desc">
                        <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>[{v.code}]</strong>
                        {' '}{v.description}
                      </div>
                      {v.reference && (
                        <div className="violation-ref">
                          Ref:&nbsp;
                          {v.reference.startsWith('http') ? (
                            <a href={v.reference} target="_blank" rel="noopener noreferrer">{v.reference}</a>
                          ) : v.reference}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ML Feature Drivers */}
      {ml.is_anomalous && Object.keys(features).length > 0 && (
        <div>
          <SectionLabel>ML Anomaly Feature Drivers</SectionLabel>
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
  )
}
