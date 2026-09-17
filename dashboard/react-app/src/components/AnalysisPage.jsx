import { useState, useCallback } from 'react'
import PostureGauge from './PostureGauge.jsx'
import RiskMatrix from './RiskMatrix.jsx'
import SessionTable from './SessionTable.jsx'
import FindingsExplorer from './FindingsExplorer.jsx'
import EvidenceProvenancePanel from './EvidenceProvenancePanel.jsx'
import ExportPanel, { buildHTMLReport } from './ExportPanel.jsx'
import AINarrativePanel from './AINarrativePanel.jsx'
import AnalystTriagePanel from './AnalystTriagePanel.jsx'

function getTierClass(tier) {
  if (tier === 'CRITICAL') return 'kpi-value--critical'
  if (tier === 'HIGH')     return 'kpi-value--high'
  if (tier === 'MEDIUM')   return 'kpi-value--medium'
  return 'kpi-value--low'
}

function getScoreClass(score) {
  if (score >= 80) return 'kpi-value--green'
  if (score >= 55) return 'kpi-value--medium'
  if (score >= 30) return 'kpi-value--high'
  return 'kpi-value--critical'
}

function EnterpriseExplanationPanel({ explanation, policy, engineVersion, schemaVersion }) {
  if (!explanation) return null
  const expl = explanation
  const sessionContribs = expl.session_contributions || []

  return (
    <div className="panel audit-panel fade-in">
      {/* ── Header ── */}
      <div className="audit-panel-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>
            Cryptographic Posture Scoring Engine &amp; Enterprise Aggregation Audit
          </span>
          <span className="policy-badge">
            {policy?.id || 'crypto-posture-v1'} v{policy?.version || '1.0'}
          </span>
          <span className="engine-sub-badge">
            Engine v{engineVersion || '1.0.0'} · Schema v{schemaVersion || '2.0'}
          </span>
        </div>
      </div>

      {/* ── Section 1: Enterprise Harmonic Mean Aggregation ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
            1. Enterprise Volume-Weighted Harmonic Aggregation
          </span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
          Individual session posture scores are aggregated into an authoritative enterprise metric using a
          volume-weighted harmonic mean. In contrast to arithmetic averaging, the harmonic mean enforces the
          <strong> Weakest-Link Principle</strong>: high-volume or critical security failures disproportionately depress
          the enterprise index and cannot be diluted by many low-risk connections.
        </p>

        <div className="audit-cards-grid">
          <div className="audit-card">
            <div className="audit-card-label">Harmonic Aggregation Formula</div>
            <div className="audit-card-formula">
              H = W_total / ∑(w_i / S_i)
            </div>
            <div className="audit-card-desc">
              Where <code>W_total = ∑ w_i</code> is cumulative byte volume, and <code>S_i</code> is the session posture score.
            </div>
          </div>

          <div className="audit-card">
            <div className="audit-card-label">Total Operational Volume</div>
            <div className="audit-card-value">
              {(expl.total_volume_bytes || 0).toLocaleString()} bytes
            </div>
            <div className="audit-card-desc">
              Reconstructed TCP payload and stream bytes serve as the proxy for network surface exposure.
            </div>
          </div>

          <div className="audit-card">
            <div className="audit-card-label">Weakest-Link Principle</div>
            <div className="audit-card-desc" style={{ marginTop: 6, fontSize: '0.82rem' }}>
              {expl.rationale || 'Penalizes critical vulnerabilities disproportionately to ensure security gaps cannot be averaged away.'}
            </div>
          </div>
        </div>

        {sessionContribs.length > 0 && (
          <div style={{ marginTop: 14 }}>
            <div style={{ fontWeight: 600, fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Per-Session Exposure Weights & Enterprise Score Contribution
            </div>
            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Flow</th>
                    <th>Protocol</th>
                    <th>Byte Volume</th>
                    <th>Traffic %</th>
                    <th>Session Score</th>
                    <th>Risk Tier</th>
                  </tr>
                </thead>
                <tbody>
                  {sessionContribs.map((c, i) => (
                    <tr key={i}>
                      <td style={{ color: 'var(--text-primary)' }}>{c.flow || c.session_id}</td>
                      <td style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{c.protocol}</td>
                      <td>{(c.byte_count || 0).toLocaleString()} B</td>
                      <td>{(c.volume_percent || 0).toFixed(1)}%</td>
                      <td style={{
                        fontWeight: 700,
                        color: c.posture_score >= 80 ? 'var(--risk-low)' : c.posture_score >= 55 ? 'var(--risk-medium)' : c.posture_score >= 30 ? 'var(--risk-high)' : 'var(--risk-critical)',
                      }}>
                        {c.posture_score?.toFixed(1)}
                      </td>
                      <td>
                        <span className={`risk-pill risk-pill--${c.risk_tier}`} style={{ fontSize: '0.62rem', padding: '2px 7px' }}>
                          {c.risk_tier}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ── Section 2: Calibrated Scoring Dimensions ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
            2. Six Calibrated Posture Dimensions (crypto-posture-v1)
          </span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
          Each reconstructed session is independently assessed across 6 calibrated cryptographic sub-domains.
          Numerical base weights sum to 100% and reflect risk prioritization established by IETF RFCs and NIST SP 800 guidelines.
        </p>

        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Dimension</th>
                <th>Base Wt (w_i)</th>
                <th>Evaluation Criteria & Scoring Rules</th>
                <th>Standards Authority</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>TLS Version</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>25%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  TLS 1.3 (100 pts) · TLS 1.2 (80 pts) · TLS 1.1 (20 pts) · TLS 1.0 / SSLv3 (0 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 9325 / RFC 8996 / NIST SP 800-52r2</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>Cipher Suite</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>20%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  AEAD (GCM / Poly1305 = 100 pts) · CBC with SHA-256 (50 pts) · 3DES (10 pts) · RC4 / NULL (0 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>NIST SP 800-52r2 §3.3.1 / RFC 9325</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>Certificate Health</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>20%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Valid PKI chain & key size ≥2048-bit RSA / ≥256-bit ECC (100 pts) · Self-Signed (70 pts) · Expired (10 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 5280 / NIST SP 800-57 Part 1</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>STARTTLS Transition</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>15%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Implicit TLS on secure ports (100 pts) · Successful STARTTLS negotiation (80 pts) · Plaintext fallback (0 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 8314 §3 / RFC 3207 / RFC 3501</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>Forward Secrecy</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>10%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  ECDHE ephemeral key exchange (100 pts) · DHE (80 pts) · Static RSA key exchange without PFS (0 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 9325 §4.2 / NIST SP 800-52r2</td>
              </tr>
              <tr>
                <td style={{ color: 'var(--text-primary)', fontWeight: 700 }}>Protocol Hygiene</td>
                <td style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>10%</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  ALPN, SNI, Extended Master Secret (100 pts) · Downgrade/stripping, buffer injection anomalies (0 pts)
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 8446 / RFC 7627 / Poddebniak et al.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 3: Evidence-Aware Dynamic Renormalization ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
            3. Evidence-Aware Dynamic Weight Renormalization
          </span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
          Traditional scoring engines penalize unobserved dimensions with 0 or assign optimistic default scores (e.g. 50%).
          CryptoPosture solves this with dynamic evidence-aware weight renormalization: unobserved or inconclusive dimensions
          receive 0% effective weight, and observed dimensions scale proportionally so that their effective weights strictly sum to 100%.
        </p>

        <div className="audit-cards-grid">
          <div className="audit-card">
            <div className="audit-card-label">Dynamic Effective Weight Formula</div>
            <div className="audit-card-formula">
              w_i^eff = w_i / ∑_(j ∈ assessed) w_j
            </div>
            <div className="audit-card-desc">
              Only dimensions with forensic proof are evaluated. Unobserved dimensions have <code>w_i^eff = 0</code>.
            </div>
          </div>

          <div className="audit-card">
            <div className="audit-card-label">Renormalized Base Score</div>
            <div className="audit-card-formula">
              S_renorm = ∑_(i ∈ assessed) w_i^eff · S_i
            </div>
            <div className="audit-card-desc">
              Maintains full 100-point scale parity regardless of whether 3, 5, or all 6 dimensions are visible.
            </div>
          </div>

          <div className="audit-card">
            <div className="audit-card-label">Evidence Provenance Guarantee</div>
            <div className="audit-card-desc" style={{ marginTop: 6, fontSize: '0.82rem' }}>
              Prevents blind penalties on non-mail flows or implicit TLS sessions where STARTTLS is intentionally absent,
              while documenting exact component coverage in forensic metadata.
            </div>
          </div>
        </div>
      </div>

      {/* ── Section 4: Non-Additive Critical Score Caps ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--risk-critical)' }}>
            4. Non-Additive Critical Score Caps (Floor & Ceiling Enforcement)
          </span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
          Subtractive penalty deductions can produce inconsistent results when compounded or diluted.
          To guarantee that catastrophic vulnerabilities cannot be masked by strong scores in other dimensions,
          the engine applies non-additive score caps:
        </p>

        <div style={{
          background: 'rgba(239, 68, 68, 0.06)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          borderRadius: 'var(--radius-md)',
          padding: '12px 16px',
          marginBottom: 14,
          fontFamily: 'var(--font-mono)',
          fontSize: '0.92rem',
          color: 'var(--text-primary)',
        }}>
          <strong>Final Session Score:</strong> <code>S_final = min(S_renorm, Cap_min)</code>
        </div>

        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Trigger Condition</th>
                <th>Cap Ceiling</th>
                <th>Forensic & Security Rationale</th>
                <th>Authority Reference</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ color: '#ff6b6b', fontWeight: 700 }}>Plaintext Mail / Cleartext Auth</td>
                <td style={{ color: 'var(--risk-critical)', fontWeight: 800 }}>Cap ≤ 0.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Total confidentiality compromise: credentials, mail content, or session tokens exposed in cleartext
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 8314 §3</td>
              </tr>
              <tr>
                <td style={{ color: '#ff6b6b', fontWeight: 700 }}>Prohibited SSLv2 / SSLv3 Active</td>
                <td style={{ color: 'var(--risk-critical)', fontWeight: 800 }}>Cap ≤ 15.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Cryptographically broken protocols vulnerable to POODLE, DROWN, and rollback attacks
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 8996</td>
              </tr>
              <tr>
                <td style={{ color: '#ff6b6b', fontWeight: 700 }}>Buffer Injection Exploit Detected</td>
                <td style={{ color: 'var(--risk-critical)', fontWeight: 800 }}>Cap ≤ 15.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Active command pipelining exploit across the cleartext/TLS boundary
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>Poddebniak et al. USENIX '21</td>
              </tr>
              <tr>
                <td style={{ color: '#ff6b6b', fontWeight: 700 }}>STARTTLS Stripping Downgrade</td>
                <td style={{ color: 'var(--risk-critical)', fontWeight: 800 }}>Cap ≤ 15.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Active MitM attack tampering with protocol capabilities to force cleartext transmission
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 3207 / RFC 8314</td>
              </tr>
              <tr>
                <td style={{ color: '#fb923c', fontWeight: 700 }}>Prohibited / Null / Export Cipher</td>
                <td style={{ color: 'var(--risk-critical)', fontWeight: 800 }}>Cap ≤ 20.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Cryptographically void encryption (RC4, 3DES, EXPORT, NULL) susceptible to plaintext recovery
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>NIST SP 800-52r2 §3.3.1</td>
              </tr>
              <tr>
                <td style={{ color: '#fbbf24', fontWeight: 700 }}>Invalid / Self-Signed / Expired Cert</td>
                <td style={{ color: 'var(--risk-medium)', fontWeight: 800 }}>Cap ≤ 60.0</td>
                <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'inherit' }}>
                  Trust chain invalidation prevents mutual authentication and opens channel to interception
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>RFC 5280 / NIST SP 800-57</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 5: Calibrated Risk Tiers ── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
            5. Calibrated Risk Tier Thresholds
          </span>
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>
          Final posture indices map to four operational risk tiers calibrated against NIST and BCP 195 compliance targets:
        </p>

        <div className="audit-cards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))' }}>
          <div className="audit-card" style={{ borderLeft: '3px solid var(--risk-low)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="risk-pill risk-pill--LOW">LOW RISK</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--risk-low)' }}>80.0 – 100.0</span>
            </div>
            <div className="audit-card-desc" style={{ marginTop: 4, fontSize: '0.80rem' }}>
              Full compliance with modern RFC 9325 & NIST SP 800-52r2 standards. AEAD ciphers, PFS, and valid PKI chain.
            </div>
          </div>

          <div className="audit-card" style={{ borderLeft: '3px solid var(--risk-medium)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="risk-pill risk-pill--MEDIUM">MEDIUM RISK</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--risk-medium)' }}>55.0 – 79.9</span>
            </div>
            <div className="audit-card-desc" style={{ marginTop: 4, fontSize: '0.80rem' }}>
              Operational encryption with minor gaps (e.g. CBC ciphers, self-signed certificates, or legacy TLS 1.2 setups).
            </div>
          </div>

          <div className="audit-card" style={{ borderLeft: '3px solid var(--risk-high)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="risk-pill risk-pill--HIGH">HIGH RISK</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--risk-high)' }}>30.0 – 54.9</span>
            </div>
            <div className="audit-card-desc" style={{ marginTop: 4, fontSize: '0.80rem' }}>
              Major security defects or deprecated protocols (e.g. TLS 1.0/1.1, missing forward secrecy, expired certs).
            </div>
          </div>

          <div className="audit-card" style={{ borderLeft: '3px solid var(--risk-critical)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="risk-pill risk-pill--CRITICAL">CRITICAL RISK</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--risk-critical)' }}>0.0 – 29.9</span>
            </div>
            <div className="audit-card-desc" style={{ marginTop: 4, fontSize: '0.80rem' }}>
              Catastrophic vulnerabilities: cleartext traffic, SSLv2/v3, buffer injection exploits, or active downgrade attacks.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AnalysisPage({ result, analysisMs, onToast, currentUser, token, onTriageUpdated }) {
  const [activeTab, setActiveTab] = useState('sessions')
  const [digestCopied, setDigestCopied] = useState(false)

  const ev = result?.evidence || {}
  const epi = result?.enterprise_posture_index ?? 0
  const tier = result?.overall_risk_tier ?? 'CRITICAL'
  const rb = result?.risk_breakdown || {}
  const vb = result?.violation_severity_breakdown || {}
  const sessions = result?.sessions || []
  const totalViolations = result?.total_violations ?? 0

  const formatBytes = (b) => {
    if (!b) return '0 B'
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / (1024 * 1024)).toFixed(2)} MB`
  }

  const shortHash = ev.sha256_hash
    ? `${ev.sha256_hash.slice(0, 10)}…${ev.sha256_hash.slice(-8)}`
    : '—'

  const copyDigest = useCallback(() => {
    if (!ev.sha256_hash) return
    navigator.clipboard.writeText(ev.sha256_hash).then(() => {
      setDigestCopied(true)
      onToast?.('SHA-256 Digest copied to clipboard.', 'success')
      setTimeout(() => setDigestCopied(false), 2000)
    })
  }, [ev.sha256_hash, onToast])

  const handleQuickDownloadHTML = useCallback(() => {
    try {
      const html = buildHTMLReport(result)
      const filename = ev.filename?.replace(/\./g, '_') || 'pcap'
      const blob = new Blob([html], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `forensic_report_${filename}.html`
      a.click()
      URL.revokeObjectURL(url)
      onToast?.('HTML forensic report downloaded.', 'success')
    } catch (e) {
      onToast?.(`HTML export failed: ${e.message}`, 'error')
    }
  }, [result, ev.filename, onToast])

  const handleQuickDownloadJSON = useCallback(() => {
    try {
      const jsonStr = JSON.stringify(result, null, 2)
      const filename = ev.filename?.replace(/\./g, '_') || 'pcap'
      const blob = new Blob([jsonStr], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `forensic_report_${filename}.json`
      a.click()
      URL.revokeObjectURL(url)
      onToast?.('JSON report downloaded.', 'success')
    } catch (e) {
      onToast?.(`JSON export failed: ${e.message}`, 'error')
    }
  }, [result, ev.filename, onToast])

  return (
    <div className="page-inner">
      {/* ── KPI Strip (Aligned at top of page container) ── */}
      <div className="kpi-strip fade-in">
        <div className="kpi-item">
          <div className="kpi-label">Posture Index</div>
          <div className={`kpi-value ${getScoreClass(epi)}`}>{epi.toFixed(1)}</div>
          <div className="kpi-sub">out of 100</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Risk Tier</div>
          <div className={`kpi-value kpi-value--${tier.toLowerCase()} ${getTierClass(tier)}`}>{tier}</div>
          <div className="kpi-sub">overall posture</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Sessions</div>
          <div className="kpi-value kpi-value--blue">{result.session_count ?? sessions.length}</div>
          <div className="kpi-sub">reconstructed</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Findings</div>
          <div className={`kpi-value ${totalViolations > 0 ? getTierClass(tier) : 'kpi-value--green'}`}>
            {totalViolations}
          </div>
          <div className="kpi-sub">RFC/NIST violations</div>
        </div>
        <div className="kpi-item">
          <div className="kpi-label">Triage Verdict</div>
          <div className="kpi-value" style={{ fontSize: '0.85rem' }}>
            <span className={`triage-tag triage-tag--${result?.triage?.status || 'UNASSIGNED'}`}>
              {result?.triage?.status || 'UNASSIGNED'}
            </span>
          </div>
          <div className="kpi-sub">{result?.triage?.assigned_analyst ? `@${result.triage.assigned_analyst}` : 'analyst sign-off'}</div>
        </div>
        {analysisMs != null && (
          <div className="kpi-item">
            <div className="kpi-label">Analyzed In</div>
            <div className="kpi-value kpi-value--green">{analysisMs.toFixed(2)}s</div>
            <div className="kpi-sub">pipeline latency</div>
          </div>
        )}
      </div>

      {/* ── Header Bar with Action Buttons ── */}
      <div className="header-bar fade-in">
        <div className="header-bar-titles">
          <div className="kicker">
            <span className="kicker-dot" />
            ANALYSIS / CRYPTOGRAPHIC POSTURE · {result.scoring_policy?.id || 'crypto-posture-v1'} v{result.scoring_policy?.version || '1.0'}
          </div>
          <h1 className="page-title">Email Cryptographic Forensics</h1>
          <p className="page-subtitle">
            AI-Assisted Passive Network Forensics · NIST SP 800-52r2 · RFC 9325 · RFC 8314 · RFC 8996
          </p>
        </div>

        <div className="header-actions">
          <button
            type="button"
            className="btn-action-primary"
            onClick={handleQuickDownloadHTML}
            title="Download standalone forensic HTML report"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>HTML Report</span>
          </button>
          <button
            type="button"
            className="btn-action-secondary"
            onClick={handleQuickDownloadJSON}
            title="Download machine-readable JSON data"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>JSON</span>
          </button>
          <button
            type="button"
            className="btn-action-ghost"
            onClick={copyDigest}
            title="Copy SHA-256 evidence digest"
          >
            {digestCopied
              ? <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>
              : <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
            }
            <span>{digestCopied ? 'Copied' : 'Digest'}</span>
          </button>
          <div className="header-seal">
            <span>ENGINE</span>
            <b>v{result.forensic_engine_version || '1.0.0'}</b>
          </div>
        </div>
      </div>

      {/* ── Executive Command Deck (Equal Height Columns) ── */}
      <div className="command-deck-grid fade-in">
        {/* Deck Column 1: Posture Gauge */}
        <div className="command-deck-card">
          <div className="deck-card-header">
            <span className="deck-card-title">Cryptographic Posture Index</span>
            <span className={`risk-pill risk-pill--${tier}`}>{tier}</span>
          </div>
          <div className="deck-card-body deck-card-body--gauge">
            <PostureGauge score={epi} tier={tier} bare />
          </div>
        </div>

        {/* Deck Column 2: Risk & Severity Matrix */}
        <div className="command-deck-card">
          <div className="deck-card-header">
            <span className="deck-card-title">Threat & Finding Distribution</span>
            <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              {sessions.length} Flows Analyzed
            </span>
          </div>
          <div className="deck-card-body">
            <RiskMatrix
              breakdown={rb}
              totalViolations={totalViolations}
              sessionCount={result?.session_count ?? sessions.length}
              violationBreakdown={vb}
              bare
            />
          </div>
        </div>

        {/* Deck Column 3: Forensic Ingestion & Integrity Seal */}
        <div className="command-deck-card deck-card-evidence">
          <div className="deck-card-header">
            <span className="deck-card-title">Evidence Ingestion &amp; Integrity</span>
            <span className={`integrity-badge${ev.is_tamper_free === false ? ' integrity-badge--tampered' : ''}`}>
              {ev.is_tamper_free === false
                ? <><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4M12 17h.01"/></svg> TAMPERED</>
                : <><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg> INTACT</>
              }
            </span>
          </div>

          <div className="deck-evidence-body">
            <div className="deck-evidence-filename" title={ev.filename}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 5, flexShrink: 0 }} aria-hidden="true"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>
              {ev.filename || 'Unknown PCAP'}
            </div>

            <div className="deck-evidence-hashrow">
              <span className="deck-hash-label">SHA-256</span>
              <span
                className={`hash-chip${digestCopied ? ' hash-chip--copied' : ''}`}
                onClick={copyDigest}
                title="Click to copy SHA-256 digest"
              >
                {digestCopied ? '✓ Copied!' : shortHash}
              </span>
            </div>

            <div className="deck-stats-grid">
              <div className="deck-stat">
                <div className="deck-stat-label">Packets</div>
                <div className="deck-stat-val">{(ev.total_packets || 0).toLocaleString()}</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">File Size</div>
                <div className="deck-stat-val">{formatBytes(ev.file_size_bytes)}</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">Duration</div>
                <div className="deck-stat-val">{(ev.capture_duration || 0).toFixed(2)}s</div>
              </div>
              <div className="deck-stat">
                <div className="deck-stat-label">Format</div>
                <div className="deck-stat-val" style={{ color: 'var(--accent-blue)' }}>{ev.capture_format || 'PCAP'}</div>
              </div>
            </div>

            {ev.evidence_id && (
              <div className="deck-evidence-id">
                <span>Evidence ID:</span> <strong>{ev.evidence_id}</strong>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="analysis-layout fade-in">
        {/* ── Sidebar Navigation ── */}
        <div className="analysis-sidebar">
          {/* AI Summary — top of nav, highlighted */}
          <button
            type="button"
            className={`workspace-tab workspace-tab--ai${activeTab === 'narrative' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('narrative')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 3v2M12 19v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M3 12h2M19 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/><circle cx="12" cy="12" r="4"/></svg>
            </span>
            <span>AI Summary</span>
            {result?.ai_narrative?.narrative && <span className="workspace-tab-badge workspace-tab-badge--ai">NEW</span>}
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'sessions' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>
            </span>
            <span>Network Sessions</span>
            <span className="workspace-tab-badge">{sessions.length}</span>
          </button>

          <button
            type="button"
            className={`workspace-tab workspace-tab--triage${activeTab === 'triage' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('triage')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
            </span>
            <span>Analyst Triage</span>
            <span className={`workspace-tab-badge workspace-tab-badge--${(result?.triage?.status || 'UNASSIGNED').toLowerCase()}`}>
              {result?.triage?.status || 'CASE'}
            </span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'findings' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4M12 17h.01"/></svg>
            </span>
            <span>Policy Findings</span>
            <span className={`workspace-tab-badge ${totalViolations > 0 ? 'workspace-tab-badge--alert' : ''}`}>
              {totalViolations}
            </span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'audit' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>
            </span>
            <span>Posture Audit</span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'evidence' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('evidence')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            </span>
            <span>Evidence &amp; Lineage</span>
          </button>

          <button
            type="button"
            className={`workspace-tab${activeTab === 'export' ? ' workspace-tab--active' : ''}`}
            onClick={() => setActiveTab('export')}
          >
            <span className="workspace-tab-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            </span>
            <span>Export Suite</span>
          </button>
        </div>

        {/* ── Active Content Area ── */}
        <div className="analysis-content">
          {activeTab === 'triage' && (
            <div>
              <AnalystTriagePanel
                result={result}
                currentUser={currentUser}
                token={token}
                onToast={onToast}
                onTriageUpdated={onTriageUpdated}
              />
            </div>
          )}

          {activeTab === 'narrative' && (
            <div>
              <AINarrativePanel result={result} onToast={onToast} />
            </div>
          )}

          {activeTab === 'sessions' && (
            <div>
              <SessionTable sessions={sessions} />
            </div>
          )}

          {activeTab === 'findings' && (
            <div>
              <FindingsExplorer sessions={sessions} />
            </div>
          )}

          {activeTab === 'audit' && (
            <div>
              <EnterpriseExplanationPanel
                explanation={result?.enterprise_explanation}
                policy={result?.scoring_policy}
                engineVersion={result?.forensic_engine_version}
                schemaVersion={result?.schema_version}
              />
            </div>
          )}

          {activeTab === 'evidence' && (
            <div>
              <EvidenceProvenancePanel
                evidence={ev}
                sessions={sessions}
                result={result}
              />
            </div>
          )}

          {activeTab === 'export' && (
            <div>
              <ExportPanel data={result} onToast={onToast} />
            </div>
          )}
        </div>
      </div>

      {/* ── Page Footer ── */}
      <div className="footer">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        CryptoPosture · AI-Assisted Passive Network Forensic Framework
        for Enterprise Email Cryptographic Posture Assessment<br />
        SIH-26 Demo · For authorized forensic use only · All analyses performed offline.
      </div>
    </div>
  )
}
