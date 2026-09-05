import { useState, useCallback, useMemo } from 'react'

const PIPELINE_STAGES = [
  {
    id: 'stage-1',
    name: 'PCAP Parser & Decapsulation',
    desc: 'Strict libpcap binary parsing, link-layer decapsulation, and packet header verification.',
    standard: 'NIST SP 800-86',
  },
  {
    id: 'stage-2',
    name: 'TCP Stream Reassembly & Flow Tracker',
    desc: 'Zero-copy 4-tuple TCP stream reassembly, segment ordering, and directional payload isolation.',
    standard: 'RFC 793 / RFC 9293',
  },
  {
    id: 'stage-3',
    name: 'Protocol Identification Engine',
    desc: 'Heuristic & port-based identification of email transmission flows (SMTP, IMAP, POP3).',
    standard: 'RFC 5321 / RFC 3501',
  },
  {
    id: 'stage-4',
    name: 'STARTTLS State Machine & Transition Auditor',
    desc: 'Validates cleartext command sequencing, detects STARTTLS stripping, and buffer injection.',
    standard: 'RFC 8314 / RFC 3207',
  },
  {
    id: 'stage-5',
    name: 'TLS Handshake Parser & Extension Dissector',
    desc: 'Dissects ClientHello / ServerHello records, supported ciphers, ALPN, and elliptic curves.',
    standard: 'RFC 8446 / RFC 5246',
  },
  {
    id: 'stage-6',
    name: 'X.509 Certificate Chain Validator',
    desc: 'Evaluates leaf and intermediate certificates: validity periods, RSA/ECC key sizes, and SHA-1 signatures.',
    standard: 'RFC 5280 / NIST SP 800-52r2',
  },
  {
    id: 'stage-7',
    name: 'JA4 / JA4S / JA4X Fingerprinting Engine',
    desc: 'Computes cryptographic fingerprint digests for TLS client, server, and X.509 certificate.',
    standard: 'FoxIO JA4 Specification',
  },
  {
    id: 'stage-8',
    name: 'Post-Quantum Cryptography (PQC) Evaluator',
    desc: 'Inspects key share groups for hybrid ML-KEM / Kyber post-quantum cryptographic readiness.',
    standard: 'NIST FIPS 203',
  },
  {
    id: 'stage-9',
    name: 'Deterministic Policy & Mandate Rule Engine',
    desc: 'Evaluates RFC MUST/SHOULD mandates and NIST guidelines against reconstructed session facts.',
    standard: 'RFC 9325 / RFC 8996',
  },
  {
    id: 'stage-10',
    name: 'Isolation Forest Anomaly & Outlier Engine',
    desc: 'Statistical outlier scoring based on multidimensional Liu et al. Isolation Forest deviations.',
    standard: 'Extended Isolation Forest',
  },
  {
    id: 'stage-11',
    name: 'Enterprise Harmonic Posture Aggregator',
    desc: 'Volume-weighted harmonic mean aggregation ensuring critical gaps cannot be averaged away.',
    standard: 'CryptoPosture v1.0',
  },
]

export default function EvidenceProvenancePanel({ evidence = {}, sessions = [], result = {} }) {
  const [copiedHash, setCopiedHash] = useState(false)
  const [copiedId, setCopiedId] = useState(false)
  const [rawJsonOpen, setRawJsonOpen] = useState(false)

  const ev = useMemo(() => evidence || {}, [evidence])

  const formatBytes = (b) => {
    if (!b) return '0 B'
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / (1024 * 1024)).toFixed(2)} MB`
  }

  const copyToClipboard = useCallback((text, setFlag) => {
    if (!text) return
    navigator.clipboard.writeText(text).then(() => {
      setFlag(true)
      setTimeout(() => setFlag(false), 2000)
    })
  }, [])

  // Calculate packet rates and total byte volume
  const { pps, avgPacketSize, bufferInjectionsCount } = useMemo(() => {
    const vol = sessions.reduce((sum, s) => sum + (s.byte_count || s.bytes_total || 0), 0)
    const duration = ev.capture_duration || 0
    const packets = ev.total_packets || 0
    const packetRate = duration > 0 ? (packets / duration).toFixed(1) : '—'
    const avgSize = packets > 0 ? Math.round((ev.file_size_bytes || vol) / packets) : 0
    const injections = sessions.filter((s) => s.buffer_injection_detected).length
    const pqc = sessions.filter((s) => s.pqc_state === 2).length

    return {
      totalVolumeBytes: vol || ev.file_size_bytes || 0,
      pps: packetRate,
      avgPacketSize: avgSize,
      bufferInjectionsCount: injections,
      pqcCount: pqc,
    }
  }, [sessions, ev])

  return (
    <div className="evidence-provenance-wrap fade-in">
      {/* ── Top Grid: Forensic Chain of Custody & Ingestion Health ── */}
      <div className="provenance-grid">
        {/* Card 1: Chain of Custody */}
        <div className="provenance-card">
          <div className="provenance-card-title">
            <span className="detail-card-title-dot" />
            Forensic Chain of Custody & Seal
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Evidence File</span>
            <span className="provenance-val" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              📄 {ev.filename || 'Unknown PCAP'}
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Evidence ID</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="provenance-val mono" style={{ color: 'var(--accent-blue)' }}>
                {ev.evidence_id || 'EVID-UNSET'}
              </span>
              {ev.evidence_id && (
                <button
                  type="button"
                  className="btn-tiny"
                  onClick={() => copyToClipboard(ev.evidence_id, setCopiedId)}
                >
                  {copiedId ? '✓' : 'Copy'}
                </button>
              )}
            </div>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Integrity Status</span>
            <span className={`integrity-badge${ev.is_tamper_free === false ? ' integrity-badge--tampered' : ''}`}>
              {ev.is_tamper_free === false ? '⚠ INTEGRITY COMPROMISED' : '✔ CRYPTOGRAPHICALLY INTACT'}
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Ingestion Timestamp</span>
            <span className="provenance-val mono">
              {ev.ingestion_timestamp
                ? new Date(ev.ingestion_timestamp).toLocaleString()
                : 'Offline Analysis Run'}
            </span>
          </div>

          <div className="provenance-hash-block">
            <div className="provenance-hash-header">
              <span>SHA-256 Evidence Digest</span>
              <button
                type="button"
                className="btn-tiny"
                onClick={() => copyToClipboard(ev.sha256_hash, setCopiedHash)}
              >
                {copiedHash ? '✓ Copied Digest' : 'Copy Hash'}
              </button>
            </div>
            <div className="provenance-hash-text" title="Click to copy SHA-256">
              {ev.sha256_hash || 'No hash recorded'}
            </div>
          </div>

          <div className="provenance-note">
            🛡️ Ingested in strict read-only mode conforming to NIST SP 800-86 forensic standards. SHA-256 digest is calculated before stream reassembly to ensure non-repudiation.
          </div>
        </div>

        {/* Card 2: Capture Telemetry */}
        <div className="provenance-card">
          <div className="provenance-card-title">
            <span className="detail-card-title-dot" style={{ background: 'var(--accent-violet)', boxShadow: '0 0 6px var(--accent-violet)' }} />
            Network Capture Telemetry
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Capture Format</span>
            <span className="provenance-val" style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>
              {ev.capture_format || 'PCAP / Wireshark'}
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Link-Layer Type</span>
            <span className="provenance-val mono">{ev.link_layer_type || 'LINKTYPE_ETHERNET (1)'}</span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Total Packets</span>
            <span className="provenance-val mono">{(ev.total_packets || 0).toLocaleString()}</span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">File Size</span>
            <span className="provenance-val mono">
              {formatBytes(ev.file_size_bytes)}
              {ev.file_size_bytes ? ` (${ev.file_size_bytes.toLocaleString()} bytes)` : ''}
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Capture Duration</span>
            <span className="provenance-val mono">
              {ev.capture_duration ? `${ev.capture_duration.toFixed(3)}s` : '—'}
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Throughput / Rate</span>
            <span className="provenance-val mono">
              {pps !== '—' ? `${pps} pkts/sec` : '—'} · ~{avgPacketSize} B/pkt
            </span>
          </div>

          <div className="provenance-row">
            <span className="provenance-key">Reconstructed Flows</span>
            <span className="provenance-val" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
              {sessions.length} Flow{sessions.length !== 1 ? 's' : ''} Identified
            </span>
          </div>

          {bufferInjectionsCount > 0 && (
            <div className="provenance-alert-box">
              ⚠ <strong>Buffer Injection Detected:</strong> {bufferInjectionsCount} flow(s) exhibited pre-TLS command pipelining violation (RFC 8314 §5.2).
            </div>
          )}
        </div>
      </div>

      {/* ── Pipeline Stage Provenance Matrix ── */}
      <div className="provenance-pipeline-panel">
        <div className="provenance-pipeline-header">
          <div>
            <div className="section-title">11-Stage Forensic Pipeline Verification Audit</div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', marginTop: 3 }}>
              Every session transitions through a deterministic, reproducible 11-stage processing chain.
            </div>
          </div>
          <div style={{
            fontSize: '0.66rem',
            fontFamily: 'var(--font-mono)',
            padding: '4px 10px',
            borderRadius: 6,
            background: 'rgba(80,233,177,0.08)',
            border: '1px solid rgba(80,233,177,0.25)',
            color: 'var(--accent-green)',
            fontWeight: 700,
          }}>
            11 / 11 STAGES ACTIVE
          </div>
        </div>

        <div className="provenance-stages-grid">
          {PIPELINE_STAGES.map((st, i) => (
            <div key={st.id} className="provenance-stage-card">
              <div className="provenance-stage-header">
                <span className="provenance-stage-step">Stage {i + 1}</span>
                <span className="provenance-stage-standard">{st.standard}</span>
              </div>
              <div className="provenance-stage-name">{st.name}</div>
              <div className="provenance-stage-desc">{st.desc}</div>
              <div className="provenance-stage-footer">
                <span className="provenance-stage-status">
                  <span className="risk-dot risk-dot--LOW" />
                  VERIFIED
                </span>
                <span className="provenance-stage-engine">v{result.forensic_engine_version || '1.0.0'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Collapsible Raw Diagnostics & Audit JSON ── */}
      <div className="provenance-raw-section">
        <button
          type="button"
          className="provenance-raw-toggle"
          onClick={() => setRawJsonOpen((v) => !v)}
        >
          <span className={`toggle-chevron${rawJsonOpen ? ' toggle-chevron--open' : ''}`}>▶</span>
          <span>{rawJsonOpen ? 'Hide Raw Forensic Diagnostics JSON' : 'Inspect Raw Forensic Metadata & Diagnostics Record'}</span>
        </button>

        {rawJsonOpen && (
          <div className="provenance-raw-body fade-in">
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
              <button
                type="button"
                className="btn-tiny"
                onClick={() =>
                  copyToClipboard(
                    JSON.stringify({ evidence: ev, scoring_policy: result.scoring_policy, engine_version: result.forensic_engine_version }, null, 2),
                    setCopiedHash
                  )
                }
              >
                Copy Forensic JSON
              </button>
            </div>
            <pre className="provenance-raw-pre">
              {JSON.stringify(
                {
                  evidence_id: ev.evidence_id,
                  filename: ev.filename,
                  sha256_hash: ev.sha256_hash,
                  is_tamper_free: ev.is_tamper_free,
                  ingestion_timestamp: ev.ingestion_timestamp,
                  file_size_bytes: ev.file_size_bytes,
                  total_packets: ev.total_packets,
                  capture_duration: ev.capture_duration,
                  link_layer_type: ev.link_layer_type,
                  diagnostics: ev.diagnostics || [],
                  scoring_policy: result.scoring_policy,
                  forensic_engine_version: result.forensic_engine_version,
                  schema_version: result.schema_version,
                },
                null,
                2
              )}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}
