import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
} from 'chart.js'
import { Radar } from 'react-chartjs-2'

ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip, Legend)

const LABELS = ['TLS Version', 'Cipher Suite', 'Cert Health', 'STARTTLS', 'Fwd Secrecy', 'Proto Ctx']
const KEYS   = ['tls_version', 'cipher_suite', 'cert_health', 'starttls_transition', 'forward_secrecy', 'protocol_context']

export default function ComponentScoreChart({ scores }) {
  const cs = scores || {}
  const values = KEYS.map(k => cs[k] ?? 0)

  const data = {
    labels: LABELS,
    datasets: [
      {
        label: 'Score',
        data: values,
        backgroundColor: 'rgba(59, 130, 246, 0.12)',
        borderColor: 'rgba(59, 130, 246, 0.8)',
        borderWidth: 2,
        pointBackgroundColor: 'rgba(59, 130, 246, 0.9)',
        pointBorderColor: '#fff',
        pointBorderWidth: 1,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
    ],
  }

  const options = {
    responsive: true,
    maintainAspectRatio: true,
    scales: {
      r: {
        min: 0,
        max: 100,
        ticks: {
          stepSize: 25,
          color: 'rgba(100,116,139,0.7)',
          font: { family: "'JetBrains Mono', monospace", size: 9 },
          backdropColor: 'transparent',
        },
        grid:        { color: 'rgba(15, 30, 61, 0.8)' },
        angleLines:  { color: 'rgba(15, 30, 61, 0.8)' },
        pointLabels: {
          color: 'rgba(148,163,184,0.9)',
          font: { family: "'Inter', sans-serif", size: 10, weight: '600' },
        },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(8,13,26,0.95)',
        borderColor: 'rgba(59,130,246,0.3)',
        borderWidth: 1,
        titleColor: '#93c5fd',
        bodyColor: '#e2e8f0',
        titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
        bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
        padding: 10,
        callbacks: {
          label: ctx => ` ${ctx.parsed.r.toFixed(1)} / 100`,
        },
      },
    },
    animation: {
      duration: 900,
      easing: 'easeOutCubic',
    },
  }

  return (
    <div style={{ padding: 16, maxWidth: 280, margin: '0 auto' }}>
      <Radar data={data} options={options} />
    </div>
  )
}
