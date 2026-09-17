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

  const isLight = typeof document !== 'undefined' && (
    document.documentElement.getAttribute('data-theme')?.startsWith('stone') ||
    document.documentElement.getAttribute('data-theme')?.startsWith('slate') ||
    document.documentElement.getAttribute('data-theme')?.startsWith('warm')
  )

  const gridColor  = isLight ? 'rgba(163, 177, 198, 0.45)' : 'rgba(22, 43, 54, 0.9)'
  const tickColor  = isLight ? 'rgba(100, 116, 139, 0.85)' : 'rgba(76, 106, 112, 0.8)'
  const labelColor = isLight ? 'rgba(51, 65, 85, 0.95)'    : 'rgba(133, 168, 170, 0.9)'

  const data = {
    labels: LABELS,
    datasets: [
      {
        label: 'Score',
        data: values,
        backgroundColor: isLight ? 'rgba(155, 114, 207, 0.16)' : 'rgba(61, 216, 232, 0.08)',
        borderColor:     isLight ? 'rgba(155, 114, 207, 0.85)' : 'rgba(61, 216, 232, 0.7)',
        borderWidth: 1.8,
        pointBackgroundColor: isLight ? 'rgba(155, 114, 207, 1)' : 'rgba(61, 216, 232, 0.9)',
        pointBorderColor:     isLight ? '#e0e5ec' : 'rgba(9, 17, 24, 0.9)',
        pointBorderWidth: 1.5,
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
          color: tickColor,
          font: { family: "'JetBrains Mono', monospace", size: 8 },
          backdropColor: 'transparent',
        },
        grid:        { color: gridColor },
        angleLines:  { color: gridColor },
        pointLabels: {
          color: labelColor,
          font: { family: "'Inter', sans-serif", size: 9.5, weight: '600' },
        },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(9, 17, 24, 0.97)',
        borderColor: 'rgba(61, 216, 232, 0.25)',
        borderWidth: 1,
        titleColor: '#3dd8e8',
        bodyColor: '#e4f0ef',
        titleFont: { family: "'JetBrains Mono', monospace", size: 10 },
        bodyFont:  { family: "'JetBrains Mono', monospace", size: 10 },
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
    <div style={{ padding: 12, maxWidth: 250, margin: '0 auto' }}>
      <Radar data={data} options={options} />
    </div>
  )
}
