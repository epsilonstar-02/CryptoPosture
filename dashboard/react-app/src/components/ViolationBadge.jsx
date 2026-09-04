export default function ViolationBadge({ severity }) {
  return (
    <span
      className={`risk-pill risk-pill--${severity}`}
      style={{ fontSize: '0.56rem', padding: '2px 7px', flexShrink: 0 }}
    >
      <span className={`risk-dot risk-dot--${severity}`} />
      {severity}
    </span>
  )
}
