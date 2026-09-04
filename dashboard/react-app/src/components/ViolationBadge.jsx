export default function ViolationBadge({ severity }) {
  return <span className={`risk-pill risk-pill--${severity}`}>{severity}</span>
}
