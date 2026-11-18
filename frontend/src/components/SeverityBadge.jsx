export default function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge">-</span>
  return <span className={'badge ' + severity.toLowerCase()}>{severity}</span>
}