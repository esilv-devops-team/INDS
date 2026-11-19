import { formatTime } from '../format'

export default function ResponseLifecycle({ action }) {
  const events = [
    ['Proposed', action.created_at],
    ['Decision recorded', action.decided_at, action.decided_by?.username],
    ['Applied by gateway', action.applied_at],
    ['Removed by gateway', action.removed_at],
    ['Scheduled expiry', action.expires_at],
    ['Last record update', action.updated_at],
  ]
  return (
    <dl className="response-lifecycle">
      {events.filter(([, timestamp]) => timestamp).map(([label, timestamp, operator]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{formatTime(timestamp)}{operator && ' · ' + operator}</dd>
        </div>
      ))}
    </dl>
  )
}
