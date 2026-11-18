import { X } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api'
import { formatTime, readable } from '../format'
import { usePolling } from '../usePolling'
import SeverityBadge from './SeverityBadge'

const APPROVAL_LABELS = {
  pending: 'Waiting for approval',
  approved: 'Approved',
  rejected: 'Rejected',
  cancelled: 'Cancelled',
}

const EXECUTION_LABELS = {
  not_applied: 'waiting for the gateway',
  applying: 'being applied',
  active: 'active on the gateway',
  removing: 'being removed',
  removed: 'removed',
  failed: 'failed',
  unknown: 'unknown',
}

function showValue(value) {
  if (Array.isArray(value)) return value.join(', ')
  if (value !== null && typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function Details({ values }) {
  const entries = Object.entries(values)
  if (entries.length === 0) return <p className="muted">Nothing recorded.</p>
  return (
    <dl className="details">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{readable(key)}</dt>
          <dd>{showValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

function Assessment({ analysis }) {
  if (!analysis) return <p className="muted">No AI analysis for this incident yet.</p>
  if (analysis.status === 'pending' || analysis.status === 'running') {
    return <p className="muted">DeepSeek is analysing this incident...</p>
  }
  if (analysis.status === 'failed') return <p className="error">The analysis failed: {analysis.error_message}</p>
  if (analysis.status === 'cancelled') return <p className="muted">The analysis was cancelled.</p>

  const { summary, ...rest } = analysis.assessment
  return (
    <>
      {summary && <p className="assessment">{summary}</p>}
      <Details values={rest} />
      <p className="muted small">{analysis.model}, {formatTime(analysis.completed_at)}</p>
    </>
  )
}

export default function IncidentDetail({ id, onChange, onClose }) {
  const { data: incident, error, reload } = usePolling('/api/incidents/' + id, 10)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const [confirming, setConfirming] = useState(null)

  async function send(path, method, body) {
    setBusy(true)
    setActionError('')
    try {
      await api(path, { method, body })
      reload()
      onChange()
    } catch (err) {
      setActionError(err.message)
    }
    setBusy(false)
    setConfirming(null)
  }

  if (error && !incident) {
    return (
      <section className="panel">
        <p className="error">{error}</p>
      </section>
    )
  }
  if (!incident) return <section className="panel muted">Loading...</section>

  const device = incident.source_device

  return (
    <section className="panel incident-detail">
      <div className="detail-head">
        <div>
          <h2>#{incident.id} {readable(incident.rule_code)}</h2>
          <p className="muted small">
            {formatTime(incident.first_seen_at)} to {formatTime(incident.last_seen_at)}
          </p>
        </div>
        <button className="icon-button" onClick={onClose} title="Close">
          <X size={16} />
        </button>
      </div>

      <div className="detail-line">
        <SeverityBadge severity={incident.severity} />
        {incident.risk_score !== null && <span>Risk score <b>{incident.risk_score}</b>/100</span>}
        <span className="capitalize">{incident.status}</span>
      </div>

      <div className="buttons">
        {incident.status === 'open' && (
          <button className="button small" disabled={busy} onClick={() => send('/api/incidents/' + id, 'PATCH', { status: 'investigating' })}>
            Start investigating
          </button>
        )}
        {incident.status !== 'resolved' && (
          <button className="button small secondary" disabled={busy} onClick={() => send('/api/incidents/' + id, 'PATCH', { status: 'resolved' })}>
            Mark as resolved
          </button>
        )}
        {incident.status === 'resolved' && (
          <button className="button small secondary" disabled={busy} onClick={() => send('/api/incidents/' + id, 'PATCH', { status: 'open' })}>
            Reopen
          </button>
        )}
      </div>

      {actionError && <p className="error">{actionError}</p>}

      <h3>Source and target</h3>
      <dl className="details">
        <div>
          <dt>Source</dt>
          <dd>
            <span className="mono">{incident.source_ip}</span>
            {device && <span className="muted"> ({device.hostname || device.mac_address})</span>}
          </dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd className="mono">{incident.target_ip}</dd>
        </div>
      </dl>

      <h3>Evidence</h3>
      <Details values={incident.evidence} />

      <h3>AI assessment</h3>
      <Assessment analysis={incident.analyses[0]} />

      <h3>Proposed responses</h3>
      {incident.actions.length === 0 && <p className="muted">No response proposed for this incident.</p>}
      {incident.actions.map((action) => (
        <div className="action" key={action.id}>
          <div className="action-head">
            <b>{action.action_type === 'block' ? 'Block the device' : 'Limit to ' + action.rate_limit_kbps + ' kbit/s'}</b>
            <span className={'approval ' + action.approval_status}>{APPROVAL_LABELS[action.approval_status]}</span>
          </div>
          <div className="mono muted small">
            {action.target_mac}
            {action.target_ip && ' / ' + action.target_ip}
          </div>
          <p>{action.reason}</p>

          {action.approval_status === 'pending' && confirming?.id !== action.id && (
            <div className="buttons">
              <button className="button small" disabled={busy} onClick={() => setConfirming({ id: action.id, decision: 'approved' })}>
                Approve
              </button>
              <button className="button small secondary" disabled={busy} onClick={() => setConfirming({ id: action.id, decision: 'rejected' })}>
                Reject
              </button>
            </div>
          )}

          {confirming?.id === action.id && (
            <div className="confirm">
              <span>{confirming.decision === 'approved' ? 'Send this action to the gateway?' : 'Reject this proposal?'}</span>
              <button
                className="button small"
                disabled={busy}
                onClick={() => send('/api/actions/' + action.id + '/decision', 'POST', { decision: confirming.decision })}
              >
                Yes
              </button>
              <button className="link-button" onClick={() => setConfirming(null)}>Cancel</button>
            </div>
          )}

          {action.decided_by && (
            <p className="muted small">
              {APPROVAL_LABELS[action.approval_status]} by {action.decided_by.username}, {formatTime(action.decided_at)}
              {action.approval_status === 'approved' && ' - gateway: ' + EXECUTION_LABELS[action.execution_status]}
            </p>
          )}
          {action.error_message && <p className="error small">{action.error_message}</p>}
        </div>
      ))}
    </section>
  )
}