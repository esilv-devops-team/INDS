import { X } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api'
import { formatTime, readable } from '../format'
import { usePolling } from '../usePolling'
import AIAnalysis from './AIAnalysis'
import { actionName } from '../responseStates'
import ResponseLifecycle from './ResponseLifecycle'
import ResponseStatus from './ResponseStatus'
import SeverityBadge from './SeverityBadge'
import './IncidentDetail.css'

const RESPONSE_EVENTS = {
  proposed: 'Response proposed',
  expiry_due: 'Temporary block expired',
  proposal_expired: 'Response proposal expired',
  approved: 'Response approved',
  rejected: 'Response rejected',
  applied: 'Block applied on the gateway',
  reversal_requested: 'Removal of the block requested',
  cleared: 'Block removed from the gateway',
  cancelled: 'Response cancelled',
  apply_unconfirmed: 'Gateway could not confirm the block',
  reverse_unconfirmed: 'Gateway could not confirm the removal',
  cleanup_unconfirmed: 'Gateway could not confirm the cleanup',
}

function showValue(value) {
  if (Array.isArray(value)) return value.join(', ')
  if (value !== null && typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function describe(event) {
  const details = event.details
  const [kind, name] = event.event_type.split('.')
  if (event.event_type === 'incident.created') {
    return 'Detected as ' + details.severity + ' (score ' + details.risk_score + ')'
  }
  if (event.event_type === 'incident.finding_correlated') return 'Related finding recorded'
  if (event.event_type === 'incident.escalated') {
    return 'Severity changed from ' + details.from + ' to ' + details.to + ' (score ' + details.risk_score + ')'
  }
  if (event.event_type === 'incident.status_changed') {
    if (details.to === 'resolved') return 'Marked as resolved'
    if (details.from === 'resolved') return 'Reopened as ' + details.to
    return 'Status changed from ' + details.from + ' to ' + details.to
  }
  if (event.event_type === 'ai_analysis.attached') {
    return 'AI analysis completed by ' + details.model + (details.risk_level ? ' (risk ' + details.risk_level + ')' : '')
  }
  if (event.event_type === 'ai_analysis.failed') return 'AI analysis failed: ' + details.error
  if (event.event_type === 'ai_analysis.requested') return 'New AI analysis requested'
  if (kind === 'response_action') {
    const text = RESPONSE_EVENTS[name] || readable(name)
    return details.action_type ? text + ' (' + details.action_type.replace('_', ' ') + ')' : text
  }
  return readable(event.event_type.replace('.', '_'))
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

function History({ events, error }) {
  if (!events) return <p className={error ? 'error' : 'muted'}>{error || 'Loading the history...'}</p>
  if (events.length === 0) return <p className="muted">Nothing happened on this incident yet.</p>
  return (
    <ol className="history">
      {events.map((event) => (
        <li key={event.id} className={event.outcome === 'failure' ? 'failed' : undefined}>
          <div className="history-meta">{formatTime(event.occurred_at)} · {event.actor || 'INDS'}</div>
          <div>{describe(event)}</div>
          {event.event_type === 'incident.finding_correlated' && (
            <details>
              <summary>Evidence from {formatTime(event.details.observed_at)}</summary>
              <Details values={event.details.evidence} />
            </details>
          )}
          {event.details.note && <q>{event.details.note}</q>}
        </li>
      ))}
    </ol>
  )
}

export default function IncidentDetail({ id, onChange, onClose }) {
  const { data: incident, error, reload, updatedAt } = usePolling('/api/incidents/' + id)
  const { data: history, error: historyError, reload: reloadHistory } = usePolling('/api/incidents/' + id + '/history')
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')
  const [confirming, setConfirming] = useState(null)
  const [note, setNote] = useState('')
  const [proposalReason, setProposalReason] = useState('')
  const [duration, setDuration] = useState('')

  async function send(path, method, body) {
    setBusy(true)
    setActionError('')
    let done = false
    try {
      await api(path, { method, body })
      reload()
      reloadHistory()
      onChange()
      done = true
    } catch (err) {
      setActionError(err.message)
    }
    setBusy(false)
    setConfirming(null)
    return done
  }

  async function changeStatus(status) {
    if (await send('/api/incidents/' + id, 'PATCH', { status, note })) setNote('')
  }

  function decisionButtons(action) {
    if (action.approval_status !== 'pending') return null
    if (confirming?.id === action.id) {
      return (
        <div className="confirm">
          <span>{confirming.decision === 'approved' ? 'Record approval for this proposal?' : 'Reject this proposal?'}</span>
          <button
            className="button small"
            disabled={busy}
            onClick={() => send('/api/actions/' + action.id + '/decision', 'POST', { decision: confirming.decision })}
          >
            Yes
          </button>
          <button className="link-button" onClick={() => setConfirming(null)}>Cancel</button>
        </div>
      )
    }
    return (
      <div className="buttons">
        <button className="button small" disabled={busy} onClick={() => setConfirming({ id: action.id, decision: 'approved' })}>
          Approve
        </button>
        <button className="button small secondary" disabled={busy} onClick={() => setConfirming({ id: action.id, decision: 'rejected' })}>
          Reject
        </button>
      </div>
    )
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
  const latestAnalysis = incident.analyses[0]
  const aiProposal = latestAnalysis && incident.actions.find((action) => action.ai_analysis_id === latestAnalysis.id)

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

      <input
        className="status-note"
        placeholder="Note for the history (optional)"
        maxLength={300}
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />

      <div className="buttons">
        {incident.status === 'open' && (
          <button className="button small" disabled={busy} onClick={() => changeStatus('investigating')}>
            Start investigating
          </button>
        )}
        {incident.status !== 'resolved' && (
          <button className="button small secondary" disabled={busy} onClick={() => changeStatus('resolved')}>
            Mark as resolved
          </button>
        )}
        {incident.status === 'resolved' && (
          <button className="button small secondary" disabled={busy} onClick={() => changeStatus('open')}>
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
      <Details values={Object.fromEntries(Object.entries(incident.evidence).filter(([key]) => key !== 'latest_finding'))} />
      {incident.evidence.latest_finding && (
        <>
          <h3>Latest related finding</h3>
          <Details values={incident.evidence.latest_finding} />
        </>
      )}
      {incident.related_incidents?.length > 0 && (
        <>
          <h3>Related incidents</h3>
          <ul>
            {incident.related_incidents.map((item) => (
              <li key={item.id}>
                #{item.id} · {item.rule_code} · {readable(item.relationship)} · {readable(item.status)}
                {item.responses?.map((action) => (
                  <span key={action.id}> · {actionName(action)} <ResponseStatus action={action} /></span>
                ))}
              </li>
            ))}
          </ul>
        </>
      )}

      <h3>AI analysis</h3>
      <AIAnalysis
        analyses={incident.analyses}
        proposal={aiProposal}
        decision={aiProposal && decisionButtons(aiProposal)}
        now={updatedAt}
        busy={busy}
        onRetry={() => send('/api/incidents/' + incident.id + '/analysis', 'POST')}
      />

      <h3>Proposed responses</h3>
      {incident.policy && (
        <>
          <Details values={{
            risk: incident.policy.risk,
            confidence: readable(incident.policy.confidence),
            recommendation: readable(incident.policy.recommendation),
            reasons: incident.policy.reasons,
          }} />
          {incident.policy.approval_required && (
            <form onSubmit={async (event) => {
              event.preventDefault()
              const proposed = await send('/api/actions', 'POST', {
                incident_id: incident.id,
                reason: proposalReason,
                duration_minutes: duration ? Number(duration) : null,
              })
              if (proposed) setProposalReason('')
            }}>
              <label>Reason <input value={proposalReason} onChange={(event) => setProposalReason(event.target.value)}
                required maxLength={300} /></label>
              <label>Minutes <input type="number" min="1" max="60" value={duration}
                placeholder={incident.policy.recommendation === 'temporary_block' ? '15' : 'Optional'}
                onChange={(event) => setDuration(event.target.value)} /></label>
              <button className="button small" disabled={busy}>Propose block</button>
            </form>
          )}
        </>
      )}
      {incident.actions.length === 0 && <p className="muted">No response proposed for this incident.</p>}
      {incident.actions.map((action) => (
        <div className="action" key={action.id}>
          <div className="action-head">
            <b>{actionName(action)}{action.rate_limit_kbps && ' · ' + action.rate_limit_kbps + ' kbit/s'}</b>
            <ResponseStatus action={action} />
          </div>
          <div className="mono muted small">
            {action.target_mac}
            {action.target_ip && ' / ' + action.target_ip}
          </div>
          <p>{action.reason}</p>

          {decisionButtons(action)}

          <ResponseLifecycle action={action} />
          {action.error_message && <p className="error small">{action.error_message}</p>}
        </div>
      ))}

      <h3>History</h3>
      <History events={history} error={historyError} />
    </section>
  )
}
