import { formatTime, toDate } from '../format'
import ResponseStatus from './ResponseStatus'
import SeverityBadge from './SeverityBadge'

const STATUS_NAMES = {
  pending: 'Pending',
  running: 'Analyzing',
  succeeded: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

const ACTION_NAMES = {
  block: 'Block the device',
  monitor: 'Keep monitoring',
}

function Result({ result, proposal, decision }) {
  return (
    <>
      <p className="ai-summary">{result.summary}</p>
      <div className="detail-line">
        {result.risk_level && <SeverityBadge severity={result.risk_level} />}
        {result.classification && <span>{result.classification}</span>}
        {result.confidence !== undefined && <span>Confidence <b>{result.confidence}%</b></span>}
      </div>

      {result.explanation && (
        <>
          <h4>What is happening</h4>
          <p>{result.explanation}</p>
        </>
      )}
      {result.evidence?.length > 0 && (
        <>
          <h4>Evidence</h4>
          <ul>
            {result.evidence.map((item, index) => <li key={index}>{item}</li>)}
          </ul>
        </>
      )}
      {result.impact && (
        <>
          <h4>Possible impact</h4>
          <p>{result.impact}</p>
        </>
      )}
      {result.recommended_action && (
        <>
          <h4>Recommended action</h4>
          <p><b>{ACTION_NAMES[result.recommended_action] || result.recommended_action}</b></p>
          {result.justification && <p>{result.justification}</p>}
          {result.response_note && <p className="muted small">{result.response_note}</p>}
        </>
      )}
      {proposal && (
        <div className="ai-proposal">
          <div className="action-head">
            <span>Proposed block #{proposal.id}</span>
            <ResponseStatus action={proposal} />
          </div>
          {decision}
        </div>
      )}
      {result.uncertainty && (
        <>
          <h4>Uncertainty</h4>
          <p>{result.uncertainty}</p>
        </>
      )}
      <p className="muted small">The risk level is the AI's opinion, it does not change the severity or score of INDS.</p>
    </>
  )
}

export default function AIAnalysis({ analyses, proposal, decision, now, busy, onRetry }) {
  const analysis = analyses[0]
  if (!analysis) {
    return (
      <div className="ai-box">
        <p className="muted">No AI analysis for this incident.</p>
        <button className="button small" disabled={busy} onClick={onRetry}>Analyse with AI</button>
      </div>
    )
  }

  const previous = analyses[1]
  const waiting = analysis.status === 'pending' && now && toDate(analysis.requested_at).getTime() > now.getTime()

  return (
    <div className="ai-box">
      <div className="ai-head">
        <span className={'ai-status ' + analysis.status}>{STATUS_NAMES[analysis.status] || analysis.status}</span>
        <span className="muted small">
          {analysis.model}
          {analysis.completed_at && ' · ' + formatTime(analysis.completed_at)}
        </span>
      </div>

      {analysis.status === 'pending' && waiting && (
        <p className="muted">
          The last try failed{previous?.error_message && ' (' + previous.error_message + ')'}. Next try at {formatTime(analysis.requested_at)}.
        </p>
      )}
      {analysis.status === 'pending' && !waiting && <p className="muted">Waiting for the AI to start...</p>}
      {analysis.status === 'running' && <p className="muted">DeepSeek is analysing this incident...</p>}
      {analysis.status === 'failed' && (
        <>
          <p className="error">{analysis.error_message}</p>
          <button className="button small" disabled={busy} onClick={onRetry}>Try again</button>
        </>
      )}
      {analysis.status === 'cancelled' && <p className="muted">Cancelled because the monitoring was stopped.</p>}
      {analysis.status === 'succeeded' && analysis.assessment && (
        <Result result={analysis.assessment} proposal={proposal} decision={decision} />
      )}
    </div>
  )
}
