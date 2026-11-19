import { ArrowUpRight, ChevronDown } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import ResponseLifecycle from '../components/ResponseLifecycle'
import ResponseStatus from '../components/ResponseStatus'
import { formatTime } from '../format'
import { actionName, approvalLabels, executionLabels } from '../responseStates'
import { usePolling } from '../usePolling'
import './Responses.css'

const PAGE_SIZE = 15

function ResponseRecord({ action }) {
  return (
    <details className="response-record">
      <summary>
        <span className="response-title">
          <strong>{actionName(action)}</strong>
          <span className="muted small mono">{action.target_ip || action.target_mac}</span>
        </span>
        <ResponseStatus action={action} />
        <time className="muted small" dateTime={action.created_at + 'Z'}>{formatTime(action.created_at)}</time>
        <ChevronDown className="response-expand" size={16} aria-hidden="true" />
      </summary>
      <div className="response-details">
        <p>{action.reason}</p>
        <dl className="response-target">
          <div><dt>Target MAC</dt><dd className="mono">{action.target_mac}</dd></div>
          {action.target_ip && <div><dt>Target IP</dt><dd className="mono">{action.target_ip}</dd></div>}
          {action.rate_limit_kbps && <div><dt>Rate limit</dt><dd>{action.rate_limit_kbps} kbit/s</dd></div>}
        </dl>
        <ResponseLifecycle action={action} />
        {action.error_message && <p className="error small">{action.error_message}</p>}
        <div className="response-links">
          {action.incident_id && (
            <Link className="device-link" to={'/incidents/' + action.incident_id}>
              Incident #{action.incident_id} <ArrowUpRight size={14} aria-hidden="true" />
            </Link>
          )}
          {action.device_id && (
            <Link className="device-link" to={'/devices/' + action.device_id}>
              Investigate device <ArrowUpRight size={14} aria-hidden="true" />
            </Link>
          )}
        </div>
      </div>
    </details>
  )
}

function ResponseResults({ path, page, setPage }) {
  const { data, error } = usePolling(path)
  if (!data) return <p className={error ? 'error' : 'muted'}>{error || 'Loading responses…'}</p>

  return (
    <>
      {error && <p className="muted small" role="status">Response refresh failed. Showing the last available data.</p>}
      {data.length ? data.slice(0, PAGE_SIZE).map((action) => <ResponseRecord key={action.id} action={action} />) : (
        <p className="device-empty muted">No responses match this view.</p>
      )}
      {(page > 0 || data.length > PAGE_SIZE) && (
        <div className="device-pagination">
          <button className="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span className="muted small">Page {page + 1}</span>
          <button className="button" disabled={data.length <= PAGE_SIZE} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </>
  )
}

function ResponseHistory({ deviceId }) {
  const [approval, setApproval] = useState('')
  const [execution, setExecution] = useState('')
  const [page, setPage] = useState(0)
  const query = new URLSearchParams({ limit: PAGE_SIZE + 1, offset: PAGE_SIZE * page })
  if (deviceId) query.set('device_id', deviceId)
  if (approval) query.set('approval', approval)
  if (execution) query.set('execution', execution)
  const path = '/api/actions?' + query

  return (
    <section className="panel response-history">
      <div className="device-section-head">
        <h2>Response history {deviceId && <span className="badge">Device #{deviceId}</span>}</h2>
        {deviceId && <Link className="device-link small" to="/responses">View all devices</Link>}
      </div>
      <div className="toolbar response-filters">
        <select aria-label="Filter by approval" value={approval}
          onChange={(event) => { setApproval(event.target.value); setPage(0) }}>
          <option value="">All approval states</option>
          {Object.entries(approvalLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <select aria-label="Filter by execution" value={execution}
          onChange={(event) => { setExecution(event.target.value); setPage(0) }}>
          <option value="">All execution states</option>
          {Object.entries(executionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </div>
      <ResponseResults key={path} path={path} page={page} setPage={setPage} />
    </section>
  )
}

export default function Responses() {
  const [params] = useSearchParams()
  const deviceId = params.get('device_id')
  return <ResponseHistory key={deviceId || 'all'} deviceId={deviceId} />
}
