import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import IncidentDetail from '../components/IncidentDetail'
import SeverityBadge from '../components/SeverityBadge'
import { formatTime, readable } from '../format'
import { usePolling } from '../usePolling'

export default function Incidents() {
  const { incidentId } = useParams()
  const navigate = useNavigate()
  const { data: incidents, error, reload } = usePolling('/api/incidents?limit=200', 10)
  const [status, setStatus] = useState('active')
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')

  if (error && !incidents) return <p className="error">Could not load the incidents: {error}</p>
  if (!incidents) return <p className="muted">Loading...</p>

  const count = (value) => incidents.filter((incident) => incident.status === value).length

  let shown = incidents
  if (status === 'active') shown = shown.filter((incident) => incident.status !== 'resolved')
  else if (status !== 'all') shown = shown.filter((incident) => incident.status === status)
  if (severity !== 'all') shown = shown.filter((incident) => incident.severity === severity)
  if (search) {
    const text = search.toLowerCase()
    shown = shown.filter((incident) =>
      [incident.source_ip, incident.target_ip, incident.rule_code].join(' ').toLowerCase().includes(text),
    )
  }

  return (
    <>
      <div className="summary">
        <span><b className={count('open') > 0 ? 'orange' : ''}>{count('open')}</b> open</span>
        <span><b>{count('investigating')}</b> investigating</span>
        <span><b>{count('resolved')}</b> resolved</span>
      </div>

      <div className={incidentId ? 'incidents-layout with-detail' : 'incidents-layout'}>
        <section className="panel wide">
          <div className="toolbar">
            <input className="search" placeholder="Search IP or rule" value={search} onChange={(e) => setSearch(e.target.value)} />
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="active">Open and investigating</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="all">All</option>
            </select>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="all">Any severity</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {incidents.length === 0 ? (
            <p className="muted">No incidents yet. The network looks quiet.</p>
          ) : shown.length === 0 ? (
            <p className="muted">No incident matches these filters.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Rule</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((incident) => (
                  <tr
                    key={incident.id}
                    className={String(incident.id) === incidentId ? 'clickable selected' : 'clickable'}
                    onClick={() => navigate('/incidents/' + incident.id)}
                  >
                    <td>{formatTime(incident.created_at)}</td>
                    <td>{readable(incident.rule_code)}</td>
                    <td className="mono">{incident.source_ip}</td>
                    <td className="mono">{incident.target_ip}</td>
                    <td><SeverityBadge severity={incident.severity} /></td>
                    <td className="capitalize">{incident.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {incidentId && (
          <IncidentDetail key={incidentId} id={incidentId} onChange={reload} onClose={() => navigate('/incidents')} />
        )}
      </div>
    </>
  )
}