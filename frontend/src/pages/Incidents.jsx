import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import IncidentDetail from '../components/IncidentDetail'
import SeverityBadge from '../components/SeverityBadge'
import { formatTime, readable } from '../format'
import { usePolling } from '../usePolling'

const PAGE_SIZE = 50

function IncidentPage({ filters, page, last, selected, changes, onMore }) {
  const navigate = useNavigate()
  const path = '/api/incidents?limit=' + (PAGE_SIZE + 1) + '&offset=' + page * PAGE_SIZE + filters
  const { data, error, reload } = usePolling(path)

  useEffect(() => {
    if (changes > 0) reload()
  }, [changes, reload])

  if (!data) {
    return (
      <tbody>
        <tr><td colSpan="6" className={error ? 'error' : 'muted'}>{error || 'Loading...'}</td></tr>
      </tbody>
    )
  }

  return (
    <tbody>
      {page === 0 && data.length === 0 && (
        <tr><td colSpan="6" className="muted">No incident matches these filters.</td></tr>
      )}
      {data.slice(0, PAGE_SIZE).map((incident) => (
        <tr
          key={incident.id}
          className={String(incident.id) === selected ? 'clickable selected' : 'clickable'}
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
      {last && data.length > PAGE_SIZE && (
        <tr>
          <td colSpan="6" className="load-more">
            <button className="button small secondary" onClick={onMore}>Load {PAGE_SIZE} more</button>
          </td>
        </tr>
      )}
    </tbody>
  )
}

export default function Incidents() {
  const { incidentId } = useParams()
  const navigate = useNavigate()
  const { data: counts, reload: reloadCounts } = usePolling('/api/incidents/counts')
  const [status, setStatus] = useState('active')
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [pages, setPages] = useState(1)
  const [changes, setChanges] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim())
      setPages(1)
    }, 400)
    return () => clearTimeout(timer)
  }, [search])

  function changeFilter(setter, value) {
    setter(value)
    setPages(1)
  }

  function incidentChanged() {
    reloadCounts()
    setChanges(changes + 1)
  }

  let filters = ''
  if (status !== 'all') filters += '&status=' + status
  if (severity !== 'all') filters += '&severity=' + severity
  if (query) filters += '&search=' + encodeURIComponent(query)

  const total = counts ? counts.open + counts.investigating + counts.resolved : null

  return (
    <>
      <div className="summary">
        <span><b className={counts?.open > 0 ? 'orange' : ''}>{counts ? counts.open : '-'}</b> open</span>
        <span><b>{counts ? counts.investigating : '-'}</b> investigating</span>
        <span><b>{counts ? counts.resolved : '-'}</b> resolved</span>
      </div>

      <div className={incidentId ? 'incidents-layout with-detail' : 'incidents-layout'}>
        <section className="panel wide">
          <div className="toolbar">
            <input className="search" placeholder="Search IP or rule" value={search} onChange={(e) => setSearch(e.target.value)} />
            <select value={status} onChange={(e) => changeFilter(setStatus, e.target.value)}>
              <option value="active">Open and investigating</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="all">All</option>
            </select>
            <select value={severity} onChange={(e) => changeFilter(setSeverity, e.target.value)}>
              <option value="all">Any severity</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {total === 0 ? (
            <p className="muted">No incidents yet. The network looks quiet.</p>
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
              {Array.from({ length: pages }, (_, page) => (
                <IncidentPage
                  key={filters + '-' + page}
                  filters={filters}
                  page={page}
                  last={page === pages - 1}
                  selected={incidentId}
                  changes={changes}
                  onMore={() => setPages(pages + 1)}
                />
              ))}
            </table>
          )}
        </section>

        {incidentId && (
          <IncidentDetail key={incidentId} id={incidentId} onChange={incidentChanged} onClose={() => navigate('/incidents')} />
        )}
      </div>
    </>
  )
}