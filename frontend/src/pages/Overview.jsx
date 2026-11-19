import { useNavigate } from 'react-router'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'
import { formatTime, timeAgo } from '../format'
import { usePolling } from '../usePolling'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low']

export default function Overview() {
  const navigate = useNavigate()
  const { data: status, error } = usePolling('/api/system/status')
  const { data: incidents, error: incidentError } = usePolling('/api/incidents?limit=6')

  if (error && !status) return <p className="error">Could not load the status: {error}</p>
  if (!status) return <p className="muted">Loading...</p>

  const counts = status.open_by_severity
  const highest = Math.max(1, ...Object.values(counts))
  const urgent = counts.Critical + counts.High

  return (
    <>
      <div className="stats">
        <StatCard label="Devices" value={status.devices} note={'last seen ' + timeAgo(status.last_device_seen_at)} />
        <StatCard label="Online now" value={status.online_devices} note="seen in the last 5 min" />
        <StatCard
          label="Open incidents"
          value={status.open_incidents}
          note={urgent > 0 ? urgent + ' high or critical' : 'nothing urgent'}
          color={urgent > 0 ? 'var(--high)' : undefined}
        />
        <StatCard
          label="Monitoring"
          value={status.monitoring.toUpperCase()}
          note={status.monitoring_since ? 'since ' + formatTime(status.monitoring_since) : 'not running'}
          color={status.monitoring === 'on' ? 'var(--accent)' : 'var(--muted)'}
        />
      </div>

      <div className="columns">
        <section className="panel">
          <h2>Open incidents by severity</h2>
          {SEVERITIES.map((severity) => (
            <div className="bar-row" key={severity}>
              <span>{severity}</span>
              <div className="bar">
                <div className={'bar-fill ' + severity.toLowerCase()} style={{ width: (counts[severity] / highest) * 100 + '%' }} />
              </div>
              <b>{counts[severity]}</b>
            </div>
          ))}
        </section>

        <section className="panel wide">
          <h2>Latest incidents</h2>
          {!incidents && <p className={incidentError ? 'error' : 'muted'}>{incidentError || 'Loading…'}</p>}
          {incidents && incidentError && <p className="muted small" role="status">Incident updates delayed.</p>}
          {incidents && incidents.length === 0 && <p className="muted">No incidents yet. The network looks quiet.</p>}
          {incidents && incidents.length > 0 && (
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
                {incidents.map((incident) => (
                  <tr key={incident.id} className="clickable" onClick={() => navigate('/incidents/' + incident.id)}>
                    <td>{formatTime(incident.created_at)}</td>
                    <td>{incident.rule_code}</td>
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
      </div>
    </>
  )
}
