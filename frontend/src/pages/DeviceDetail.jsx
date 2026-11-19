import { Activity, ArrowLeft, ArrowUpRight, Network, Shield } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { axisProps, colors, tooltipProps } from '../chartTheme'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'
import { formatBytes, formatRate, formatTime, readable, timeAgo, toDate, wasRecentlySeen } from '../format'
import { usePolling } from '../usePolling'

const WINDOWS = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']]
const PAGE_SIZE = 10

function TrafficWindow({ path, period }) {
  const { data, error } = usePolling(path + '/traffic/history?window=' + period, 20)
  const { data: rates } = usePolling(path + '/traffic', 10)
  if (!data) return <p className={error ? 'error' : 'muted'}>{error || 'Loading traffic…'}</p>

  const points = data.buckets.map((point) => ({
    start: point.start,
    download: point.download / point.seconds,
    upload: point.upload / point.seconds,
  }))
  const tickFormat = (value) => toDate(value).toLocaleString('en-GB', period === '7d'
    ? { weekday: 'short', hour: '2-digit' }
    : { hour: '2-digit', minute: '2-digit' })

  return (
    <>
      <div className="device-metrics">
        <StatCard label="Downloaded" value={formatBytes(data.download)} note={rates && formatRate(rates.download_bps / 8) + ' recent average'} />
        <StatCard label="Uploaded" value={formatBytes(data.upload)} note={rates && formatRate(rates.upload_bps / 8) + ' recent average'} />
        <StatCard label="Packets" value={data.packets.toLocaleString()} note="Sent and received" />
      </div>
      {error && <p className="muted small" role="status">Traffic refresh failed. Showing the last available data.</p>}
      {data.download + data.upload > 0 ? (
        <div className="device-chart">
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={points} margin={{ top: 10, right: 12, left: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="device-download" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor={colors.download} stopOpacity={0.36} />
                  <stop offset="100%" stopColor={colors.download} stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="device-upload" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor={colors.upload} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={colors.upload} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} stroke={colors.grid} />
              <XAxis dataKey="start" tickFormatter={tickFormat} minTickGap={24} {...axisProps} />
              <YAxis tickFormatter={formatRate} width={80} {...axisProps} />
              <Tooltip {...tooltipProps} labelFormatter={formatTime} formatter={formatRate} />
              <Legend iconType="plainline" />
              <Area dataKey="download" name="Download" stroke={colors.download} strokeWidth={2} fill="url(#device-download)" isAnimationActive={false} />
              <Area dataKey="upload" name="Upload" stroke={colors.upload} strokeWidth={2} fill="url(#device-upload)" isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      ) : <p className="device-empty muted">No traffic was recorded for this device in this period.</p>}
      <p className="muted small">Chart points average {data.bucket_minutes} minutes. Recent rates use the last five completed minutes.</p>
    </>
  )
}

function IncidentPage({ deviceId, status, page, onPage }) {
  const filter = status ? '&status=' + status : ''
  const path = '/api/incidents?source_device_id=' + deviceId + '&limit=' + (PAGE_SIZE + 1) + '&offset=' + page * PAGE_SIZE + filter
  const { data, error } = usePolling(path)
  if (!data) return <p className={error ? 'error' : 'muted'}>{error || 'Loading incidents…'}</p>

  return (
    <>
      {error && <p className="muted small" role="status">Incident refresh failed. Showing the last available data.</p>}
      {data.length ? (
        <ol className="device-timeline">
          {data.slice(0, PAGE_SIZE).map((incident) => (
            <li key={incident.id}>
              <Link to={'/incidents/' + incident.id} className="device-incident">
                <div>
                  <strong>{readable(incident.rule_code)}</strong>
                  <div className="muted small">#{incident.id} · {formatTime(incident.created_at)}</div>
                </div>
                <SeverityBadge severity={incident.severity} />
                <span className="muted">{readable(incident.status)}</span>
                <ArrowUpRight size={16} aria-hidden="true" />
              </Link>
            </li>
          ))}
        </ol>
      ) : <p className="device-empty muted">{page ? 'No more incidents.' : 'No matching incidents for this device.'}</p>}
      {(page > 0 || data.length > PAGE_SIZE) && (
        <div className="device-pagination">
          <button className="button" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</button>
          <span className="muted small">Page {page + 1}</span>
          <button className="button" disabled={data.length <= PAGE_SIZE} onClick={() => onPage(page + 1)}>Next</button>
        </div>
      )}
    </>
  )
}

function Investigation({ deviceId }) {
  const path = '/api/devices/' + deviceId
  const { data: device, error, updatedAt } = usePolling(path)
  const [period, setPeriod] = useState('24h')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(0)

  if (!device) return <p className={error ? 'error' : 'muted'}>{error || 'Loading device…'}</p>

  const recentlySeen = wasRecentlySeen(device.last_seen_at, updatedAt.getTime())
  const facts = [
    ['IP address', device.current_ip || 'Unknown'],
    ['MAC address', device.mac_address],
    ['Manufacturer', device.vendor === 'Randomized' ? 'Private MAC' : device.vendor || 'Unknown'],
    ['First seen', formatTime(device.first_seen_at)],
    ['Last seen', formatTime(device.last_seen_at)],
  ]

  return (
    <div className="device-investigation">
      {error && <p className="muted small" role="status">Device refresh failed. Showing the last available data.</p>}
      <section className="panel device-profile">
        <div className="device-profile-head">
          <div className="device-profile-icon"><Network size={24} aria-hidden="true" /></div>
          <div className="device-profile-name">
            <h2>{device.hostname || device.mac_address}</h2>
            <span className="muted small">Last observed {timeAgo(device.last_seen_at, updatedAt.getTime())}</span>
          </div>
          <div className="device-status">
            <span className={recentlySeen ? 'status online' : 'status'}><span className="dot" />{recentlySeen ? 'Recently seen' : 'Inactive'}</span>
            <span className="tag">{device.is_trusted ? 'Trusted' : 'Not trusted'}</span>
            <Link className="device-link small" to={'/responses?device_id=' + device.id}>Response history</Link>
          </div>
        </div>
        <dl className="device-facts">
          {facts.map(([label, value], index) => (
            <div key={label}><dt>{label}</dt><dd className={index < 2 ? 'mono' : undefined}>{value}</dd></div>
          ))}
        </dl>
      </section>

      <section className="panel">
        <div className="device-section-head">
          <h2><Activity size={17} aria-hidden="true" /> Traffic activity</h2>
          <div className="segmented">
            {WINDOWS.map(([key, label]) => (
              <button key={key} className={period === key ? 'active' : ''} onClick={() => setPeriod(key)} aria-pressed={period === key}>{label}</button>
            ))}
          </div>
        </div>
        <TrafficWindow key={period} path={path} period={period} />
      </section>

      <section className="panel">
        <div className="device-section-head">
          <h2><Shield size={17} aria-hidden="true" /> Incident history <span className="badge">{device.open_incidents} active</span></h2>
          <select aria-label="Filter incidents by status" value={status} onChange={(event) => { setStatus(event.target.value); setPage(0) }}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
        <IncidentPage key={status + page} deviceId={deviceId} status={status} page={page} onPage={setPage} />
      </section>
    </div>
  )
}

export default function DeviceDetail() {
  const { deviceId } = useParams()
  return (
    <>
      <Link className="device-back device-link" to="/devices"><ArrowLeft size={16} aria-hidden="true" /> All devices</Link>
      <Investigation key={deviceId} deviceId={deviceId} />
    </>
  )
}
