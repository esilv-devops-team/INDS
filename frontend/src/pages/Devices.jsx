import { RefreshCw, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '../api'
import { formatTime, timeAgo, toDate } from '../format'
import { usePolling } from '../usePolling'

const ONLINE_MINUTES = 5

function isOnline(device) {
  return Date.now() - toDate(device.last_seen_at).getTime() < ONLINE_MINUTES * 60 * 1000
}

function matches(device, search) {
  const text = [device.hostname, device.current_ip, device.mac_address, device.vendor].join(' ').toLowerCase()
  return text.includes(search.toLowerCase())
}

export default function Devices() {
  const { data: devices, error, updatedAt, reload } = usePolling('/api/devices', 10)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [saving, setSaving] = useState(null)
  const [actionError, setActionError] = useState('')

  async function toggleTrust(device) {
    setSaving(device.id)
    setActionError('')
    try {
      await api('/api/devices/' + device.id, { method: 'PATCH', body: { is_trusted: !device.is_trusted } })
      reload()
    } catch (err) {
      setActionError('Could not update ' + (device.hostname || device.mac_address) + ': ' + err.message)
    }
    setSaving(null)
  }

  if (error && !devices) return <p className="error">Could not load the devices: {error}</p>
  if (!devices) return <p className="muted">Loading...</p>

  const online = devices.filter(isOnline)
  const atRisk = devices.filter((device) => device.open_incidents > 0)
  const trusted = devices.filter((device) => device.is_trusted)

  let shown = devices.filter((device) => matches(device, search))
  if (filter === 'online') shown = shown.filter(isOnline)
  if (filter === 'offline') shown = shown.filter((device) => !isOnline(device))
  if (filter === 'risk') shown = shown.filter((device) => device.open_incidents > 0)
  if (filter === 'trusted') shown = shown.filter((device) => device.is_trusted)

  return (
    <>
      <div className="summary">
        <span><b>{devices.length}</b> devices</span>
        <span><b className="green">{online.length}</b> online</span>
        <span><b>{devices.length - online.length}</b> offline</span>
        <span><b className={atRisk.length > 0 ? 'orange' : ''}>{atRisk.length}</b> at risk</span>
        <span><b>{trusted.length}</b> trusted</span>
      </div>

      <section className="panel wide">
        <div className="toolbar">
          <input
            className="search"
            placeholder="Search name, IP, MAC or manufacturer"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All devices</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="risk">At risk</option>
            <option value="trusted">Trusted</option>
          </select>
          <span className="muted updated">
            {error ? 'Connection problem, retrying...' : 'Updated ' + updatedAt.toLocaleTimeString('en-GB')}
          </span>
          <button className="icon-button" onClick={reload} title="Refresh now">
            <RefreshCw size={16} />
          </button>
        </div>

        {actionError && <p className="error">{actionError}</p>}

        {devices.length === 0 ? (
          <p className="muted">No devices yet. Start the discovery sniffer on the gateway and they will show up here.</p>
        ) : shown.length === 0 ? (
          <p className="muted">No device matches this search.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Device</th>
                <th>IP address</th>
                <th>Manufacturer</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th>Incidents</th>
                <th>Trusted</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((device) => (
                <tr key={device.id}>
                  <td>
                    <span className={isOnline(device) ? 'status online' : 'status'}>
                      <span className="dot" />
                      {isOnline(device) ? 'Online' : 'Offline'}
                    </span>
                  </td>
                  <td>
                    <Link className="device-link" to={'/devices/' + device.id}>
                      {device.hostname || device.mac_address}
                    </Link>
                    {device.hostname && <div className="mono muted">{device.mac_address}</div>}
                  </td>
                  <td className="mono">{device.current_ip || '-'}</td>
                  <td>
                    {device.vendor === 'Randomized' ? (
                      <span className="tag" title="The device hides its real MAC address">Private MAC</span>
                    ) : (
                      device.vendor || 'Unknown'
                    )}
                  </td>
                  <td>{formatTime(device.first_seen_at)}</td>
                  <td>{timeAgo(device.last_seen_at)}</td>
                  <td>
                    {device.open_incidents > 0 ? (
                      <span className="badge high">{device.open_incidents} open</span>
                    ) : (
                      <span className="muted">None</span>
                    )}
                  </td>
                  <td>
                    <button
                      className={device.is_trusted ? 'trust-button trusted' : 'trust-button'}
                      onClick={() => toggleTrust(device)}
                      disabled={saving === device.id}
                    >
                      <ShieldCheck size={15} />
                      {device.is_trusted ? 'Trusted' : 'Not trusted'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
