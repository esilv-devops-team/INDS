import { ArrowUpRight, Network, Router, Server, Wifi } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { timeAgo, toDate } from '../format'
import { usePolling } from '../usePolling'
import './Topology.css'

const PAGE_SIZE = 12
const RECENT_MS = 5 * 60 * 1000

function NodeDetails({ node }) {
  return (
    <aside className="topology-inspector panel" aria-label="Selected node">
      <h2>{node.title}</h2>
      {node.description && <p className="muted">{node.description}</p>}
      <dl>
        {node.facts.map(([label, value]) => (
          <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
        ))}
      </dl>
      {node.path && (
        <Link className="device-link topology-detail-link" to={node.path}>
          {node.action} <ArrowUpRight size={15} aria-hidden="true" />
        </Link>
      )}
    </aside>
  )
}

export default function Topology() {
  const inventory = usePolling('/api/devices')
  const gateway = usePolling('/api/gateway/health', 10)
  const [selection, setSelection] = useState('gateway')
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [page, setPage] = useState(0)
  const devices = inventory.data || []
  const now = inventory.updatedAt?.getTime()
  const recent = (device) => now - toDate(device.last_seen_at).getTime() < RECENT_MS
  const bridge = gateway.data?.interfaces.find((item) => item.is_bridge)
  const backbone = [
    {
      key: 'router', title: 'Upstream router', icon: Router, caption: 'DHCP and internet',
      description: 'The upstream router provides addressing and internet access in the INDS deployment.',
      facts: [['Role', 'Default gateway'], ['Identity', 'Unreported']],
    },
    {
      key: 'gateway', title: 'INDS gateway', icon: Server,
      caption: bridge ? bridge.name + (bridge.is_up ? ' · Up' : ' · Down') : 'Inline bridge',
      facts: [
        ['Host', gateway.data?.system.hostname || 'Unknown'],
        ['Bridge', bridge ? bridge.name : 'Unreported'],
        ['Bridge status', bridge ? (bridge.is_up ? 'Up' : 'Down') : 'Unknown'],
      ],
      path: '/gateway', action: 'View gateway health',
    },
    {
      key: 'ap', title: 'Guest access point', icon: Wifi, caption: 'Guest network',
      description: 'Device observations represent the guest inventory. Individual Wi-Fi associations are unreported.',
      facts: [['Role', 'Guest Wi-Fi'], ['Identity', 'Unreported']],
    },
  ]

  const needle = search.trim().toLowerCase()
  const matches = devices.filter((device) => {
    const identity = [device.hostname, device.mac_address, device.current_ip].join(' ').toLowerCase()
    return identity.includes(needle) && (
      filter === 'all' || (filter === 'recent' && recent(device)) || (filter === 'incidents' && device.open_incidents > 0)
    )
  })
  const currentPage = Math.min(page, Math.max(0, Math.ceil(matches.length / PAGE_SIZE) - 1))
  const start = currentPage * PAGE_SIZE
  const selectedDevice = devices.find((device) => device.id === selection)
  const inspected = selectedDevice ? {
    title: selectedDevice.hostname || selectedDevice.mac_address,
    facts: [
      ['IP address', selectedDevice.current_ip || 'Unknown'],
      ['MAC address', selectedDevice.mac_address],
      ['Last observed', timeAgo(selectedDevice.last_seen_at, now)],
      ['Trust', selectedDevice.is_trusted ? 'Trusted' : 'Not trusted'],
      ['Active incidents', selectedDevice.open_incidents],
    ],
    path: '/devices/' + selectedDevice.id,
    action: 'Investigate device',
  } : backbone.find((node) => node.key === selection) || backbone[1]

  return (
    <div className="topology-layout">
      <section className="panel topology-map" aria-label="Network map">
        <header className="topology-header">
          <h2>Network map</h2>
          <span className="topology-legend muted small">Deployment layout · Observed inventory</span>
        </header>
        {gateway.error && <p className="muted small" role="status">Gateway health refresh failed.</p>}
        <div className="topology-backbone" role="group" aria-label="Deployment layout">
          {backbone.map(({ key, title, caption, icon: Icon }) => (
            <button key={key} type="button" className="topology-node" aria-pressed={selection === key} onClick={() => setSelection(key)}>
              <Icon size={22} aria-hidden="true" />
              <strong>{title}</strong>
              <span className="muted small">{caption}</span>
            </button>
          ))}
        </div>
        <section className="topology-inventory" aria-labelledby="topology-devices">
          <header className="topology-header">
            <h3 id="topology-devices">Observed devices <span className="badge">{devices.length}</span></h3>
            <div className="toolbar topology-controls">
              <input className="search" aria-label="Search topology devices" placeholder="Search name, IP or MAC" value={search}
                onChange={(event) => { setSearch(event.target.value); setPage(0) }} />
              <select aria-label="Filter topology devices" value={filter}
                onChange={(event) => { setFilter(event.target.value); setPage(0) }}>
                <option value="all">All devices</option>
                <option value="recent">Recently seen</option>
                <option value="incidents">Active incidents</option>
              </select>
            </div>
          </header>
          {inventory.error && <p className="error" role="status">{inventory.error}</p>}
          {inventory.data ? (
            matches.length ? (
              <div className="topology-devices">
                {matches.slice(start, start + PAGE_SIZE).map((device) => (
                  <button key={device.id} type="button" className="topology-node topology-device"
                    aria-pressed={selection === device.id} onClick={() => setSelection(device.id)}>
                    <Network size={17} aria-hidden="true" />
                    <strong>{device.hostname || device.mac_address}</strong>
                    <span className="muted small mono">{device.current_ip || 'IP unknown'}</span>
                    <span className={recent(device) ? 'status online' : 'status'}><span className="dot" />{recent(device) ? 'Recently seen' : 'Inactive'}</span>
                    {device.open_incidents > 0 && <span className="badge high">{device.open_incidents} active</span>}
                  </button>
                ))}
              </div>
            ) : <p className="muted topology-empty">{devices.length ? 'No matching devices.' : 'No devices have been observed yet.'}</p>
          ) : !inventory.error && <p className="muted topology-empty">Loading device inventory…</p>}
          {matches.length > PAGE_SIZE && (
            <div className="device-pagination">
              <button className="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button>
              <span className="muted small">{start + 1}–{Math.min(start + PAGE_SIZE, matches.length)} of {matches.length}</span>
              <button className="button" disabled={start + PAGE_SIZE >= matches.length} onClick={() => setPage(currentPage + 1)}>Next</button>
            </div>
          )}
        </section>
      </section>
      <NodeDetails node={inspected} />
    </div>
  )
}
