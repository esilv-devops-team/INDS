import { Pause, Play, Trash2 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api'
import { axisProps, colors, tooltipProps } from '../chartTheme'
import { formatTime, readable } from '../format'
import MonitoringPanel from '../components/MonitoringPanel'
import StatCard from '../components/StatCard'
import './LiveNetwork.css'

const KEEP = 500
const PROTOCOLS = ['All', 'TCP', 'UDP', 'ARP', 'ICMP', 'ICMPv6', 'IP']
const FLAG_NAMES = { S: 'SYN', A: 'ACK', F: 'FIN', R: 'RST', P: 'PSH', U: 'URG', E: 'ECE', C: 'CWR' }

const EVENTS = {
  'incident.created': (details) => readable(details.rule || 'incident') + ' detected (' + details.severity + ')',
  'incident.escalated': (details) => 'Severity raised from ' + details.from + ' to ' + details.to,
  'ai_analysis.attached': (details) => 'AI analysis done' + (details.risk_level ? ' (risk ' + details.risk_level + ')' : ''),
  'ai_analysis.failed': () => 'AI analysis failed',
  'response_action.proposed': () => 'Block proposed',
  'response_action.approved': () => 'Block approved',
  'response_action.rejected': () => 'Block rejected',
  'response_action.applied': () => 'Device blocked on the gateway',
  'response_action.cleared': () => 'Block removed',
}

function clock(seconds) {
  const date = new Date(seconds * 1000)
  return date.toLocaleTimeString('en-GB') + '.' + String(date.getMilliseconds()).padStart(3, '0')
}

function flagText(flags) {
  return flags.split('').map((flag) => FLAG_NAMES[flag] || flag).join(', ')
}

function rowClass(packet, selected) {
  const names = ['proto-' + packet.protocol.toLowerCase()]
  if (packet.mode === 'watch') names.push('unprotected')
  if (packet.incident_id) names.push('flagged')
  if (packet.dropped) names.push('dropped')
  if (selected) names.push('selected')
  return names.join(' ')
}

function matches(packet, text, protocol) {
  if (protocol !== 'All' && packet.protocol !== protocol) return false
  if (!text) return true
  const search = text.toLowerCase()
  return [packet.source_ip, packet.destination_ip, packet.source_mac, packet.destination_mac, packet.protocol, packet.info]
    .some((value) => value && value.toLowerCase().includes(search))
}

function ModeBanner({ mode, secondsLeft, busy, onWatch, onStop }) {
  if (mode === 'protect') {
    return (
      <div className="live-mode protect">
        <b>INDS is ON</b>
        <span>Every packet goes through detection. Attacks become incidents, the AI analyses them and approved blocks drop the traffic.</span>
      </div>
    )
  }
  if (mode === 'watch') {
    return (
      <div className="live-mode watch">
        <b>Watching without INDS</b>
        <span>
          Packets are only displayed, nothing is detected, analysed or blocked.
          {secondsLeft !== null && ' Stops in ' + Math.floor(secondsLeft / 60) + ':' + String(secondsLeft % 60).padStart(2, '0') + '.'}
        </span>
        <button className="button small secondary" disabled={busy} onClick={onStop}>Stop watching</button>
      </div>
    )
  }
  return (
    <div className="live-mode off">
      <b>INDS is OFF</b>
      <span>Nothing is captured. Watch the traffic without INDS, or turn monitoring on to protect the network.</span>
      <button className="button small" disabled={busy} onClick={onWatch}>Watch traffic without INDS</button>
    </div>
  )
}

function PacketDetails({ packet }) {
  if (!packet) return <p className="muted small live-hint">Click a packet to see its headers.</p>
  return (
    <div className="packet-details mono">
      <div>Frame {packet.number}: {packet.length} bytes captured at {clock(packet.time)}</div>
      <div>Ethernet II, Src: {packet.source_mac}, Dst: {packet.destination_mac}</div>
      <div>
        {packet.protocol === 'ARP' ? 'Address Resolution Protocol' : 'Internet Protocol'}, Src: {packet.source_ip}, Dst: {packet.destination_ip}
      </div>
      {packet.source_port !== null && (
        <div>
          {packet.protocol === 'TCP' ? 'Transmission Control Protocol' : 'User Datagram Protocol'}, Src Port: {packet.source_port}, Dst
          Port: {packet.destination_port}
          {packet.tcp_flags && ', Flags: ' + flagText(packet.tcp_flags)}
        </div>
      )}
      <div className="inds-line">
        INDS:{' '}
        {packet.mode === 'watch' && 'not inspected, INDS was off'}
        {packet.mode === 'protect' && !packet.incident_id && 'inspected, no incident for this device'}
        {packet.incident_id && <>source has <Link to={'/incidents/' + packet.incident_id}>incident #{packet.incident_id}</Link></>}
        {packet.dropped && ', dropped by the gateway firewall'}
      </div>
    </div>
  )
}

function RateChart({ rates }) {
  const points = rates.map((count, index) => ({ second: index - rates.length + 1, count }))
  return (
    <ResponsiveContainer width="100%" height={130}>
      <AreaChart data={points} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
        <XAxis dataKey="second" {...axisProps} tickFormatter={(value) => value + 's'} interval={14} />
        <YAxis {...axisProps} allowDecimals={false} />
        <Tooltip {...tooltipProps} labelFormatter={(value) => value + ' s'} formatter={(value) => [value, 'packets']} />
        <Area type="monotone" dataKey="count" stroke={colors.download} fill={colors.download} fillOpacity={0.2}
          isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function TopTalkers({ packets }) {
  const counts = {}
  for (const packet of packets) {
    counts[packet.source_ip] = (counts[packet.source_ip] || 0) + 1
  }
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5)
  if (top.length === 0) return <p className="muted small">No packets yet.</p>
  return (
    <ul className="talkers">
      {top.map(([address, count]) => (
        <li key={address}>
          <span className="mono">{address}</span>
          <div className="bar"><div className="bar-fill" style={{ width: (count / top[0][1]) * 100 + '%' }} /></div>
          <b>{count}</b>
        </li>
      ))}
    </ul>
  )
}

function EventFeed({ events }) {
  if (events.length === 0) return <p className="muted small">No incidents or responses yet.</p>
  return (
    <ul className="live-events">
      {[...events].reverse().map((event) => (
        <li key={event.id} className={event.event_type.split('.')[0].replace('_', '-')}>
          <span className="muted small">{formatTime(event.occurred_at)}</span>
          <Link to={'/incidents/' + event.incident_id}>#{event.incident_id}</Link>{' '}
          {(EVENTS[event.event_type] || (() => readable(event.event_type.replace('.', '_'))))(event.details)}
        </li>
      ))}
    </ul>
  )
}

export default function LiveNetwork() {
  const [live, setLive] = useState({ mode: null, watch_seconds_left: null, rates: [], packets: [] })
  const [events, setEvents] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [frozen, setFrozen] = useState(null)
  const [selected, setSelected] = useState(null)
  const [text, setText] = useState('')
  const [protocol, setProtocol] = useState('All')
  const lastPacket = useRef(0)
  const lastEvent = useRef(0)
  const tableBox = useRef(null)
  const refresh = useRef(null)

  useEffect(() => {
    async function loadPackets() {
      try {
        const data = await api('/api/live?after=' + lastPacket.current)
        const restarted = data.last < lastPacket.current
        lastPacket.current = data.last
        setLive((old) => ({ ...data, packets: [...(restarted ? [] : old.packets), ...data.packets].slice(-KEEP) }))
        setError('')
      } catch (err) {
        setError(err.message)
      }
    }

    async function loadEvents() {
      try {
        const data = await api('/api/live/events?after=' + lastEvent.current)
        if (data.length > 0) {
          lastEvent.current = data[data.length - 1].id
          setEvents((old) => [...old, ...data].slice(-30))
        }
      } catch {
        return
      }
    }

    refresh.current = loadPackets
    const first = setTimeout(() => {
      loadPackets()
      loadEvents()
    }, 0)
    const packetTimer = setInterval(loadPackets, 1000)
    const eventTimer = setInterval(loadEvents, 2000)
    return () => {
      clearTimeout(first)
      clearInterval(packetTimer)
      clearInterval(eventTimer)
    }
  }, [])

  const shown = (frozen || live.packets).filter((packet) => matches(packet, text, protocol))

  useEffect(() => {
    if (!frozen && tableBox.current) tableBox.current.scrollTop = tableBox.current.scrollHeight
  }, [live.packets, frozen])

  async function changeWatch(method) {
    setBusy(true)
    try {
      await api('/api/live/watch', { method })
      setError('')
    } catch (err) {
      setError(err.message)
    }
    setBusy(false)
    refresh.current()
  }

  const selectedPacket = selected && (frozen || live.packets).find((packet) => packet.number === selected)
  const flagged = live.packets.filter((packet) => packet.incident_id).length
  const dropped = live.packets.filter((packet) => packet.dropped).length
  const rate = live.rates.length > 1 ? live.rates[live.rates.length - 2] : 0

  return (
    <>
      <MonitoringPanel />
      {live.mode && (
        <ModeBanner mode={live.mode} secondsLeft={live.watch_seconds_left} busy={busy}
          onWatch={() => changeWatch('POST')} onStop={() => changeWatch('DELETE')} />
      )}
      {error && <p className="error live-error">{error}</p>}

      <div className="stats">
        <StatCard label="Packets per second" value={rate} note={live.interface ? 'on ' + live.interface : 'no interface set'} />
        <StatCard label="Packets in view" value={live.packets.length} note={'last ' + KEEP + ' kept'} />
        <StatCard label="From devices with an incident" value={flagged} color={flagged ? 'var(--high)' : undefined} />
        <StatCard label="Dropped by INDS" value={dropped} color={dropped ? 'var(--critical)' : undefined} />
      </div>

      <div className="live-layout">
        <section className="panel live-packets">
          <div className="toolbar">
            <input className="search" placeholder="Filter: address, MAC, protocol or info" value={text}
              onChange={(event) => setText(event.target.value)} />
            <select value={protocol} onChange={(event) => setProtocol(event.target.value)}>
              {PROTOCOLS.map((name) => <option key={name}>{name}</option>)}
            </select>
            <button className="button small secondary" onClick={() => setFrozen(frozen ? null : live.packets)}>
              {frozen ? <><Play size={14} /> Resume</> : <><Pause size={14} /> Pause</>}
            </button>
            <button className="button small secondary" title="Clear the list" onClick={() => {
              setLive((old) => ({ ...old, packets: [] }))
              setFrozen(null)
              setSelected(null)
            }}>
              <Trash2 size={14} />
            </button>
            <span className="muted small">{shown.length} shown{frozen && ', paused'}</span>
          </div>

          <div className="packet-box" ref={tableBox}>
            <table className="packet-table mono">
              <thead>
                <tr>
                  <th>No.</th>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Length</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((packet) => (
                  <tr key={packet.number} className={rowClass(packet, packet.number === selected)}
                    onClick={() => setSelected(packet.number)}>
                    <td>{packet.number}</td>
                    <td>{clock(packet.time)}</td>
                    <td>{packet.source_ip}</td>
                    <td>{packet.destination_ip}</td>
                    <td>{packet.protocol}</td>
                    <td>{packet.length}</td>
                    <td>
                      {packet.dropped && <span className="tag dropped">DROPPED</span>}
                      {packet.incident_id && <span className="tag incident">#{packet.incident_id}</span>}
                      {packet.info}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && (
              <p className="muted live-hint">
                {live.mode === 'off' ? 'No capture running.' : 'Waiting for packets...'}
              </p>
            )}
          </div>
          <PacketDetails packet={selectedPacket} />
        </section>

        <aside className="live-side">
          <section className="panel">
            <h3>Packets per second (60 s)</h3>
            <RateChart rates={live.rates} />
          </section>
          <section className="panel">
            <h3>Busiest sources</h3>
            <TopTalkers packets={live.packets} />
          </section>
          <section className="panel">
            <h3>Incidents and responses</h3>
            <EventFeed events={events} />
          </section>
        </aside>
      </div>
    </>
  )
}
