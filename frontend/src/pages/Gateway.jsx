import { ArrowDown, ArrowUp } from 'lucide-react'
import Meter from '../components/Meter'
import { formatBytes, formatRate, formatUptime } from '../format'
import { usePolling } from '../usePolling'

function temperatureNote(temperature) {
  if (temperature === null) return 'no sensor on this machine'
  if (temperature >= 80) return 'too hot, the Pi slows down'
  if (temperature >= 70) return 'warm'
  return 'normal'
}

export default function Gateway() {
  const { data: health, error, updatedAt } = usePolling('/api/gateway/health', 5)
  const rules = usePolling('/api/detection/rules', 30)

  if (error && !health) return <p className="error">Could not load the gateway health: {error}</p>
  if (!health) return <p className="muted">Loading...</p>

  const { system, interfaces, services } = health
  const problems = services.filter((service) => service.state === 'down').length

  return (
    <>
      <div className="summary">
        <span><b>{system.hostname}</b></span>
        <span>{system.platform}</span>
        <span>up {formatUptime(system.uptime_seconds)}</span>
        <span>load {system.load_average.join(' / ')}</span>
        <span className="muted updated">
          {error ? 'Connection problem, retrying...' : 'Updated ' + updatedAt.toLocaleTimeString('en-GB')}
        </span>
      </div>

      <section className="panel">
        <h2>Detection rules</h2>
        {rules.error && <p className="error">{rules.error}</p>}
        {!rules.data && !rules.error && <p className="muted">Loading rules…</p>}
        <ul className="services">
          {rules.data?.map((rule) => (
            <li key={rule.rule_code}>
              <div>
                <b>{rule.rule_code}</b>
                <div className="muted">{rule.description}</div>
                <div className="muted">{rule.severity} · {rule.cooldown_seconds}s cooldown</div>
              </div>
              <span>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
            </li>
          ))}
        </ul>
      </section>

      <div className="stats">
        <div className="stat-card">
          <span className="stat-label">CPU</span>
          <strong className="stat-value">{system.cpu_percent.toFixed(0)}%</strong>
          <Meter percent={system.cpu_percent} />
          <span className="stat-note">{system.cpu_count} cores</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Memory</span>
          <strong className="stat-value">{system.memory.percent.toFixed(0)}%</strong>
          <Meter percent={system.memory.percent} />
          <span className="stat-note">{formatBytes(system.memory.used)} of {formatBytes(system.memory.total)}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Temperature</span>
          <strong className="stat-value">{system.temperature === null ? '-' : system.temperature + ' °C'}</strong>
          {system.temperature !== null && <Meter percent={system.temperature} warn={70} danger={80} />}
          <span className="stat-note">{temperatureNote(system.temperature)}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Disk</span>
          <strong className="stat-value">{system.disk.percent.toFixed(0)}%</strong>
          <Meter percent={system.disk.percent} warn={80} danger={90} />
          <span className="stat-note">{formatBytes(system.disk.used)} of {formatBytes(system.disk.total)}</span>
        </div>
      </div>

      <div className="columns">
        <section className="panel">
          <h2>Services {problems > 0 && <span className="badge critical">{problems} down</span>}</h2>
          <ul className="services">
            {services.map((service) => (
              <li key={service.name}>
                <span className={'state ' + service.state} />
                <div>
                  <div>{service.name}</div>
                  <div className="muted small">{service.detail}</div>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel wide">
          <h2>Network interfaces</h2>
          {interfaces.length === 0 ? (
            <p className="muted">No network interface found.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Interface</th>
                  <th>State</th>
                  <th>Speed</th>
                  <th>Download</th>
                  <th>Upload</th>
                  <th>Total in / out</th>
                </tr>
              </thead>
              <tbody>
                {interfaces.map((item) => (
                  <tr key={item.name}>
                    <td className="mono">
                      {item.name} {(item.role || item.is_bridge) && <span className="tag">{item.role || 'bridge'}</span>}
                    </td>
                    <td>
                      <span className={item.is_up ? 'status online' : 'status'}>
                        <span className="dot" />
                        {item.is_up ? 'Up' : 'Down'}
                      </span>
                    </td>
                    <td>{item.speed_mbps ? item.speed_mbps + ' Mbit/s' : '-'}</td>
                    <td><ArrowDown size={13} className="muted" /> {formatRate(item.rx_rate)}</td>
                    <td><ArrowUp size={13} className="muted" /> {formatRate(item.tx_rate)}</td>
                    <td className="muted">{formatBytes(item.rx_bytes)} / {formatBytes(item.tx_bytes)}</td>
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
