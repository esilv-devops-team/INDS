import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useState } from 'react'
import StatCard from '../components/StatCard'
import { axisProps, colors, tooltipProps } from '../chartTheme'
import { formatBytes, toDate } from '../format'
import { usePolling } from '../usePolling'

const WINDOWS = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
]

const SEVERITY_ORDER = ['Low', 'Medium', 'High', 'Critical']

function axisLabel(value, period) {
  const date = toDate(value)
  const time = date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  if (period === '7d') {
    return date.toLocaleDateString('en-GB', { weekday: 'short' }) + ' ' + time
  }
  return time
}

function legendText(value) {
  return <span style={{ color: colors.text }}>{value}</span>
}

function fullLabel(value) {
  return toDate(value).toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

function toMbits(bytes, seconds) {
  return Math.round(((bytes * 8) / seconds / 1000000) * 100) / 100
}

export default function Statistics() {
  const [period, setPeriod] = useState('24h')
  const { data: stats, error, updatedAt } = usePolling('/api/statistics?window=' + period, 20)

  if (error && !stats) return <p className="error">Could not load the statistics: {error}</p>
  if (!stats) return <p className="muted">Loading...</p>

  const points = stats.buckets.map((bucket) => ({
    ...bucket,
    label: axisLabel(bucket.start, stats.window),
    downloadRate: toMbits(bucket.download, bucket.seconds),
    uploadRate: toMbits(bucket.upload, bucket.seconds),
  }))
  const peak = Math.max(0, ...points.map((point) => point.downloadRate + point.uploadRate))
  const biggest = Math.max(1, ...stats.top_devices.map((device) => device.total))
  const totals = stats.totals
  const tooltipLabel = (label, payload) => (payload.length > 0 ? fullLabel(payload[0].payload.start) : label)

  return (
    <>
      <div className="toolbar">
        <div className="segmented">
          {WINDOWS.map((item) => (
            <button key={item.value} className={item.value === period ? 'active' : ''} onClick={() => setPeriod(item.value)}>
              {item.label}
            </button>
          ))}
        </div>
        <span className="muted updated">
          {stats.bucket_minutes < 60 ? stats.bucket_minutes + ' min' : stats.bucket_minutes / 60 + ' h'} per point
          {updatedAt && ' - updated ' + updatedAt.toLocaleTimeString('en-GB')}
        </span>
      </div>

      <div className="stats">
        <StatCard
          label="Traffic"
          value={formatBytes(totals.download + totals.upload)}
          note={formatBytes(totals.download) + ' down, ' + formatBytes(totals.upload) + ' up'}
        />
        <StatCard label="Peak throughput" value={peak + ' Mbit/s'} note="highest point, download + upload" />
        <StatCard label="Active devices" value={totals.active_devices} note={totals.new_devices + ' new in this period'} />
        <StatCard
          label="Incidents"
          value={totals.incidents}
          note="created in this period"
          color={totals.incidents > 0 ? 'var(--high)' : undefined}
        />
      </div>

      <section className="panel chart-panel">
        <h2>Average throughput (Mbit/s)</h2>
        {totals.download + totals.upload === 0 && (
          <p className="muted small">No traffic recorded in this period. Traffic appears here once monitoring collects it.</p>
        )}
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={points} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
            <CartesianGrid stroke={colors.grid} vertical={false} />
            <XAxis dataKey="label" {...axisProps} minTickGap={24} />
            <YAxis {...axisProps} axisLine={false} allowDecimals />
            <Tooltip {...tooltipProps} labelFormatter={tooltipLabel} separator=": " formatter={(value) => value + ' Mbit/s'} />
            <Legend iconType="plainline" formatter={legendText} wrapperStyle={{ fontSize: 13 }} />
            <Area type="monotone" dataKey="downloadRate" name="Download" stroke={colors.download} fill={colors.download} fillOpacity={0.15} strokeWidth={2} dot={false} />
            <Area type="monotone" dataKey="uploadRate" name="Upload" stroke={colors.upload} fill={colors.upload} fillOpacity={0.15} strokeWidth={2} dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </section>

      <div className="columns two">
        <section className="panel chart-panel">
          <h2>Incidents by severity</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={points} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid stroke={colors.grid} vertical={false} />
              <XAxis dataKey="label" {...axisProps} minTickGap={24} />
              <YAxis {...axisProps} axisLine={false} allowDecimals={false} />
              <Tooltip {...tooltipProps} labelFormatter={tooltipLabel} separator=": " />
              <Legend
                iconType="square"
                formatter={legendText}
                itemSorter={(item) => SEVERITY_ORDER.indexOf(item.value)}
                wrapperStyle={{ fontSize: 13 }}
              />
              <Bar dataKey="low" name="Low" stackId="severity" fill={colors.low} stroke={colors.panel} strokeWidth={1} maxBarSize={24} />
              <Bar dataKey="medium" name="Medium" stackId="severity" fill={colors.medium} stroke={colors.panel} strokeWidth={1} maxBarSize={24} />
              <Bar dataKey="high" name="High" stackId="severity" fill={colors.high} stroke={colors.panel} strokeWidth={1} maxBarSize={24} />
              <Bar dataKey="critical" name="Critical" stackId="severity" fill={colors.critical} stroke={colors.panel} strokeWidth={1} maxBarSize={24} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="panel chart-panel">
          <h2>Active devices</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={points} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid stroke={colors.grid} vertical={false} />
              <XAxis dataKey="label" {...axisProps} minTickGap={24} />
              <YAxis {...axisProps} axisLine={false} allowDecimals={false} />
              <Tooltip {...tooltipProps} labelFormatter={tooltipLabel} separator=": " />
              <Bar dataKey="active_devices" name="Devices with traffic" fill={colors.devices} maxBarSize={24} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      <section className="panel">
        <h2>Top devices by traffic</h2>
        {stats.top_devices.length === 0 ? (
          <p className="muted">No device traffic in this period.</p>
        ) : (
          stats.top_devices.map((device) => (
            <div className="top-device" key={device.id}>
              <div>
                <div>{device.name}</div>
                <div className="mono muted small">{device.ip || '-'}</div>
              </div>
              <div className="bar">
                <div className="bar-fill download" style={{ width: (device.total / biggest) * 100 + '%' }} />
              </div>
              <div className="top-device-value">
                <b>{formatBytes(device.total)}</b>
                <div className="muted small">{formatBytes(device.download)} down, {formatBytes(device.upload)} up</div>
              </div>
            </div>
          ))
        )}
      </section>
    </>
  )
}
