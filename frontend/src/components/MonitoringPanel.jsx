import { Power } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api'
import { formatTime, formatUptime, toDate } from '../format'
import { usePolling } from '../usePolling'

const STOP_REASONS = {
  administrator: 'Last stopped by an administrator.',
  shutdown: 'Last stopped when the backend shut down.',
  interrupted: 'The last run was interrupted (backend restart).',
  failure: 'The last capture stopped because of an error. Check the gateway page before turning it on again.',
}

export default function MonitoringPanel() {
  const { data: status, updatedAt, reload } = usePolling('/api/system/status')
  const { reload: reloadApprovals } = usePolling('/api/actions?approval=pending&limit=101')
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState('')

  if (!status) return null

  const isOn = status.monitoring === 'on'
  const runningFor = isOn ? Math.max(0, (updatedAt.getTime() - toDate(status.monitoring_since).getTime()) / 1000) : 0

  async function send(command) {
    setBusy(true)
    setError('')
    try {
      await api('/api/system/monitoring/' + command, { method: 'POST' })
    } catch (err) {
      setError(err.message)
    }
    setBusy(false)
    setConfirming(false)
    reload()
    reloadApprovals()
  }

  return (
    <section className={isOn ? 'panel monitoring on' : 'panel monitoring'}>
      <div className="monitoring-state">
        <Power size={22} />
        <div>
          <h2>Monitoring is {isOn ? 'ON' : 'OFF'}</h2>
          {isOn ? (
            <p>
              Capturing traffic since {formatTime(status.monitoring_since)} (
              {formatUptime(runningFor)}). Detection and responses are active.
            </p>
          ) : (
            <p>
              Nothing is captured or analysed and no action is applied. The gateway keeps forwarding traffic, so guests stay online.
            </p>
          )}
          {!isOn && status.monitoring_stop_reason && (
            <p className={status.monitoring_stop_reason === 'failure' ? 'error small' : 'muted small'}>
              {STOP_REASONS[status.monitoring_stop_reason]}
            </p>
          )}
          {error && <p className="error small">{error}</p>}
        </div>
      </div>

      {confirming ? (
        <div className="confirm">
          <span>Stop capture and detection? Pending approvals will be cancelled.</span>
          <button className="button small danger" disabled={busy} onClick={() => send('stop')}>
            Turn off
          </button>
          <button className="link-button" disabled={busy} onClick={() => setConfirming(false)}>Cancel</button>
        </div>
      ) : (
        <button
          className={isOn ? 'switch on' : 'switch'}
          role="switch"
          aria-checked={isOn}
          aria-label="Monitoring"
          disabled={busy}
          onClick={() => (isOn ? setConfirming(true) : send('start'))}
        >
          <span className="switch-knob" />
          <span>{busy ? 'Please wait...' : isOn ? 'ON' : 'OFF'}</span>
        </button>
      )}
    </section>
  )
}