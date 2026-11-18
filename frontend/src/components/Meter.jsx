export default function Meter({ percent, warn = 70, danger = 85 }) {
  let level = 'good'
  if (percent >= danger) level = 'critical'
  else if (percent >= warn) level = 'medium'

  return (
    <div className="bar">
      <div className={'bar-fill ' + level} style={{ width: Math.min(percent, 100) + '%' }} />
    </div>
  )
}