export const colors = {
  download: '#3987e5',
  upload: '#199e70',
  devices: '#3987e5',
  low: '#7f93a8',
  medium: '#d4a73f',
  high: '#e07b3c',
  critical: '#d9534f',
  grid: '#2d333b',
  text: '#8b939d',
  panel: '#1d2127',
}

export const axisProps = {
  stroke: colors.grid,
  tick: { fill: colors.text, fontSize: 12 },
  tickLine: false,
}

export const tooltipProps = {
  contentStyle: { background: '#252a31', border: '1px solid #2d333b', borderRadius: 5, fontSize: 13 },
  labelStyle: { color: '#d9dee4', marginBottom: 4 },
  itemStyle: { color: '#d9dee4', padding: 0 },
  cursor: { fill: 'rgba(255, 255, 255, 0.04)', stroke: colors.grid },
}