export function toDate(value) {
  return new Date(value.endsWith('Z') ? value : value + 'Z')
}

export function wasRecentlySeen(lastSeenAt, now) {
  return now - toDate(lastSeenAt).getTime() <= 5 * 60 * 1000
}

export function formatTime(value) {
  if (!value) return '-'
  return toDate(value).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' })
}

export function timeAgo(value, now = Date.now()) {
  if (!value) return 'never'
  const seconds = Math.floor((now - toDate(value).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago'
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' h ago'
  return Math.floor(seconds / 86400) + ' days ago'
}


export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value = value / 1024
    unit++
  }
  return (unit === 0 ? value : value.toFixed(1)) + ' ' + units[unit]
}

export function formatRate(bytesPerSecond) {
  if (bytesPerSecond === null || bytesPerSecond === undefined) return '-'
  const bits = bytesPerSecond * 8
  if (bits >= 1000000) return (bits / 1000000).toFixed(1) + ' Mbit/s'
  if (bits >= 1000) return (bits / 1000).toFixed(0) + ' kbit/s'
  return Math.round(bits) + ' bit/s'
}

export function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return days + 'd ' + hours + 'h'
  if (hours > 0) return hours + 'h ' + minutes + 'min'
  return minutes + ' min'
}

export function readable(text) {
  const words = text.replaceAll('_', ' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}
