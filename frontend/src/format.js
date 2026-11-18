export function toDate(value) {
  return new Date(value.endsWith('Z') ? value : value + 'Z')
}

export function formatTime(value) {
  if (!value) return '-'
  return toDate(value).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' })
}

export function timeAgo(value) {
  if (!value) return 'never'
  const seconds = Math.floor((Date.now() - toDate(value).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago'
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' h ago'
  return Math.floor(seconds / 86400) + ' days ago'
}