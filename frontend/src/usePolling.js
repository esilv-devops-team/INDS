import { useCallback, useEffect, useSyncExternalStore } from 'react'
import { api } from './api'
import { useAuth } from './auth'

const idle = { data: null, error: '', updatedAt: null, unauthorized: false }
const active = new Map()
const REQUEST_TIMEOUT_MS = 10000

function canRefresh() {
  return document.visibilityState !== 'hidden' && navigator.onLine
}

function subscribe(path, seconds, notify) {
  let entry = active.get(path)
  if (!entry) {
    entry = createPoll(path)
    active.set(path, entry)
  }
  entry.listeners.set(notify, seconds)
  if (!entry.request && !entry.timer) entry.refresh()

  return () => {
    entry.listeners.delete(notify)
    if (entry.listeners.size === 0) {
      active.delete(path)
      entry.dispose()
    }
  }
}

function createPoll(path) {
  const entry = {
    snapshot: idle,
    listeners: new Map(),
    request: null,
    timer: null,
    refresh,
    dispose,
  }

  function clearTimer() {
    window.clearTimeout(entry.timer)
    entry.timer = null
  }

  function publish(snapshot) {
    entry.snapshot = snapshot
    entry.listeners.forEach((_, notify) => notify())
  }

  async function refresh(force = false) {
    clearTimer()
    if (!navigator.onLine) {
      const previous = entry.request
      entry.request = null
      previous?.abort()
      if (entry.snapshot.error !== 'Browser is offline') {
        publish({ ...entry.snapshot, error: 'Browser is offline' })
      }
      return
    }
    if (!canRefresh() || (!force && entry.request)) return

    const previous = entry.request
    const request = new AbortController()
    entry.request = request
    previous?.abort()

    const timeout = window.setTimeout(() => request.abort(new Error('Refresh timed out')), REQUEST_TIMEOUT_MS)
    try {
      const data = await api(path, { signal: request.signal, cache: 'no-store' })
      if (entry.request === request) publish({ ...idle, data, updatedAt: new Date() })
    } catch (error) {
      if (entry.request !== request) return
      if (error.status === 401) {
        publish({ ...idle, unauthorized: true })
      } else {
        publish({ ...entry.snapshot, error: error.message })
      }
    } finally {
      window.clearTimeout(timeout)
      if (entry.request === request) {
        entry.request = null
        if (entry.listeners.size && canRefresh() && !entry.snapshot.unauthorized) {
          const interval = Math.min(...entry.listeners.values())
          entry.timer = window.setTimeout(refresh, interval * 1000)
        }
      }
    }
  }

  function handleAvailability() {
    refresh()
  }

  function dispose() {
    clearTimer()
    const request = entry.request
    entry.request = null
    request?.abort()
    document.removeEventListener('visibilitychange', handleAvailability)
    for (const event of ['focus', 'online', 'offline']) {
      window.removeEventListener(event, handleAvailability)
    }
  }

  document.addEventListener('visibilitychange', handleAvailability)
  for (const event of ['focus', 'online', 'offline']) {
    window.addEventListener(event, handleAvailability)
  }
  return entry
}

export function usePolling(path, seconds = 5) {
  const { clearSession } = useAuth()
  const watch = useCallback((notify) => subscribe(path, seconds, notify), [path, seconds])
  const getSnapshot = useCallback(() => active.get(path)?.snapshot || idle, [path])
  const snapshot = useSyncExternalStore(watch, getSnapshot)
  const reload = useCallback(() => active.get(path)?.refresh(true), [path])

  useEffect(() => {
    if (snapshot.unauthorized) clearSession()
  }, [snapshot.unauthorized, clearSession])

  return { ...snapshot, reload }
}
