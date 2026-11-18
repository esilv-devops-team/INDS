import { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { useAuth } from './auth'

export function usePolling(path, seconds = 10) {
  const { clearSession } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [updatedAt, setUpdatedAt] = useState(null)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    let stopped = false

    function load() {
      api(path)
        .then((result) => {
          if (stopped) return
          setData(result)
          setError('')
          setUpdatedAt(new Date())
        })
        .catch((err) => {
          if (stopped) return
          if (err.status === 401) {
            clearSession()
          } else {
            setError(err.message)
          }
        })
    }

    load()
    const timer = setInterval(load, seconds * 1000)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [path, seconds, clearSession, version])

  const reload = useCallback(() => setVersion((v) => v + 1), [])

  return { data, error, updatedAt, reload }
}