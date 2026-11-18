import { useEffect, useState } from 'react'
import { api } from './api'
import { useAuth } from './auth'

export function usePolling(path, seconds = 10) {
  const { clearSession } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let stopped = false

    function load() {
      api(path)
        .then((result) => {
          if (stopped) return
          setData(result)
          setError('')
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
  }, [path, seconds, clearSession])

  return { data, error }
}