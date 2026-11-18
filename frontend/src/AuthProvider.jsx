import { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { AuthContext } from './auth'

export default function AuthProvider({ children }) {
  const [admin, setAdmin] = useState(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    api('/api/auth/me')
      .then(setAdmin)
      .catch(() => setAdmin(null))
      .finally(() => setChecking(false))
  }, [])

  async function login(username, password, firstTime) {
    const path = firstTime ? '/api/auth/setup' : '/api/auth/login'
    const result = await api(path, { method: 'POST', body: { username, password } })
    setAdmin(result)
  }

  async function logout() {
    await api('/api/auth/logout', { method: 'POST' })
    setAdmin(null)
  }

  const clearSession = useCallback(() => setAdmin(null), [])

  return (
    <AuthContext.Provider value={{ admin, checking, login, logout, clearSession }}>
      {children}
    </AuthContext.Provider>
  )
}