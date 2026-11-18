import { Shield } from 'lucide-react'
import { useState } from 'react'
import { useAuth } from '../auth'

export default function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [firstTime, setFirstTime] = useState(false)
  const [error, setError] = useState('')
  const [sending, setSending] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setSending(true)
    try {
      await login(username, password, firstTime)
    } catch (err) {
      setError(err.status === 422 ? 'Username needs 3+ characters, password 8+ characters.' : err.message)
      setSending(false)
    }
  }

  return (
    <div className="login-page">
      <form className="login-box" onSubmit={handleSubmit}>
        <div className="login-title">
          <Shield size={28} />
          <div>
            <h1>INDS</h1>
            <p>Intelligent Network Defense System</p>
          </div>
        </div>

        <h2>{firstTime ? 'Create the administrator account' : 'Administrator login'}</h2>

        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={firstTime ? 'new-password' : 'current-password'}
            required
          />
        </label>

        {error && <p className="error">{error}</p>}

        <button className="button" type="submit" disabled={sending}>
          {sending ? 'Please wait...' : firstTime ? 'Create account' : 'Log in'}
        </button>

        <button type="button" className="link-button" onClick={() => setFirstTime(!firstTime)}>
          {firstTime ? 'I already have an account' : 'First time? Create the admin account'}
        </button>
      </form>
      <p className="login-footer">Firas El Kheshen & Adam Hawash</p>
    </div>
  )
}