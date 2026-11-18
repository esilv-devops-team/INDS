import { LogOut, Menu } from 'lucide-react'
import { useLocation } from 'react-router'
import { useAuth } from '../auth'
import { navItems } from '../navigation'
import { usePolling } from '../usePolling'

export default function Topbar({ onMenu }) {
  const { admin, logout } = useAuth()
  const { data: status } = usePolling('/api/system/status', 10)
  const location = useLocation()
  const page = navItems.find((item) => item.path === location.pathname)

  return (
    <header className="topbar">
      <button className="icon-button menu-button" onClick={onMenu} aria-label="Open menu">
        <Menu size={20} />
      </button>
      <h1>{page ? page.label : 'INDS'}</h1>

      {status && (
        <span className={status.monitoring === 'on' ? 'pill on' : 'pill'}>
          <span className="dot" />
          Monitoring {status.monitoring.toUpperCase()}
        </span>
      )}

      <span className="user">{admin.username}</span>
      <button className="icon-button" onClick={logout} title="Log out">
        <LogOut size={17} />
      </button>
    </header>
  )
}