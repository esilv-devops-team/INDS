import { Shield } from 'lucide-react'
import { NavLink } from 'react-router'
import { navItems } from '../navigation'

export default function Sidebar({ open, onClose }) {
  return (
    <aside className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand">
        <Shield size={22} />
        <div>
          <strong>INDS</strong>
          <span>Network Defense</span>
        </div>
      </div>

      <nav>
        {navItems.map((item) => {
          const Icon = item.icon
          return (
            <NavLink key={item.path} to={item.path} end={item.path === '/'} onClick={onClose}>
              <Icon size={17} />
              {item.label}
            </NavLink>
          )
        })}
      </nav>

      <p className="sidebar-footer">ESILV Software Engineering<br />v0.1 - Sprint 4</p>
    </aside>
  )
}