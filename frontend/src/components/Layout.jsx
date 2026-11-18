import { useState } from 'react'
import { Outlet } from 'react-router'
import Sidebar from './Sidebar'
import Topbar from './Topbar'

export default function Layout() {
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <div className="app">
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      {menuOpen && <div className="backdrop" onClick={() => setMenuOpen(false)} />}
      <div className="main">
        <Topbar onMenu={() => setMenuOpen(!menuOpen)} />
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}