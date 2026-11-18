import { Activity, LayoutDashboard, Monitor, Server, ShieldAlert } from 'lucide-react'

export const navItems = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/devices', label: 'Devices', icon: Monitor },
  { path: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { path: '/statistics', label: 'Statistics', icon: Activity },
  { path: '/gateway', label: 'Gateway', icon: Server },
]