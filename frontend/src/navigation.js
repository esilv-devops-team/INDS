import { Activity, LayoutDashboard, Monitor, Network, Server, ShieldAlert, ShieldCheck } from 'lucide-react'

export const navItems = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/devices', label: 'Devices', icon: Monitor },
  { path: '/topology', label: 'Topology', icon: Network },
  { path: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { path: '/responses', label: 'Responses', icon: ShieldCheck },
  { path: '/statistics', label: 'Statistics', icon: Activity },
  { path: '/gateway', label: 'Gateway', icon: Server },
]
