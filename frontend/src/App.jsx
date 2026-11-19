import { lazy } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router'
import { useAuth } from './auth'
import Layout from './components/Layout'
import Devices from './pages/Devices'
import Gateway from './pages/Gateway'
import Incidents from './pages/Incidents'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Responses from './pages/Responses'
import Topology from './pages/Topology'

const DeviceDetail = lazy(() => import('./pages/DeviceDetail'))
const Statistics = lazy(() => import('./pages/Statistics'))

export default function App() {
  const { admin, checking } = useAuth()
  const location = useLocation()
  const returnTo = location.state?.returnTo
  const returnPath = returnTo?.pathname
  const safeReturn = typeof returnPath === 'string' && returnPath.startsWith('/') &&
    !returnPath.startsWith('//') && !returnPath.includes('\\')

  if (checking) {
    return <p className="loading-screen">Loading...</p>
  }

  if (!admin) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace state={{
          returnTo: { pathname: location.pathname, search: location.search, hash: location.hash },
        }} />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to={safeReturn ? returnTo : '/'} replace />} />
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/devices/:deviceId" element={<DeviceDetail />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:incidentId" element={<Incidents />} />
        <Route path="/responses" element={<Responses />} />
        <Route path="/statistics" element={<Statistics />} />
        <Route path="/gateway" element={<Gateway />} />
        <Route path="/topology" element={<Topology />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
