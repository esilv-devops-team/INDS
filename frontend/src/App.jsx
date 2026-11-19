import { Navigate, Route, Routes } from 'react-router'
import { useAuth } from './auth'
import Layout from './components/Layout'
import DeviceDetail from './pages/DeviceDetail'
import Devices from './pages/Devices'
import Gateway from './pages/Gateway'
import Incidents from './pages/Incidents'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Statistics from './pages/Statistics'

export default function App() {
  const { admin, checking } = useAuth()

  if (checking) {
    return <p className="loading-screen">Loading...</p>
  }

  if (!admin) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/devices/:deviceId" element={<DeviceDetail />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:incidentId" element={<Incidents />} />
        <Route path="/statistics" element={<Statistics />} />
        <Route path="/gateway" element={<Gateway />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
