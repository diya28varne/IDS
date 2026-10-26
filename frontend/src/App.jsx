import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { AboutPage } from './pages/About'
import { AlertHistoryPage } from './pages/AlertHistory'
import { OverviewPage } from './pages/Overview'
import { TrafficAnalysisPage } from './pages/TrafficAnalysis'
import { getHealth } from './services/api'

export default function App() {
  const [connection, setConnection] = useState('checking')
  const [connectionDetail, setConnectionDetail] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)
  const [refreshing, setRefreshing] = useState(false)

  const checkHealth = useCallback(async () => {
    setConnection('checking')
    try {
      const health = await getHealth()
      const fullyReady = Boolean(health.models_ready && health.database_ready)
      setConnection(fullyReady ? 'connected' : 'degraded')
      setConnectionDetail(
        fullyReady
          ? `status=${health.status}`
          : health.detail || `status=${health.status}`,
      )
    } catch (err) {
      setConnection('offline')
      setConnectionDetail(err.message || String(err))
    }
  }, [])

  useEffect(() => {
    checkHealth()
  }, [checkHealth, refreshKey])

  async function onRefresh() {
    setRefreshing(true)
    setRefreshKey((k) => k + 1)
    await checkHealth()
    setRefreshing(false)
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route
          element={
            <Layout
              connection={connection}
              connectionDetail={connectionDetail}
              onRefresh={onRefresh}
              refreshing={refreshing}
            />
          }
        >
          <Route index element={<OverviewPage refreshKey={refreshKey} />} />
          <Route
            path="alerts"
            element={<AlertHistoryPage refreshKey={refreshKey} />}
          />
          <Route
            path="traffic"
            element={<TrafficAnalysisPage refreshKey={refreshKey} />}
          />
          <Route path="about" element={<AboutPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
