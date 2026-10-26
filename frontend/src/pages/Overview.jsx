import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getAlert, getAlertStats, listAlerts } from '../services/api'
import { AlertTable } from '../components/AlertTable'
import { AlertDetailModal } from '../components/AlertDetailModal'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanels'
import { StatCard } from '../components/StatCard'
import { decisionChartData } from '../lib/stats'

const RECENT_LIMIT = 8
const COLORS = {
  BENIGN: '#3dd68c',
  SUSPICIOUS: '#f0b429',
  DDoS: '#ff6b7a',
}

export function OverviewPage({ refreshKey }) {
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [detailId, setDetailId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.all([getAlertStats(), listAlerts(RECENT_LIMIT, 0)])
      .then(([statsPayload, page]) => {
        if (cancelled) return
        setStats(statsPayload)
        setRecent(page.alerts || [])
        setError(null)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [refreshKey])

  useEffect(() => {
    if (detailId == null) {
      setDetail(null)
      setDetailError(null)
      return
    }
    let cancelled = false
    setDetailLoading(true)
    getAlert(detailId)
      .then((row) => {
        if (!cancelled) {
          setDetail(row)
          setDetailError(null)
        }
      })
      .catch((err) => {
        if (!cancelled) setDetailError(err.message || String(err))
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [detailId])

  const total = stats?.total ?? 0
  const decisions = stats?.decisions ?? {
    BENIGN: 0,
    SUSPICIOUS: 0,
    DDoS: 0,
    other: 0,
  }
  const pieData = decisionChartData(decisions)
  const riskData = (stats?.risk_buckets || []).map((bucket) => ({
    name: bucket.label,
    count: bucket.count,
  }))

  const showEmpty = !loading && !error && total === 0
  const showReady = !loading && !error && total > 0

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>Overview</h1>
          <p>
            Historical summary of every persisted ThreatLens alert in SQLite.
            Decision and risk charts use full-database aggregates from{' '}
            <code>GET /alerts/stats</code> — not a truncated page sample.
          </p>
        </div>
        <Link className="btn btn-primary" to="/traffic">
          Open Traffic Analysis
        </Link>
      </header>

      {loading ? <LoadingState label="Loading historical alerts…" /> : null}
      {error ? <ErrorState message={error} /> : null}

      {showEmpty ? (
        <EmptyState label="No stored alerts yet. Submit a flow on Traffic Analysis to populate history." />
      ) : null}

      {showReady ? (
        <>
          <div className="grid-stats">
            <StatCard
              label="Total stored events"
              value={total}
              hint="Full SQLite total"
            />
            <StatCard
              label="BENIGN"
              value={decisions.BENIGN}
              hint="Full-database count"
            />
            <StatCard
              label="SUSPICIOUS"
              value={decisions.SUSPICIOUS}
              hint="Full-database count"
            />
            <StatCard
              label="DDoS"
              value={decisions.DDoS}
              hint="Full-database count"
            />
          </div>
          <p className="panel-note">
            {stats?.note ||
              'Statistics are calculated from stored alert history (not live network traffic).'}
          </p>

          <div className="grid-2">
            <div className="panel">
              <h2 className="panel-title">Decision distribution</h2>
              <p className="panel-note">All stored occurrences in the database.</p>
              <div className="chart-wrap">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={2}
                    >
                      {pieData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={COLORS[entry.name] || '#3aa0ff'}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="panel">
              <h2 className="panel-title">Risk-score distribution</h2>
              <p className="panel-note">
                Heuristic prioritization scores (0–100), not attack probabilities.
                Counts cover the full stored history.
              </p>
              <div className="chart-wrap">
                <ResponsiveContainer>
                  <BarChart data={riskData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#243954" />
                    <XAxis dataKey="name" stroke="#93a4bd" />
                    <YAxis allowDecimals={false} stroke="#93a4bd" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#3aa0ff" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <div className="panel" style={{ marginTop: '1rem' }}>
            <h2 className="panel-title">Recent alert activity</h2>
            {recent.length === 0 ? (
              <EmptyState label="No recent rows returned for the activity table." />
            ) : (
              <AlertTable alerts={recent} onSelect={setDetailId} />
            )}
          </div>
        </>
      ) : null}

      <AlertDetailModal
        open={detailId != null}
        loading={detailLoading}
        error={detailError}
        alert={detail}
        onClose={() => setDetailId(null)}
      />
    </section>
  )
}
