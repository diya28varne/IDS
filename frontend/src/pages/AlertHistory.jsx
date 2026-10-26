import { useEffect, useMemo, useState } from 'react'
import { getAlert, listAlerts } from '../services/api'
import { AlertDetailModal } from '../components/AlertDetailModal'
import { AlertTable } from '../components/AlertTable'
import { EmptyState, ErrorState, LoadingState } from '../components/StatePanels'
import { resolveListView } from '../lib/viewState'

const PAGE_SIZE = 25

export function AlertHistoryPage({ refreshKey }) {
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [decision, setDecision] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [detailId, setDetailId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    listAlerts(PAGE_SIZE, offset)
      .then((page) => {
        if (cancelled) return
        setAlerts(page.alerts || [])
        setTotal(page.total ?? 0)
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
  }, [offset, refreshKey])

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

  const filtered = useMemo(() => {
    if (decision === 'ALL') return alerts
    return alerts.filter((a) => a.final_decision === decision)
  }, [alerts, decision])

  const listView = resolveListView({ loading, error, items: filtered })
  const pageStart = total === 0 ? 0 : offset + 1
  const pageEnd = Math.min(offset + alerts.length, total)

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>Alert History</h1>
          <p>
            Newest-first occurrences from <code>GET /alerts</code>. Repeated
            content-hash alert IDs still appear as separate database records.
          </p>
        </div>
      </header>

      <div className="filters">
        <div className="field">
          <label htmlFor="decision-filter">Decision filter (current page)</label>
          <select
            id="decision-filter"
            value={decision}
            onChange={(e) => setDecision(e.target.value)}
          >
            <option value="ALL">All</option>
            <option value="BENIGN">BENIGN</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="DDoS">DDoS</option>
          </select>
        </div>
      </div>

      {listView.kind === 'loading' ? <LoadingState /> : null}
      {listView.kind === 'error' ? <ErrorState message={listView.message} /> : null}

      {listView.kind === 'empty' ? (
        <div className="panel">
          <EmptyState label="No alerts on this page match the current filter." />
        </div>
      ) : null}

      {listView.kind === 'ready' ? (
        <div className="panel">
          <AlertTable alerts={listView.items} onSelect={setDetailId} />
          <div className="pager">
            <span>
              Showing {pageStart}–{pageEnd} of {total} stored events
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn"
                disabled={offset <= 0 || loading}
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn"
                disabled={offset + PAGE_SIZE >= total || loading}
                onClick={() => setOffset((o) => o + PAGE_SIZE)}
              >
                Next
              </button>
            </div>
          </div>
        </div>
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
