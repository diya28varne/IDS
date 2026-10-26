import { NavLink, Outlet } from 'react-router-dom'
import { getApiBaseLabel } from '../services/api'

export function Layout({
  connection,
  connectionDetail,
  onRefresh,
  refreshing,
}) {
  const statusClass =
    connection === 'connected'
      ? 'ok'
      : connection === 'degraded'
        ? ''
        : connection === 'checking'
          ? ''
          : 'bad'
  const statusLabel =
    connection === 'connected'
      ? 'Backend connected'
      : connection === 'degraded'
        ? 'Backend reachable (degraded)'
        : connection === 'checking'
          ? 'Checking backend…'
          : 'Backend unavailable'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden>
            TL
          </div>
          <div>
            <strong>ThreatLens</strong>
            <span>Hybrid IDS research console</span>
          </div>
        </div>
        <nav className="nav" aria-label="Primary">
          <NavLink to="/" end>
            <span className="nav-icon">01</span> Overview
          </NavLink>
          <NavLink to="/alerts">
            <span className="nav-icon">02</span> Alert History
          </NavLink>
          <NavLink to="/traffic">
            <span className="nav-icon">03</span> Traffic Analysis
          </NavLink>
          <NavLink to="/about">
            <span className="nav-icon">04</span> About ThreatLens
          </NavLink>
        </nav>
      </aside>

      <div className="content-col">
        <header className="topbar">
          <div className="topbar-leading">
            <a className="btn-back" href="/">
              <span aria-hidden="true">←</span>
              Back
            </a>
            <div className="topbar-title">ThreatLens Dashboard</div>
          </div>
          <div className="topbar-actions">
            <span className={`status-pill ${statusClass}`} title={connectionDetail || getApiBaseLabel()}>
              <span className="status-dot" aria-hidden />
              {statusLabel}
            </span>
            <button
              type="button"
              className="btn"
              onClick={onRefresh}
              disabled={refreshing}
            >
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </header>
        <main className="main">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
