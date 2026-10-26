import { StatusBadge } from './StatusBadge'

export function AlertTable({ alerts, onSelect }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Record</th>
            <th>Timestamp (UTC)</th>
            <th>Decision</th>
            <th>Risk</th>
            <th>Alert ID</th>
            <th>Explanation</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.record_id}>
              <td>
                <button
                  type="button"
                  className="linkish"
                  onClick={() => onSelect?.(alert.record_id)}
                >
                  #{alert.record_id}
                </button>
              </td>
              <td className="mono">{alert.created_at_utc || '—'}</td>
              <td>
                <StatusBadge decision={alert.final_decision} />
              </td>
              <td className="mono">
                {typeof alert.risk_score === 'number'
                  ? alert.risk_score.toFixed(2)
                  : '—'}
              </td>
              <td className="mono">{alert.alert_id || '—'}</td>
              <td>{alert.explanation || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
