import { StatusBadge } from './StatusBadge'
import { LoadingState, ErrorState } from './StatePanels'

function ScoreBlock({ title, value }) {
  return (
    <>
      <dt>{title}</dt>
      <dd className="mono">
        {value === null || value === undefined
          ? '—'
          : typeof value === 'object'
            ? JSON.stringify(value, null, 2)
            : String(value)}
      </dd>
    </>
  )
}

export function AlertDetailModal({ open, loading, error, alert, onClose }) {
  if (!open) return null

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Alert details"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <h2 style={{ margin: 0 }}>
              Alert occurrence #{alert?.record_id ?? '—'}
            </h2>
            <p className="muted" style={{ margin: '0.35rem 0 0' }}>
              Model-generated assessment for investigation — not proof of an attack.
            </p>
          </div>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>

        {loading ? <LoadingState label="Loading alert details…" /> : null}
        {error ? <ErrorState message={error} /> : null}

        {alert && !loading && !error ? (
          <>
            <div style={{ marginBottom: '0.85rem' }}>
              <StatusBadge decision={alert.final_decision} />
            </div>
            <p>{alert.explanation || 'No explanation provided.'}</p>
            <dl className="kv" style={{ marginTop: '1rem' }}>
              <ScoreBlock title="Record ID" value={alert.record_id} />
              <ScoreBlock title="Alert ID" value={alert.alert_id} />
              <ScoreBlock title="Created (UTC)" value={alert.created_at_utc} />
              <ScoreBlock
                title="Risk score"
                value={
                  typeof alert.risk_score === 'number'
                    ? alert.risk_score.toFixed(2)
                    : alert.risk_score
                }
              />
              <ScoreBlock title="Reason" value={alert.reason} />
              <ScoreBlock
                title="Random Forest"
                value={alert.random_forest_prediction}
              />
              <ScoreBlock
                title="Isolation Forest"
                value={alert.isolation_forest_prediction}
              />
              <ScoreBlock
                title="Model identifiers"
                value={alert.model_identifiers}
              />
              <ScoreBlock
                title="Supporting scores"
                value={alert.supporting_scores}
              />
              <ScoreBlock
                title="Score components"
                value={alert.score_components}
              />
              <ScoreBlock
                title="Notes"
                value={Array.isArray(alert.notes) ? alert.notes.join(' · ') : alert.notes}
              />
            </dl>
          </>
        ) : null}
      </div>
    </div>
  )
}
