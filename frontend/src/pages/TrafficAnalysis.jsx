import { useEffect, useMemo, useState } from 'react'
import { getSchema, predictRecord } from '../services/api'
import { StatusBadge } from '../components/StatusBadge'
import { ErrorState, LoadingState } from '../components/StatePanels'

function isFiniteNumber(value) {
  if (typeof value === 'boolean' || value === '' || value === null || value === undefined) {
    return false
  }
  const n = Number(value)
  return Number.isFinite(n)
}

function emptyValues(names) {
  const next = {}
  for (const name of names) next[name] = ''
  return next
}

/** Synthetic demo bumps — labelled as test data only. */
function demoValues(names) {
  const next = emptyValues(names)
  const bump = {
    'Flow Duration': '120000',
    'Total Fwd Packets': '180',
    'Total Backward Packets': '2',
    'Total Length of Fwd Packets': '92000',
    'Flow Bytes/s': '4500000',
    'Flow Packets/s': '1800',
    'Fwd Packets/s': '1750',
    'Packet Length Mean': '512',
    'Average Packet Size': '520',
    'SYN Flag Count': '1',
    'ACK Flag Count': '1',
    'Init_Win_bytes_forward': '65535',
    'Idle Max': '50000',
    'Idle Mean': '20000',
  }
  for (const [key, value] of Object.entries(bump)) {
    if (key in next) next[key] = value
  }
  return next
}

export function TrafficAnalysisPage({ refreshKey }) {
  const [featureNames, setFeatureNames] = useState([])
  const [values, setValues] = useState({})
  const [fieldErrors, setFieldErrors] = useState({})
  const [schemaLoading, setSchemaLoading] = useState(true)
  const [schemaError, setSchemaError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState(null)
  const [result, setResult] = useState(null)

  useEffect(() => {
    let cancelled = false
    setSchemaLoading(true)
    getSchema()
      .then((schema) => {
        if (cancelled) return
        const names = schema.feature_names || []
        setFeatureNames(names)
        setValues(emptyValues(names))
        setFieldErrors({})
        setSchemaError(null)
      })
      .catch((err) => {
        if (!cancelled) setSchemaError(err.message || String(err))
      })
      .finally(() => {
        if (!cancelled) setSchemaLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [refreshKey])

  const requiredCount = featureNames.length

  const filledCount = useMemo(
    () => featureNames.filter((name) => String(values[name] ?? '').trim() !== '').length,
    [featureNames, values],
  )

  function updateField(name, raw) {
    setValues((prev) => ({ ...prev, [name]: raw }))
    setFieldErrors((prev) => {
      const next = { ...prev }
      delete next[name]
      return next
    })
  }

  function validate() {
    const errors = {}
    for (const name of featureNames) {
      const raw = values[name]
      if (raw === '' || raw === null || raw === undefined) {
        errors[name] = 'Required numeric value'
        continue
      }
      if (!isFiniteNumber(raw)) {
        errors[name] = 'Must be a finite number (no NaN/Infinity)'
      }
    }
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  function resetForm() {
    setValues(emptyValues(featureNames))
    setFieldErrors({})
    setSubmitError(null)
    setResult(null)
  }

  async function onSubmit(e) {
    e.preventDefault()
    setSubmitError(null)
    setResult(null)
    if (!validate()) {
      setSubmitError('Fix the highlighted feature fields before submitting.')
      return
    }
    const record = {}
    for (const name of featureNames) {
      record[name] = Number(values[name])
    }
    setSubmitting(true)
    try {
      const response = await predictRecord(record)
      setResult(response)
    } catch (err) {
      setSubmitError(err.message || String(err))
    } finally {
      setSubmitting(false)
    }
  }

  const alert = result?.alerts?.[0]

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>Traffic Analysis</h1>
          <p>
            Submit one network-flow feature record to <code>POST /predict</code>.
            The returned decision is a model-generated assessment for investigation,
            not proof that an attack occurred.
          </p>
        </div>
      </header>

      {schemaLoading ? <LoadingState label="Loading feature schema…" /> : null}
      {schemaError ? <ErrorState message={schemaError} /> : null}

      {!schemaLoading && !schemaError ? (
        <form className="panel" onSubmit={onSubmit}>
          <h2 className="panel-title">Feature inputs</h2>
          <p className="panel-note">
            Schema from <code>GET /schema</code>: {requiredCount} required finite
            numeric fields ({filledCount} filled). Order is preserved for the API.
          </p>

          <div className="filters">
            <button
              type="button"
              className="btn"
              onClick={() => {
                setValues(demoValues(featureNames))
                setFieldErrors({})
                setSubmitError(null)
              }}
            >
              Load synthetic demo values
            </button>
            <button type="button" className="btn" onClick={resetForm}>
              Reset form
            </button>
          </div>
          <p className="panel-note">
            Demo values are synthetic test data for UI checks — not real network traffic.
          </p>

          <div className="feature-grid">
            {featureNames.map((name) => (
              <div className="field" key={name}>
                <label htmlFor={`feat-${name}`}>
                  {name} <span className="muted">(required)</span>
                </label>
                <input
                  id={`feat-${name}`}
                  className={fieldErrors[name] ? 'invalid' : undefined}
                  inputMode="decimal"
                  value={values[name] ?? ''}
                  onChange={(e) => updateField(name, e.target.value)}
                />
                {fieldErrors[name] ? (
                  <p className="field-error">{fieldErrors[name]}</p>
                ) : null}
              </div>
            ))}
          </div>

          {submitError ? (
            <div style={{ marginTop: '1rem' }}>
              <ErrorState message={submitError} />
            </div>
          ) : null}

          <div style={{ marginTop: '1rem' }}>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting || featureNames.length === 0}
            >
              {submitting ? 'Scoring…' : 'Run prediction'}
            </button>
          </div>
        </form>
      ) : null}

      {alert ? (
        <div className="panel">
          <h2 className="panel-title">Model assessment</h2>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <StatusBadge decision={alert.final_decision} />
            <span className="mono">
              risk{' '}
              {typeof alert.risk_score === 'number'
                ? alert.risk_score.toFixed(2)
                : '—'}
            </span>
          </div>
          <p style={{ marginTop: '0.85rem' }}>{alert.explanation || '—'}</p>
          <dl className="kv" style={{ marginTop: '1rem' }}>
            <dt>Alert ID</dt>
            <dd className="mono">{alert.alert_id || '—'}</dd>
            <dt>Random Forest</dt>
            <dd className="mono">{alert.random_forest_prediction || '—'}</dd>
            <dt>Isolation Forest</dt>
            <dd className="mono">{alert.isolation_forest_prediction || '—'}</dd>
            <dt>Supporting scores</dt>
            <dd className="mono">
              {JSON.stringify(alert.supporting_scores ?? {}, null, 2)}
            </dd>
          </dl>
          {result?.note ? <p className="panel-note">{result.note}</p> : null}
          <p className="panel-note">
            Successful predictions are persisted to SQLite alert history.
          </p>
        </div>
      ) : null}
    </section>
  )
}
