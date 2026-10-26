export function StatCard({ label, value, hint }) {
  return (
    <article className="stat-card">
      <p className="label">{label}</p>
      <p className="value">{value}</p>
      {hint ? <p className="hint">{hint}</p> : null}
    </article>
  )
}
