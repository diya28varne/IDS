export function LoadingState({ label = 'Loading…' }) {
  return (
    <div className="state-box" role="status">
      {label}
    </div>
  )
}

export function EmptyState({ label }) {
  return <div className="state-box">{label}</div>
}

export function ErrorState({ message }) {
  return (
    <div className="state-box error" role="alert">
      {message}
    </div>
  )
}
