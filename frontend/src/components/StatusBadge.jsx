export function StatusBadge({ decision }) {
  const key = String(decision || '').toUpperCase()
  let cls = 'badge badge-neutral'
  if (key === 'BENIGN') cls = 'badge badge-benign'
  else if (key === 'SUSPICIOUS') cls = 'badge badge-suspicious'
  else if (key === 'DDOS') cls = 'badge badge-ddos'
  return <span className={cls}>{decision || '—'}</span>
}
