import fs from 'node:fs'
import path from 'node:path'

function tryRemove(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath)
    }
  } catch (err) {
    // Windows may still hold the handle briefly after uvicorn exits.
    if (err && (err.code === 'EBUSY' || err.code === 'EPERM')) {
      return false
    }
    throw err
  }
  return true
}

/**
 * Best-effort removal of E2E-only SQLite files. Never touch the production DB.
 */
export default async function globalTeardown() {
  const e2eDbPath = process.env.THREATLENS_E2E_DB_PATH
  const productionDbPath = process.env.THREATLENS_PRODUCTION_DB_PATH
  const markerPath = e2eDbPath
    ? path.join(path.dirname(e2eDbPath), 'active-db-path.txt')
    : null

  if (!e2eDbPath) {
    return
  }

  const resolvedE2e = path.resolve(e2eDbPath)
  if (productionDbPath && resolvedE2e === path.resolve(productionDbPath)) {
    throw new Error(
      'Refusing E2E teardown: temporary DB path equals production artifacts/threatlens_alerts.sqlite3',
    )
  }

  if (!resolvedE2e.includes(`${path.sep}.e2e-tmp${path.sep}`)) {
    throw new Error(
      `Refusing E2E teardown for unexpected DB path: ${resolvedE2e}`,
    )
  }

  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    tryRemove(`${resolvedE2e}${suffix}`)
  }
  if (markerPath) {
    tryRemove(markerPath)
  }
}
