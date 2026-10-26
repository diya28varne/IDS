import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, devices } from '@playwright/test'

const frontendDir = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(frontendDir, '..')
const python = path.join(root, '.venv', 'Scripts', 'python.exe')

// Dedicated API port so E2E never attaches to a developer uvicorn that may use
// artifacts/threatlens_alerts.sqlite3. The Vite UI uses the same-origin proxy
// (no CORS) via THREATLENS_E2E_API_PROXY.
const apiPort = 18000
const uiPort = 5174
const apiHost = `http://127.0.0.1:${apiPort}`
const uiHost = `http://127.0.0.1:${uiPort}`

const productionDbPath = path.resolve(root, 'artifacts', 'threatlens_alerts.sqlite3')
const e2eTmpDir = path.join(frontendDir, '.e2e-tmp')
fs.mkdirSync(e2eTmpDir, { recursive: true })

const dbMarkerPath = path.join(e2eTmpDir, 'active-db-path.txt')

/**
 * Config is evaluated in the main process and again in each worker. Only the
 * first evaluation may choose a fresh DB path; later evaluations must reuse it
 * so workers never delete a SQLite file the API still has open.
 */
function resolveE2eDbPath() {
  if (process.env.THREATLENS_E2E_DB_PATH) {
    return process.env.THREATLENS_E2E_DB_PATH
  }
  if (fs.existsSync(dbMarkerPath)) {
    const existing = fs.readFileSync(dbMarkerPath, 'utf8').trim()
    if (existing) {
      return existing
    }
  }
  const fresh = path.join(
    e2eTmpDir,
    `threatlens_e2e_alerts_${process.pid}_${Date.now()}.sqlite3`,
  )
  fs.writeFileSync(dbMarkerPath, fresh, 'utf8')
  return fresh
}

const e2eDbPath = resolveE2eDbPath()
process.env.THREATLENS_DB_PATH = e2eDbPath
process.env.THREATLENS_E2E_DB_PATH = e2eDbPath
process.env.THREATLENS_E2E_API_BASE = apiHost
process.env.THREATLENS_PRODUCTION_DB_PATH = productionDbPath

if (path.resolve(e2eDbPath) === path.resolve(productionDbPath)) {
  throw new Error('E2E database path must not equal the production SQLite path')
}

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  globalTeardown: './e2e/global-teardown.js',
  use: {
    baseURL: uiHost,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `"${python}" -m uvicorn threatlens.api.app:app --host 127.0.0.1 --port ${apiPort}`,
      cwd: root,
      url: `${apiHost}/health`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        THREATLENS_DB_PATH: e2eDbPath,
      },
    },
    {
      // Leave VITE_API_BASE_URL unset so the dashboard uses the Vite proxy
      // (same-origin → no CORS). Proxy target is the dedicated E2E API.
      command: `node ./node_modules/vite/bin/vite.js --host 127.0.0.1 --port ${uiPort}`,
      url: uiHost,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        THREATLENS_E2E_API_PROXY: apiHost,
      },
    },
  ],
})
