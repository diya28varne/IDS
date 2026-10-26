import fs from 'node:fs'
import path from 'node:path'
import { expect, test } from '@playwright/test'

/**
 * Full browser workflow: Traffic Analysis → real POST /predict → SQLite → Alert History.
 *
 * Uses the dedicated E2E API/DB from playwright.config.js (THREATLENS_DB_PATH under
 * frontend/.e2e-tmp/). Synthetic feature values are test data only — any model
 * decision is an assessment for investigation, not proof of a real attack.
 */

const apiBase = process.env.THREATLENS_E2E_API_BASE || 'http://127.0.0.1:18000'
const e2eDbPath = process.env.THREATLENS_E2E_DB_PATH
const productionDbPath = process.env.THREATLENS_PRODUCTION_DB_PATH

function productionDbSnapshot() {
  if (!productionDbPath || !fs.existsSync(productionDbPath)) {
    return { exists: false, size: null, mtimeMs: null }
  }
  const stat = fs.statSync(productionDbPath)
  return { exists: true, size: stat.size, mtimeMs: stat.mtimeMs }
}

async function fillAllSchemaFeatures(page, featureNames) {
  // Prefer the labelled synthetic demo bumps, then zero-fill remaining required fields.
  await page.getByRole('button', { name: 'Load synthetic demo values' }).click()
  for (const name of featureNames) {
    const input = page.locator(`[id=${JSON.stringify(`feat-${name}`)}]`)
    await expect(input).toBeVisible()
    const current = await input.inputValue()
    if (String(current).trim() === '') {
      // Finite numeric placeholder for schema completeness (synthetic test data).
      await input.fill('0')
    }
  }
}

test.describe('ThreatLens predict → persist → history workflow', () => {
  test.beforeAll(() => {
    expect(e2eDbPath, 'THREATLENS_E2E_DB_PATH must be set by playwright.config.js').toBeTruthy()
    expect(path.resolve(e2eDbPath)).not.toBe(path.resolve(productionDbPath || ''))
    expect(path.resolve(e2eDbPath)).toContain(`${path.sep}.e2e-tmp${path.sep}`)
  })

  test('submits synthetic features, persists alert, and shows it in history', async ({
    page,
    request,
  }) => {
    const prodBefore = productionDbSnapshot()

    const health = await request.get(`${apiBase}/health`)
    expect(health.ok()).toBeTruthy()
    const healthBody = await health.json()
    expect(healthBody.models_ready).toBe(true)
    expect(healthBody.database_ready).toBe(true)

    const schemaRes = await request.get(`${apiBase}/schema`)
    expect(schemaRes.ok()).toBeTruthy()
    const schema = await schemaRes.json()
    const featureNames = schema.feature_names
    expect(featureNames.length).toBeGreaterThan(10)
    expect(schema.feature_count).toBe(featureNames.length)

    const beforeList = await request.get(`${apiBase}/alerts?limit=10&offset=0`)
    expect(beforeList.ok()).toBeTruthy()
    const beforeTotal = (await beforeList.json()).total

    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    await expect(
      page.getByText(/Backend connected|Backend reachable/),
    ).toBeVisible({ timeout: 20_000 })

    await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', {
      name: /Traffic Analysis/,
    }).click()
    await expect(
      page.getByRole('heading', { name: 'Traffic Analysis' }),
    ).toBeVisible()
    await expect(page.getByText(/Schema from/)).toBeVisible({ timeout: 30_000 })
    await expect(
      page.getByText(new RegExp(`${featureNames.length} required`)),
    ).toBeVisible()

    await fillAllSchemaFeatures(page, featureNames)

    const predictWait = page.waitForResponse(
      (res) =>
        res.url().includes('/predict') &&
        res.request().method() === 'POST' &&
        res.ok(),
    )
    await page.getByRole('button', { name: 'Run prediction' }).click()
    const predictResponse = await predictWait
    const predictBody = await predictResponse.json()

    expect(predictBody.count).toBe(1)
    expect(predictBody.alerts).toHaveLength(1)
    const apiAlert = predictBody.alerts[0]
    expect(apiAlert.alert_id).toBeTruthy()
    expect(['BENIGN', 'SUSPICIOUS', 'DDoS']).toContain(apiAlert.final_decision)
    expect(apiAlert.risk_score).toBeGreaterThanOrEqual(0)
    expect(apiAlert.risk_score).toBeLessThanOrEqual(100)
    expect(apiAlert.explanation).toBeTruthy()

    // UI shows the model assessment (synthetic test input — not proof of an attack).
    await expect(page.getByRole('heading', { name: 'Model assessment' })).toBeVisible({
      timeout: 15_000,
    })
    await expect(page.getByText(apiAlert.final_decision, { exact: true }).first()).toBeVisible()
    const riskText = Number(apiAlert.risk_score).toFixed(2)
    await expect(page.getByText(new RegExp(`risk\\s+${riskText}`))).toBeVisible()
    await expect(page.getByText(apiAlert.alert_id)).toBeVisible()
    await expect(
      page.getByText(/persisted to SQLite alert history/i),
    ).toBeVisible()

    // Confirm persistence via the real API (temporary E2E DB).
    const afterList = await request.get(`${apiBase}/alerts?limit=10&offset=0`)
    expect(afterList.ok()).toBeTruthy()
    const afterPage = await afterList.json()
    expect(afterPage.total).toBe(beforeTotal + 1)
    const stored = afterPage.alerts.find((row) => row.alert_id === apiAlert.alert_id)
    expect(stored).toBeTruthy()
    expect(stored.final_decision).toBe(apiAlert.final_decision)
    expect(Number(stored.risk_score)).toBeCloseTo(Number(apiAlert.risk_score), 5)

    expect(fs.existsSync(e2eDbPath)).toBe(true)
    const prodAfter = productionDbSnapshot()
    expect(prodAfter.exists).toBe(prodBefore.exists)
    expect(prodAfter.size).toBe(prodBefore.size)
    expect(prodAfter.mtimeMs).toBe(prodBefore.mtimeMs)

    await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', {
      name: /Alert History/,
    }).click()
    await expect(page.getByRole('heading', { name: 'Alert History' })).toBeVisible()
    await expect(page.getByText(/Showing .* of .* stored events/)).toBeVisible({
      timeout: 20_000,
    })
    await expect(page.getByText(apiAlert.alert_id)).toBeVisible()
    await expect(
      page.locator('table.data').getByText(apiAlert.final_decision, { exact: true }),
    ).toBeVisible()
    await expect(
      page.locator('table.data').getByText(riskText, { exact: true }),
    ).toBeVisible()

    await page.getByRole('button', { name: `#${stored.record_id}` }).click()
    const dialog = page.getByRole('dialog', { name: 'Alert details' })
    await expect(dialog).toBeVisible()
    await expect(
      dialog.getByText(`Alert occurrence #${stored.record_id}`),
    ).toBeVisible()
    await expect(dialog.locator('.badge').getByText(apiAlert.final_decision, { exact: true })).toBeVisible()
    await expect(dialog.getByText(riskText, { exact: true })).toBeVisible()
    await expect(dialog.getByText(apiAlert.alert_id, { exact: true })).toBeVisible()
    await expect(
      dialog.getByText(/not proof of an attack/i),
    ).toBeVisible()
  })
})
