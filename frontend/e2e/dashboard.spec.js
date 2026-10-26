import { expect, test } from '@playwright/test'

/**
 * Smoke coverage against the dedicated E2E API/UI ports from playwright.config.js
 * (temporary THREATLENS_DB_PATH under frontend/.e2e-tmp/).
 */
test.describe('ThreatLens dashboard smoke', () => {
  test('overview loads and shows backend status', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    await expect(
      page.getByText(/Backend connected|Backend reachable/),
    ).toBeVisible({ timeout: 15_000 })
    // Empty E2E DB → empty history; or stats card if prior workflow test wrote rows.
    const empty = page.getByText('No stored alerts yet')
    const totalCard = page.getByText('Total stored events')
    await expect(empty.or(totalCard)).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Loading historical alerts…')).toHaveCount(0)
  })

  test('alert history and about pages navigate', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Alert History' }).click()
    await expect(page.getByRole('heading', { name: 'Alert History' })).toBeVisible()

    await page.getByRole('link', { name: 'About ThreatLens' }).click()
    await expect(page.getByRole('heading', { name: 'About ThreatLens' })).toBeVisible()
    await expect(page.getByText('Important limitations')).toBeVisible()
  })

  test('traffic analysis loads schema-driven form', async ({ page }) => {
    await page.goto('/traffic')
    await expect(page.getByRole('heading', { name: 'Traffic Analysis' })).toBeVisible()
    await expect(page.getByText(/Schema from/)).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('button', { name: 'Run prediction' })).toBeVisible()
  })

  test('shows unavailable message when API base is wrong', async ({ page }) => {
    await page.route('**/health', async (route) => {
      await route.abort('failed')
    })
    await page.goto('/')
    await expect(
      page.getByText('Backend unavailable', { exact: true }),
    ).toBeVisible({
      timeout: 15_000,
    })
  })
})
