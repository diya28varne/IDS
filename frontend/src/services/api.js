/**
 * ThreatLens API client.
 * Base URL from VITE_API_BASE_URL, or empty string to use the Vite proxy / same origin.
 */

const DEFAULT_BASE = 'http://127.0.0.1:8000'

function resolveBaseUrl() {
  const configured = import.meta.env.VITE_API_BASE_URL
  if (configured === undefined || configured === null) {
    // Dev proxy is preferred when the env var is unset.
    return import.meta.env.DEV ? '' : DEFAULT_BASE
  }
  return String(configured).replace(/\/$/, '')
}

const API_BASE = resolveBaseUrl()

function formatErrorDetail(body, status) {
  if (!body || typeof body !== 'object') {
    return `Request failed (${status})`
  }
  if (typeof body.detail === 'string') return body.detail
  if (typeof body.error === 'string' && typeof body.detail === 'string') {
    return body.detail
  }
  if (Array.isArray(body.detail)) {
    return body.detail
      .map((item) => (typeof item === 'object' ? item.msg || JSON.stringify(item) : String(item)))
      .join('; ')
  }
  return `Request failed (${status})`
}

async function request(path, init = {}) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 30000)
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
    const text = await response.text()
    let body = null
    if (text) {
      try {
        body = JSON.parse(text)
      } catch {
        body = { detail: text.slice(0, 300) }
      }
    }
    if (!response.ok) {
      throw new Error(formatErrorDetail(body, response.status))
    }
    return body
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new Error('Request timed out while contacting the ThreatLens API')
    }
    if (err instanceof TypeError) {
      throw new Error('Backend unavailable — could not reach the ThreatLens API')
    }
    throw err
  } finally {
    clearTimeout(timeout)
  }
}

export function getHealth() {
  return request('/health')
}

export function getSchema() {
  return request('/schema')
}

export function listAlerts(limit = 50, offset = 0) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  return request(`/alerts?${params}`)
}

export function getAlertStats() {
  return request('/alerts/stats')
}

export function getAlert(recordId) {
  return request(`/alerts/${recordId}`)
}

export function predictRecord(record) {
  return request('/predict', {
    method: 'POST',
    body: JSON.stringify({ record }),
  })
}

export function getApiBaseLabel() {
  return API_BASE || '(Vite proxy → http://127.0.0.1:8000)'
}
