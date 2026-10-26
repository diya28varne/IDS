import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Playwright E2E sets THREATLENS_E2E_API_PROXY to the dedicated API port.
// Local `npm run dev` keeps the default developer API on :8000.
const apiProxyTarget =
  process.env.THREATLENS_E2E_API_PROXY || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  // Production build is mounted by FastAPI at /dashboard on Vercel / :8000.
  base: process.env.NODE_ENV === 'production' ? '/dashboard/' : '/',
  server: {
    port: 5173,
    proxy: {
      '/health': apiProxyTarget,
      '/schema': apiProxyTarget,
      '/predict': apiProxyTarget,
      '/alerts': apiProxyTarget,
      '/docs': apiProxyTarget,
      '/openapi.json': apiProxyTarget,
    },
  },
})
