import { defineConfig, devices } from '@playwright/test'

// Chromium runs every test. Firefox and WebKit, which save every download
// through a Blob, run the damaged-download tests when E2E_ENGINES names them.
const engines = (process.env.E2E_ENGINES ?? 'chromium').split(/\s+/)

// End-to-end tests drive a running stack, by default the Compose stack at
// https://localhost. Its certificate comes from Caddy's local CA, which the
// browser does not know; scripts/blackbox.py checks TLS with that CA.
export default defineConfig({
  testDir: 'e2e',
  // A share may wait up to a minute for its link.
  timeout: 120_000,
  // Every test is the same client to the server's rate limits.
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  reporter: 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'https://localhost',
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
      grep: /damaged download/,
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
      grep: /damaged download/,
    },
  ].filter((project) => engines.includes(project.name)),
})
