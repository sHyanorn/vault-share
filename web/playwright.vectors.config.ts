import { defineConfig, devices } from '@playwright/test'

// Runs the crypto vectors in each browser engine, on a Vite dev server that
// serves vectors.html. Needs no running stack.
const port = 5174

export default defineConfig({
  testDir: 'vectors',
  forbidOnly: Boolean(process.env.CI),
  reporter: 'list',
  use: { baseURL: `http://localhost:${port}` },
  webServer: {
    command: `npx vite --port ${port} --strictPort`,
    url: `http://localhost:${port}/vectors.html`,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
})
