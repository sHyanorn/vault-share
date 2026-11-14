import { expect, test } from '@playwright/test'

// The vectors run in each browser's own Web Crypto, which is what the
// client uses there; Node's results say nothing about it.
test('Wycheproof vectors pass in this browser', async ({ page }) => {
  await page.goto('/vectors.html')
  const outcome = await page
    .waitForFunction(() => (globalThis as { vectors?: unknown }).vectors)
    .then((handle) => handle.jsonValue())
  expect(outcome).toEqual({
    aesGcm: { count: 66, failures: [] },
    hkdf: { count: 86, failures: [] },
    hmac: { count: 174, failures: [] },
  })
})
