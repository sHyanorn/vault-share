import { createHmac, randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'

// A headless browser cannot answer the save dialog, so downloads take the
// Blob path that browsers without the File System Access API use.
test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    delete (globalThis as { showSaveFilePicker?: unknown }).showSaveFilePicker
  })
})

/** What an authenticator app shows for a base32 secret, steps ahead of now. */
function totp(secret: string, steps = 0): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of secret.replace(/\s+/g, ''))
    bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + steps))
  const mac = createHmac('sha1', key).update(counter).digest()
  const offset = mac[mac.length - 1]! & 15
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(
    6,
    '0',
  )
}

const password = 'correct horse battery staple'

test('an account keeps its files and signs in with a second factor', async ({
  page,
  context,
}) => {
  const username = `e2e-${randomBytes(4).toString('hex')}`
  await page.goto('/')
  await page.getByRole('link', { name: 'Sign in' }).click()
  await page.getByRole('button', { name: 'Create an account' }).click()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByRole('link', { name: username })).toBeVisible({
    timeout: 60_000,
  })

  // A file shared while signed in is kept in My files, and its link works.
  const content = randomBytes(5_000)
  await page.setInputFiles('input[type=file]', {
    name: 'minutes.txt',
    mimeType: 'text/plain',
    buffer: content,
  })
  await page.getByRole('button', { name: 'Create link' }).click()
  await expect(
    page.getByRole('link', { name: 'Saved to My files' }),
  ).toBeVisible({
    timeout: 60_000,
  })
  await page.getByRole('link', { name: 'My files', exact: true }).click()
  await expect(page.getByText('minutes.txt')).toBeVisible()

  // Two-factor sign-in, set up with the code an app would show.
  await page.getByRole('link', { name: username }).click()
  await page.getByRole('button', { name: /Two-factor sign-in/ }).click()
  const secret = await page.locator('.secret code').innerText()
  await page.getByLabel('Code from the app').fill(totp(secret))
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Turn on' }).click()
  await expect(page.getByText('Two-factor sign-in is on')).toBeVisible({
    timeout: 60_000,
  })
  const codes = await page.locator('.codes code').allTextContents()
  expect(codes).toHaveLength(10)
  await page.getByRole('button', { name: 'Done' }).click()

  // Signed out, the password alone is not enough.
  await page.getByRole('button', { name: 'Sign out' }).click()
  await page.getByRole('link', { name: 'Sign in' }).click()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.getByLabel('Code').fill('000000')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('Wrong code. Try again.')).toBeVisible()
  // The code used to turn it on was spent; the next step's is fresh.
  await page.getByLabel('Code').fill(totp(secret, 1))
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/without the right code/)).toBeVisible({
    timeout: 60_000,
  })

  // A reload opens the account again from this browser's sealed copy.
  await page.goto('/files')
  await expect(page.getByText('minutes.txt')).toBeVisible({ timeout: 30_000 })
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.getByRole('button', { name: 'Copy link to minutes.txt' }).click()
  const link = String(await page.evaluate('navigator.clipboard.readText()'))
  expect(new URL(link).hash).toMatch(/^#[A-Za-z0-9_-]{22}$/)
  const recipient = await context.newPage()
  await recipient.goto(link)
  const [download] = await Promise.all([
    recipient.waitForEvent('download'),
    recipient.getByRole('button', { name: 'Download' }).click(),
  ])
  expect((await readFile(await download.path())).equals(content)).toBe(true)
  await recipient.close()

  // A recovery code signs in once.
  await page.getByRole('link', { name: username }).click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await page.getByRole('link', { name: 'Sign in' }).click()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await page.getByRole('button', { name: 'Use a recovery code' }).click()
  await page.getByLabel('Recovery code').fill(codes[0]!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('9 recovery codes left.')).toBeVisible({
    timeout: 60_000,
  })

  // Deleting the account deletes its files.
  await page.getByRole('link', { name: username }).click()
  await page.getByRole('button', { name: 'Delete account' }).click()
  await page.getByLabel('Password').fill(password)
  await page.getByLabel('Code or recovery code').fill(codes[1]!)
  await page.getByRole('button', { name: 'Delete account' }).last().click()
  await expect(
    page.getByText('Your account and its files are deleted.'),
  ).toBeVisible({
    timeout: 60_000,
  })
  const gone = await context.newPage()
  await gone.goto(link)
  await expect(gone.getByText('This file is no longer available')).toBeVisible()
})
