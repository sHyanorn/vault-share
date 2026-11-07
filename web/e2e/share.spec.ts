import { randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test, type Page } from '@playwright/test'

// A headless browser cannot answer the save dialog, so downloads take the
// Blob path that browsers without the File System Access API use.
test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    delete (globalThis as { showSaveFilePicker?: unknown }).showSaveFilePicker
  })
})

interface Options {
  password?: string
  downloads?: number
}

async function share(
  page: Page,
  name: string,
  content: Buffer,
  options: Options = {},
) {
  await page.goto('/')
  await page.setInputFiles('input[type=file]', {
    name,
    mimeType: 'application/octet-stream',
    buffer: content,
  })
  for (let n = 1; n < (options.downloads ?? 1); n++) {
    await page.getByRole('button', { name: 'More' }).click()
  }
  if (options.password) {
    await page.getByRole('button', { name: 'Add a password' }).click()
    await page.getByLabel('Password').fill(options.password)
  }
  await page.getByRole('button', { name: 'Create link' }).click()
  await expect(page.getByText('Your link is ready')).toBeVisible({
    timeout: 60_000,
  })
  const [link, deleteLink] = await page
    .locator('.share-link code')
    .allTextContents()
  return { link: link!, deleteLink: deleteLink! }
}

async function download(page: Page) {
  const button = page.getByRole('button', { name: 'Download' })
  const [file] = await Promise.all([
    page.waitForEvent('download'),
    button.click(),
  ])
  return readFile(await file.path())
}

const gone = 'This file is no longer available'

test('a shared file downloads once, decrypted, and is then gone', async ({
  page,
  context,
}) => {
  // Many 64 KiB records, and above 2 MB, where the S3 client asks the
  // service to accept the request before it sends the body.
  const content = randomBytes(3 << 20)
  const { link } = await share(page, 'report.pdf', content)
  expect(new URL(link).hash).toMatch(/^#[A-Za-z0-9_-]{22}$/)

  const recipient = await context.newPage()
  await recipient.goto(link)
  await expect(
    recipient.getByRole('heading', { name: 'report.pdf' }),
  ).toBeVisible()
  expect((await download(recipient)).equals(content)).toBe(true)
  await recipient.reload()
  await expect(recipient.getByText(gone)).toBeVisible()
})

test('a file can allow several downloads', async ({ page, context }) => {
  const content = randomBytes(1_000)
  const { link } = await share(page, 'notes.txt', content, { downloads: 2 })
  // Each visit is a fresh page, as when the recipient opens the link again.
  for (const left of ['2 downloads left', 'Last download']) {
    const visit = await context.newPage()
    await visit.goto(link)
    await expect(visit.getByText(left)).toBeVisible()
    expect((await download(visit)).equals(content)).toBe(true)
    await visit.close()
  }
  const late = await context.newPage()
  await late.goto(link)
  await expect(late.getByText(gone)).toBeVisible()
})

test('a password protects the link', async ({ page, context }) => {
  const content = randomBytes(5_000)
  const { link } = await share(page, 'keys.txt', content, {
    password: 'correct horse battery',
  })
  const recipient = await context.newPage()
  await recipient.goto(link)
  await expect(
    recipient.getByText('This file is password protected'),
  ).toBeVisible()
  await recipient.getByLabel('Password').fill('wrong guess')
  await recipient.getByRole('button', { name: 'Unlock' }).click()
  await expect(recipient.getByText('Wrong password. Try again.')).toBeVisible({
    timeout: 30_000,
  })
  await recipient.getByLabel('Password').fill('correct horse battery')
  await recipient.getByRole('button', { name: 'Unlock' }).click()
  expect((await download(recipient)).equals(content)).toBe(true)
})

test('the delete link removes the file', async ({ page, context }) => {
  const { link, deleteLink } = await share(
    page,
    'draft.docx',
    randomBytes(2_000),
  )
  const owner = await context.newPage()
  await owner.goto(deleteLink)
  await owner.getByRole('button', { name: 'Delete file' }).click()
  await expect(owner.getByText('The share link no longer works.')).toBeVisible()
  const recipient = await context.newPage()
  await recipient.goto(link)
  await expect(recipient.getByText(gone)).toBeVisible()
})

test('a link without its key is refused before anything is fetched', async ({
  page,
}) => {
  const api: string[] = []
  page.on('request', (r) => {
    if (new URL(r.url()).pathname.startsWith('/api/')) api.push(r.url())
  })
  await page.goto(`/f/${randomBytes(16).toString('base64url')}`)
  await expect(page.getByText('This link is incomplete')).toBeVisible()
  // A request sent after the message appears must be caught too.
  await page.waitForLoadState('networkidle')
  expect(api).toEqual([])
})
