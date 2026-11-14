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
  return createLink(page, name, content, options)
}

/** Shares a file from the upload page as it stands. */
async function createLink(
  page: Page,
  name: string,
  content: Buffer,
  options: Options = {},
) {
  await page.setInputFiles('input[type=file]', {
    name,
    mimeType: 'application/octet-stream',
    buffer: content,
  })
  for (let n = 1; n < (options.downloads ?? 1); n++) {
    await page.getByRole('button', { name: 'More' }).click()
  }
  if (options.password !== undefined) {
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

test('a password field left empty shares without a password', async ({
  page,
  context,
}) => {
  const content = randomBytes(1_000)
  const { link } = await share(page, 'plain.txt', content, { password: '' })
  expect(new URL(link).hash).toMatch(/^#[A-Za-z0-9_-]{22}$/)
  const recipient = await context.newPage()
  await recipient.goto(link)
  expect((await download(recipient)).equals(content)).toBe(true)
})

test('the next file does not inherit the last password', async ({
  page,
  context,
}) => {
  const first = await share(page, 'sealed.txt', randomBytes(1_000), {
    password: 'correct horse battery',
  })
  await page.getByRole('button', { name: 'Share another file' }).click()
  const content = randomBytes(1_000)
  const { link } = await createLink(page, 'open.txt', content)
  expect(new URL(link).hash).toMatch(/^#[A-Za-z0-9_-]{22}$/)
  const recipient = await context.newPage()
  await recipient.goto(link)
  expect((await download(recipient)).equals(content)).toBe(true)

  const owner = await context.newPage()
  await owner.goto(first.deleteLink)
  await owner.getByRole('button', { name: 'Delete file' }).click()
  await expect(owner.getByText('The share link no longer works.')).toBeVisible()
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

// A 200,000-byte file is three full records of 65,536 bytes after the
// 21-byte header, and a last record of 3,460. Each damage leaves at least
// one valid record in front of the error, so plaintext reaches the sink
// before decryption fails.
const RECORD = 65_536
const HEADER = 21
const damages: [string, (body: Buffer) => Buffer][] = [
  ['no last record', (body) => body.subarray(0, HEADER + 3 * RECORD)],
  [
    'data after the last record',
    (body) => Buffer.concat([body, Buffer.alloc(16)]),
  ],
  [
    'a changed byte in the third record',
    (body) => {
      const out = Buffer.from(body)
      out[HEADER + 2 * RECORD + 100]! ^= 1
      return out
    },
  ],
]
const unchanged = (body: Buffer) => body

/** Opens the link with the ciphertext the server sends passed through damage. */
async function openDamaged(
  page: Page,
  link: string,
  damage: (body: Buffer) => Buffer,
) {
  await page.route('**/api/v1/files/*/content?*', async (route) => {
    const response = await route.fetch()
    const headers = response.headers()
    delete headers['content-length']
    await route.fulfill({
      response,
      headers,
      body: damage(await response.body()),
    })
  })
  await page.goto(link)
}

async function expectDiscarded(page: Page) {
  await expect(page.getByText('Download failed')).toBeVisible()
  await expect(
    page.getByText(
      'The file could not be decrypted. The download was discarded.',
    ),
  ).toBeVisible()
}

test('a damaged download is never offered as a file', async ({
  page,
  context,
}) => {
  const content = randomBytes(200_000)
  const { link } = await share(page, 'photos.zip', content, { downloads: 4 })
  for (const [name, damage] of damages) {
    const visit = await context.newPage()
    let offered = 0
    visit.on('download', () => offered++)
    await openDamaged(visit, link, damage)
    await visit.getByRole('button', { name: 'Download' }).click()
    await expectDiscarded(visit)
    expect(offered, name).toBe(0)
    await visit.close()
  }
  // The same route without damage delivers the file, so the failures above
  // come from the damage alone.
  const visit = await context.newPage()
  await openDamaged(visit, link, unchanged)
  expect((await download(visit)).equals(content)).toBe(true)
})

test('a damaged download written to disk is aborted, never committed', async ({
  page,
  context,
}) => {
  const content = randomBytes(200_000)
  const { link } = await share(page, 'photos.zip', content, { downloads: 4 })
  const attempts = [...damages, ['no damage', unchanged] as const]
  for (const [name, damage] of attempts) {
    const visit = await context.newPage()
    await openDamaged(visit, link, damage)
    // A save dialog whose file records what reaches it, installed after the
    // page loads so the beforeEach removal of the API does not undo it.
    await visit.evaluate(() => {
      const file = { bytes: [] as number[], closed: false, aborted: false }
      Object.assign(globalThis, {
        savedFile: file,
        showSaveFilePicker: async () => ({
          createWritable: async () =>
            new WritableStream<Uint8Array>({
              write(chunk) {
                file.bytes.push(...chunk)
              },
              close() {
                file.closed = true
              },
              abort() {
                file.aborted = true
              },
            }),
        }),
      })
    })
    await visit.getByRole('button', { name: 'Download' }).click()
    if (damage === unchanged) {
      await expect(visit.getByText('Saved to your device.')).toBeVisible()
    } else {
      await expectDiscarded(visit)
    }
    const file = await visit.evaluate(
      () =>
        (
          globalThis as unknown as {
            savedFile: { bytes: number[]; closed: boolean; aborted: boolean }
          }
        ).savedFile,
    )
    if (damage === unchanged) {
      expect(file).toMatchObject({ closed: true, aborted: false })
      expect(Buffer.from(file.bytes).equals(content)).toBe(true)
    } else {
      expect(file, name).toMatchObject({ closed: false, aborted: true })
      // Plaintext of the valid records had reached the file before the error.
      expect(file.bytes.length, name).toBeGreaterThan(0)
      expect(file.bytes.length, name).toBeLessThan(content.length)
    }
    await visit.close()
  }
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
