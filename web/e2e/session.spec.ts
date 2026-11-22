import { randomBytes } from 'node:crypto'
import {
  expect,
  test,
  type BrowserContext,
  type Page,
  type Route,
} from '@playwright/test'

// One account for every test, in one browser: a client may sign up five
// times an hour, and the other suites need theirs.
test.describe.configure({ mode: 'serial' })

const username = `e2e-${randomBytes(4).toString('hex')}`
const password = 'correct horse battery staple'
const session = '**/api/v1/session'
const pendingSignOut = /^The server did not confirm your sign-out/
const unchecked = /^Your session could not be checked/

let context: BrowserContext
let page: Page

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext()
  page = await context.newPage()
  await page.goto('/signup')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(account(page)).toBeVisible({ timeout: 60_000 })
})

test.afterAll(() => context.close())

/** The header's link to the account, which only a signed-in page shows. */
function account(tab: Page) {
  return tab.getByRole('link', { name: username })
}

/** Loads the app in tab and signs in unless it already is. */
async function signedIn(tab: Page) {
  await tab.goto('/signin')
  const form = tab.getByLabel('Username')
  await expect(form.or(account(tab))).toBeVisible()
  if (await form.isVisible()) {
    await form.fill(username)
    await tab.getByLabel('Password').fill(password)
    await tab.getByRole('button', { name: 'Sign in' }).click()
  }
  await expect(account(tab)).toBeVisible({ timeout: 60_000 })
}

async function signOut(tab: Page) {
  await tab.goto('/account')
  await tab.getByRole('button', { name: 'Sign out' }).click()
}

/** A handler that answers requests of method as answer does, and counts them. */
function failing(method: string, answer: (route: Route) => Promise<void>) {
  const handler = async (route: Route) => {
    if (route.request().method() !== method) return route.fallback()
    handler.requests++
    await answer(route)
  }
  handler.requests = 0
  return handler
}

const noAnswer = (route: Route) => route.abort()

function refused(status: number, code: string) {
  return (route: Route) =>
    route.fulfill({ status, json: { error: { code, message: code } } })
}

/** What the server answers this browser about its session. */
function sessionStatus(tab: Page): Promise<number> {
  return tab.evaluate(async () => (await fetch('/api/v1/session')).status)
}

function stored(tab: Page): Promise<string[]> {
  return tab.evaluate(() => Object.keys(localStorage))
}

test('a sign-out that fails is not shown as a finished one', async () => {
  await signedIn(page)
  const refuse = failing('DELETE', refused(429, 'rate_limited'))
  await page.route(session, refuse)
  await signOut(page)
  await expect(page.getByText(pendingSignOut)).toBeVisible()
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible()
  expect(refuse.requests).toBe(2)
  expect(await stored(page)).toEqual(['vault-share/sign-out'])

  // Every load sends it again, and says so while it keeps failing.
  await page.reload()
  await expect(page.getByText(pendingSignOut)).toBeVisible()
  expect(refuse.requests).toBe(4)

  await page.unroute(session, refuse)
  expect(await sessionStatus(page)).toBe(200)
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByText('You are signed out.')).toBeVisible()
  await expect(page.getByText(pendingSignOut)).toBeHidden()
  expect(await stored(page)).toEqual([])
  expect(await sessionStatus(page)).toBe(401)
})

test('a sign-out that got no answer is sent again at the next load', async () => {
  await signedIn(page)
  const drop = failing('DELETE', noAnswer)
  await page.route(session, drop)
  await signOut(page)
  await expect(page.getByText(pendingSignOut)).toBeVisible()
  expect(drop.requests).toBe(2)

  await page.unroute(session, drop)
  await page.reload()
  await expect(page.getByText('You are signed out.')).toBeVisible()
  await expect(page.getByText(pendingSignOut)).toBeHidden()
  expect(await stored(page)).toEqual([])
  expect(await sessionStatus(page)).toBe(401)

  await page.getByRole('button', { name: 'Dismiss' }).click()
  await expect(page.getByText('You are signed out.')).toBeHidden()
})

test('a pending sign-out does not end a sign-in made since in another tab', async () => {
  await signedIn(page)
  const drop = failing('DELETE', noAnswer)
  await context.route(session, drop)
  await signOut(page)
  await expect(page.getByText(pendingSignOut)).toBeVisible()

  // The sign-in ends the session that was to be signed out, and the debt.
  const other = await context.newPage()
  await signedIn(other)
  await expect(other.getByText(pendingSignOut)).toBeHidden()
  expect(await stored(other)).toEqual(['vault-share/account'])

  await context.unroute(session, drop)
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(account(page)).toBeVisible()
  await expect(page.getByText(pendingSignOut)).toBeHidden()
  expect(await sessionStatus(other)).toBe(200)
  await other.reload()
  await expect(account(other)).toBeVisible()
  await other.close()
})

test('a session check that fails is not shown as signed out', async () => {
  await signedIn(page)
  for (const answer of [
    noAnswer,
    refused(429, 'rate_limited'),
    refused(500, 'internal'),
  ]) {
    const fail = failing('GET', answer)
    await page.route(session, fail)
    await page.goto('/files')
    await expect(page.getByText(unchecked)).toBeVisible()
    await expect(page.getByRole('link', { name: 'Sign in' })).toBeHidden()
    await expect(page.getByLabel('Username')).toBeHidden()
    expect(fail.requests).toBe(1)
    expect(await stored(page)).toEqual(['vault-share/account'])
    for (const path of ['/signin', '/signup']) {
      await page.goto(path)
      await expect(page.getByText(unchecked)).toBeVisible()
      await expect(page.getByLabel('Username')).toBeHidden()
    }

    await page.unroute(session, fail)
    await page.getByRole('button', { name: 'Try again' }).click()
    await expect(account(page)).toBeVisible()
    await expect(page.getByText(unchecked)).toBeHidden()
  }
})

test('a session that could not be checked can still be signed out', async () => {
  await signedIn(page)
  const drop = failing('GET', noAnswer)
  await page.route(session, drop)
  await page.goto('/')
  await expect(page.getByText(unchecked)).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByText(unchecked)).toBeHidden()

  await page.unroute(session, drop)
  expect(await stored(page)).toEqual([])
  expect(await sessionStatus(page)).toBe(401)
})

/** Leaves tab with a stored key that the session it signs in to does not open. */
async function withStaleKey(tab: Page) {
  const key = 'vault-share/account'
  await signedIn(tab)
  const old = await tab.evaluate((k) => localStorage.getItem(k), key)
  await signOut(tab)
  await signedIn(tab)
  await tab.evaluate(({ k, v }) => localStorage.setItem(k, v), {
    k: key,
    v: old!,
  })
}

test('a stored key the session does not open ends the session', async () => {
  await withStaleKey(page)
  const sent = failing('DELETE', (route) => route.fallback())
  await page.route(session, sent)
  await page.reload()
  await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByText(pendingSignOut)).toBeHidden()
  expect(sent.requests).toBe(1)
  expect(await stored(page)).toEqual([])
  expect(await sessionStatus(page)).toBe(401)
  await page.unroute(session, sent)
})

test('that sign-out stays pending until the server confirms it', async () => {
  await withStaleKey(page)
  const drop = failing('DELETE', noAnswer)
  await page.route(session, drop)
  await page.reload()
  await expect(page.getByText(pendingSignOut)).toBeVisible()
  expect(drop.requests).toBe(2)
  expect(await stored(page)).toEqual(['vault-share/sign-out'])

  await page.unroute(session, drop)
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByText('You are signed out.')).toBeVisible()
  await expect(page.getByText(pendingSignOut)).toBeHidden()
  expect(await stored(page)).toEqual([])
  expect(await sessionStatus(page)).toBe(401)
})
