#!/usr/bin/env node
// Browser-side security checks against a local vault-share instance, in
// headless Chromium through Playwright: the key never leaves the fragment,
// the CSP and frame-ancestors hold, and file names render as text.
//
//   node scripts/browser_checks.cjs https://localhost [screenshot dir]
//
// Needs the playwright package and its Chromium on the module path: after
// npm ci and npx playwright install chromium in web/, NODE_PATH=web/node_modules.
// Certificates are not verified here; scripts/blackbox.py checks TLS. CI runs
// these checks on every push.
'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs')
const http = require('node:http')
const path = require('node:path')
const { chromium } = require('playwright')

const base = new URL(process.argv[2] ?? 'https://localhost').origin
const shots = process.argv[3]
const counts = { PASS: 0, FAIL: 0 }

function ok(cond, what, detail = '') {
  const status = cond ? 'PASS' : 'FAIL'
  counts[status]++
  console.log(`${status}  ${what}${!cond && detail ? `  (${detail})` : ''}`)
}

async function shot(page, name) {
  if (!shots) return
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'))
  await page.screenshot({ path: path.join(shots, name) })
}

// Request bodies, taken by interception: Playwright reports none for a Blob
// sent by XHR, which is how the ciphertext is uploaded.
const bodies = new WeakMap()

async function captureBodies(context) {
  await context.route('**/*', (route) => {
    bodies.set(route.request(), route.request().postDataBuffer())
    return route.fallback()
  })
}

// Every request the browser sends from now on, with headers and body.
function record(context) {
  const requests = []
  context.on('request', (req) => requests.push(req))
  return async () =>
    Promise.all(
      requests.map(async (req) => ({
        method: req.method(),
        url: req.url(),
        headers: await req.allHeaders().catch(() => req.headers()),
        body: bodies.get(req) ?? null,
      })),
    )
}

function missingBodies(requests) {
  return requests.filter((r) => ['POST', 'PUT'].includes(r.method) && !r.body)
}

// The forms bytes take inside a larger text value: hex, and base64 or
// base64url at each of the three alignments, cut to the characters that do
// not depend on the neighbouring bytes.
function byteForms(bytes) {
  const forms = [bytes.toString('hex'), bytes.toString('hex').toUpperCase()]
  for (const shift of [0, 1, 2]) {
    const padded = Buffer.concat([Buffer.alloc(shift), bytes])
    const skip = [0, 2, 3][shift]
    const tail = padded.length % 3 ? 1 : 0
    for (const encoding of ['base64url', 'base64']) {
      const text = padded.toString(encoding).replace(/=+$/, '')
      forms.push(text.slice(skip, text.length - tail))
    }
  }
  return forms
}

function decoded(text) {
  try {
    return decodeURIComponent(text.replace(/\+/g, ' '))
  } catch {
    return ''
  }
}

// Where a secret shows up in the recorded requests: raw, percent- or
// form-encoded, hex or base64. Text secrets are searched as their UTF-8 bytes too.
function findLeaks(requests, secrets) {
  const found = []
  for (const req of requests) {
    const body = req.body ?? Buffer.alloc(0)
    const fields = [req.url, ...Object.values(req.headers), body.toString('latin1')]
    const text = [...fields, ...fields.map(decoded)].join('\n')
    for (const { label, bytes, value } of secrets) {
      const raw = bytes ?? Buffer.from(value)
      const forms = [...(value ? [value] : []), ...byteForms(raw)]
      if (forms.some((f) => text.includes(f)) || body.includes(raw))
        found.push(`${label} in ${req.method} ${new URL(req.url).pathname}`)
    }
  }
  return found
}

// The key tree of web/src/crypto/keys.ts, recomputed outside the browser.
function deriveKeys(secret) {
  const key = (label) =>
    Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(0), `vault-share/${label}`, 32))
  return { fileKey: key('file'), metaKey: key('meta'), authKey: key('auth') }
}

async function upload(page, name, content, password) {
  await page.goto(base + '/')
  await page.setInputFiles('input[type=file]', { name, mimeType: 'text/html', buffer: content })
  if (password) {
    await page.getByRole('button', { name: 'Add a password' }).click()
    await page.getByLabel('Password').fill(password)
  }
  await page.getByRole('button', { name: 'Create link' }).click()
  await page.getByText('Your link is ready').waitFor({ timeout: 60_000 })
  return page.locator('.share-link code').first().textContent()
}

async function checkFragment(context) {
  const requests = record(context)
  const page = await context.newPage()
  const dialogs = []
  context.on('dialog', (d) => dialogs.push(d.message()) && d.dismiss())
  const name = '<img src=x onerror=alert(document.domain)>.html'
  const content = crypto.randomBytes(200_000) // several 64 KiB records
  const link = await upload(page, name, content)
  await shot(page, 'upload-link-ready.png')
  const fragment = new URL(link).hash.slice(1)
  const secret = Buffer.from(fragment, 'base64url')
  ok(secret.length === 16, 'the share link carries a 16-byte key in the fragment')

  const recipient = await context.newPage()
  await recipient.goto(link)
  const button = recipient.getByRole('button', { name: 'Download' })
  await button.waitFor()
  // Characters that are invalid in file names (<>:"/\\|?*) become underscores
  // before React renders the name as text.
  const title = await recipient.locator('.hero h1').textContent()
  ok(title === name.replace(/[\\/:*?"<>|]/g, '_'), 'a file name made of markup is shown as plain text', title)
  ok((await recipient.locator('img[src="x"]').count()) === 0, 'no element is created from the file name')
  await shot(recipient, 'file-name-as-text.png')
  const [download] = await Promise.all([recipient.waitForEvent('download'), button.click()])
  const saved = fs.readFileSync(await download.path())
  ok(saved.equals(content), 'the download decrypts to the original bytes')
  await recipient.reload()
  await recipient.getByText('This file is no longer available').waitFor()
  ok(true, 'after its one permitted download the link shows the file as gone')
  await shot(recipient, 'link-after-burn.png')
  ok(dialogs.length === 0, 'no script ran from the file name', dialogs.join(', '))

  const sent = await requests()
  const missing = missingBodies(sent)
  ok(missing.length === 0, `every request body was captured, the ${content.length}-byte upload included`,
    missing.map((r) => `${r.method} ${new URL(r.url).pathname}`).join(', '))
  const keys = deriveKeys(secret)
  const leaks = findLeaks(sent, [
    { label: 'fragment', value: fragment },
    { label: 'secret', bytes: secret },
    { label: 'file key', bytes: keys.fileKey },
    { label: 'metadata key', bytes: keys.metaKey },
    { label: 'file name', value: name },
    { label: 'plaintext', bytes: content.subarray(100_000, 100_064) },
  ])
  const api = sent.filter((r) => r.url.startsWith(base + '/api/'))
  ok(api.length >= 5 && leaks.length === 0,
    `none of ${sent.length} requests (${api.length} to the API) carries the fragment, the secret, the file or metadata key, the file name or the plaintext`,
    leaks.join('; '))
  const authUses = findLeaks(sent, [{ label: 'auth key', bytes: keys.authKey }])
  ok(authUses.length === 1 && authUses[0] === 'auth key in POST /api/v1/files',
    'the auth key reaches the server once, in the create request, as designed', authUses.join('; '))
  const referers = sent.filter((r) => r.headers.referer)
  ok(referers.length === 0, 'no request carries a Referer header', referers.map((r) => r.url).join(', '))
  await page.close()
  await recipient.close()
}

async function checkPassword(context) {
  const requests = record(context)
  const page = await context.newPage()
  const password = 'correct horse battery staple'
  const link = await upload(page, 'notes.txt', crypto.randomBytes(1000), password)
  const deleteLink = new URL(await page.locator('.share-link code').nth(1).textContent())
  const fragment = new URL(link).hash.slice(1)
  ok(Buffer.from(fragment, 'base64url').length === 60, 'a protected link carries the 60-byte wrapped secret instead')
  const recipient = await context.newPage()
  await recipient.goto(link)
  await recipient.getByText('This file is password protected').waitFor()
  const before = (await requests()).length
  await recipient.getByLabel('Password').fill('wrong guess')
  await recipient.getByRole('button', { name: 'Unlock' }).click()
  await recipient.getByText('Wrong password. Try again.').waitFor({ timeout: 30_000 })
  ok((await requests()).length === before, 'a wrong password is rejected in the browser without contacting the server')
  await shot(recipient, 'password-wrong.png')
  await recipient.getByLabel('Password').fill(password)
  await recipient.getByRole('button', { name: 'Unlock' }).click()
  await recipient.getByRole('button', { name: 'Download' }).waitFor({ timeout: 30_000 })
  ok(true, 'the right password unlocks the share')
  const sent = await requests()
  const leaks = findLeaks(sent, [
    { label: 'password', value: password },
    { label: 'wrapped secret', value: fragment },
    { label: 'wrapped secret', bytes: Buffer.from(fragment, 'base64url') },
  ])
  ok(missingBodies(sent).length === 0 && leaks.length === 0, 'neither the password nor the wrapped secret is sent',
    leaks.join('; '))
  const id = deleteLink.pathname.split('/').pop()
  const removed = await context.request.delete(`${base}/api/v1/files/${id}`, {
    headers: { Authorization: `Bearer ${deleteLink.hash.slice(1)}` },
  })
  ok(removed.status() === 204, 'the delete link removes the share', String(removed.status()))
  await page.close()
  await recipient.close()
}

async function checkCSP(context) {
  const page = await context.newPage()
  await page.goto(base + '/')
  const result = await page.evaluate(async () => {
    const violations = []
    document.addEventListener('securitypolicyviolation', (e) => violations.push(e.violatedDirective))
    document.body.insertAdjacentHTML('beforeend', '<img src="/missing.png" onerror="window.__handler = 1">')
    const inline = document.createElement('script')
    inline.textContent = 'window.__inline = 1'
    document.body.append(inline)
    const remote = document.createElement('script')
    remote.src = 'https://attacker.example/x.js'
    document.body.append(remote)
    const frame = document.createElement('iframe')
    frame.src = 'javascript:parent.__frame = 1'
    document.body.append(frame)
    // Code evaluated through DevTools is exempt from the page's CSP, so the
    // string is compiled later by a timer, as page code would.
    setTimeout('window.__timer = 1', 0)
    await new Promise((resolve) => setTimeout(resolve, 1500))
    return {
      ran: ['__handler', '__inline', '__frame', '__timer'].filter((k) => k in window),
      violations: [...new Set(violations)].sort(),
    }
  })
  ok(result.ran.length === 0, 'injected handlers, inline and remote scripts, javascript: URLs and string timers do not run',
    result.ran.join(', '))
  ok(['script-src', 'script-src-attr', 'script-src-elem'].every((d) => result.violations.includes(d)),
    `the browser reports violations of ${result.violations.join(', ')}`)
  await page.close()
}

// Uploaded bytes are never executable in the app's origin, even when they are
// a script: the content endpoint answers application/octet-stream with nosniff.
async function checkUploadedScript(context) {
  const api = context.request
  const authKey = crypto.randomBytes(32)
  const payload = Buffer.from('window.__uploaded = 1;'.padEnd(64))
  const created = await api.post(base + '/api/v1/files', {
    data: {
      size: payload.length,
      meta: crypto.randomBytes(40).toString('base64url'),
      auth_key: authKey.toString('base64url'),
      expires_in: 3600,
      max_downloads: 1,
    },
  })
  const { id, owner_token: owner } = await created.json()
  await api.put(`${base}/api/v1/files/${id}/content`, {
    data: payload,
    headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/octet-stream' },
  })
  const { challenge } = await (await api.get(`${base}/api/v1/files/${id}/meta`)).json()
  const signature = crypto.createHmac('sha256', authKey).update(Buffer.from(challenge, 'base64url')).digest('base64url')
  const { token } = await (await api.post(`${base}/api/v1/files/${id}/download`, { data: { challenge, signature } })).json()
  const page = await context.newPage()
  const messages = []
  page.on('console', (m) => messages.push(m.text()))
  await page.goto(base + '/')
  const ran = await page.evaluate(async (src) => {
    const script = document.createElement('script')
    script.src = src
    document.body.append(script)
    await new Promise((resolve) => setTimeout(resolve, 1500))
    return '__uploaded' in window
  }, `/api/v1/files/${id}/content?token=${token}`)
  ok(!ran && messages.some((m) => m.includes('MIME type')),
    'an uploaded script does not run in the app origin: the browser refuses its MIME type', messages.join(' | '))
  await page.close()
}

async function attackerSite(html) {
  const server = http.createServer((_, res) => res.writeHead(200, { 'Content-Type': 'text/html' }).end(html))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, url: `http://127.0.0.1:${server.address().port}/` }
}

async function checkFraming(context) {
  const { server, url } = await attackerSite(
    `<!doctype html><title>attacker</title><p>Framing ${base}</p><iframe src="${base}/" width="640" height="360"></iframe>`,
  )
  const page = await context.newPage()
  const messages = []
  page.on('console', (m) => messages.push(m.text()))
  await page.goto(url)
  await page.waitForTimeout(2000)
  const framed = page.frames().find((f) => f !== page.mainFrame())
  const loaded = framed ? await framed.locator('#root').count().catch(() => 0) : 0
  ok(loaded === 0, 'a page on another origin cannot frame the app', framed?.url())
  ok(messages.some((m) => m.includes("frame-ancestors 'none'")), 'the browser cites frame-ancestors when it refuses the frame')
  await shot(page, 'framing-refused.png')
  await page.close()
  server.close()
}

// The page on the other site sees no answer either way, so the server's
// status comes from the browser's network log.
async function checkCrossSite(browser) {
  const { server, url } = await attackerSite('<!doctype html><title>attacker</title>')
  const context = await browser.newContext({ ignoreHTTPSErrors: true })
  const page = await context.newPage()
  const cdp = await context.newCDPSession(page)
  await cdp.send('Network.enable')
  const seen = new Map()
  const entry = (id) => seen.get(id) ?? seen.set(id, {}).get(id)
  cdp.on('Network.requestWillBeSent', (e) => Object.assign(entry(e.requestId), { method: e.request.method, url: e.request.url }))
  cdp.on('Network.requestWillBeSentExtraInfo', (e) => {
    const name = Object.keys(e.headers).find((k) => k.toLowerCase() === 'sec-fetch-site')
    entry(e.requestId).site = name && e.headers[name]
  })
  cdp.on('Network.responseReceivedExtraInfo', (e) => (entry(e.requestId).status = e.statusCode))
  await page.goto(url)
  const body = JSON.stringify({
    size: 64,
    meta: crypto.randomBytes(40).toString('base64url'),
    auth_key: crypto.randomBytes(32).toString('base64url'),
    expires_in: 3600,
    max_downloads: 1,
  })
  const id = crypto.randomBytes(16).toString('base64url')
  await page.evaluate(
    async ({ base, body, id }) => {
      const quiet = (p) => p.then(() => {}, () => {})
      await quiet(fetch(`${base}/api/v1/files`, { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' }, body }))
      await quiet(fetch(`${base}/api/v1/files/${id}/meta`, { mode: 'no-cors' }))
    },
    { base, body, id },
  )
  await page.waitForTimeout(500)
  const api = [...seen.values()].filter((r) => r.url?.startsWith(base + '/api/'))
  for (const [method, what] of [['POST', 'create'], ['GET', 'read']]) {
    const r = api.find((x) => x.method === method)
    ok(r?.site === 'cross-site' && r?.status === 403,
      `a ${what} sent from a page on another site is refused by the server [${r?.status}, Sec-Fetch-Site ${r?.site}]`)
  }
  ok(!api.some((r) => r.method === 'OPTIONS'), 'the browser sends them without a CORS preflight')
  await context.close()
  server.close()
}

async function main() {
  const host = new URL(base).hostname
  if (!['localhost', '127.0.0.1', '[::1]'].includes(host)) {
    console.error(`${host} is not local; run these checks against a local instance`)
    process.exit(2)
  }
  if (shots) fs.mkdirSync(shots, { recursive: true })
  const browser = await chromium.launch()
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    acceptDownloads: true,
    viewport: { width: 1000, height: 700 },
    deviceScaleFactor: 2,
  })
  // Take the Blob download path so Playwright receives the decrypted file.
  await context.addInitScript(() => delete window.showSaveFilePicker)
  await captureBodies(context)
  console.log(`vault-share browser checks against ${base}`)
  for (const check of [checkFragment, checkPassword, checkCSP, checkUploadedScript, checkFraming, checkCrossSite]) {
    try {
      await check(check === checkCrossSite ? browser : context)
    } catch (error) {
      ok(false, `${check.name} stopped`, error.message.split('\n')[0])
    }
  }
  await browser.close()
  console.log(`\n${counts.PASS} passed, ${counts.FAIL} failed`)
  process.exit(counts.FAIL ? 1 : 0)
}

main()
