#!/usr/bin/env node
// Browser-side security checks against a local vault-share instance, in
// headless Chromium through Playwright: the key never leaves the fragment,
// the CSP and frame-ancestors hold, and file names render as text.
//
//   node scripts/browser_checks.cjs https://localhost [screenshot dir]
//
// Needs the playwright package (1.63) with its Chromium on the module path,
// e.g. NODE_PATH=$(npm root -g). Certificates are not verified here;
// scripts/blackbox.py checks TLS.
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

// Every request the browser sends, with headers and body.
function record(context) {
  const requests = []
  context.on('request', (req) => requests.push(req))
  return async () =>
    Promise.all(
      requests.map(async (req) => ({
        method: req.method(),
        url: req.url(),
        headers: await req.allHeaders().catch(() => req.headers()),
        body: req.postDataBuffer() ?? Buffer.alloc(0),
      })),
    )
}

// Where a secret shows up in the recorded requests, in any common encoding.
function findLeaks(requests, secrets) {
  const found = []
  for (const req of requests) {
    const text = [req.url, ...Object.values(req.headers), req.body.toString('latin1')].join('\n')
    for (const { label, bytes, value } of secrets) {
      const forms = value
        ? [value]
        : [bytes.toString('base64url'), bytes.toString('base64').replace(/=+$/, ''), bytes.toString('hex')]
      if (forms.some((f) => text.includes(f)) || (bytes && req.body.includes(bytes)))
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
  const keys = deriveKeys(secret)
  const leaks = findLeaks(sent, [
    { label: 'fragment', value: fragment },
    { label: 'secret', bytes: secret },
    { label: 'file key', bytes: keys.fileKey },
    { label: 'metadata key', bytes: keys.metaKey },
  ])
  const api = sent.filter((r) => r.url.startsWith(base + '/api/'))
  ok(api.length >= 5 && leaks.length === 0,
    `none of ${sent.length} requests (${api.length} to the API) carries the fragment, the secret, the file key or the metadata key`,
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
  const leaks = findLeaks(await requests(), [
    { label: 'password', value: password },
    { label: 'wrapped secret', value: fragment },
    { label: 'wrapped secret', bytes: Buffer.from(fragment, 'base64url') },
  ])
  ok(leaks.length === 0, 'neither the password nor the wrapped secret is sent', leaks.join('; '))
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
    `the browser reports each as a CSP violation: ${result.violations.join(', ')}`)
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

async function checkCrossSite(context) {
  const { server, url } = await attackerSite('<!doctype html><title>attacker</title>')
  const requests = record(context)
  const page = await context.newPage()
  await page.goto(url)
  const auth = crypto.randomBytes(32).toString('base64url')
  const meta = crypto.randomBytes(40).toString('base64url')
  const body = JSON.stringify({ size: 1 << 20, meta, auth_key: auth, expires_in: 604800, max_downloads: 1 })
  const seen = await page.evaluate(
    async ({ target, body }) =>
      fetch(target, { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' }, body }).then(
        (r) => `an opaque response (${r.type})`,
        (e) => `an error (${e.message})`,
      ),
    { target: base + '/api/v1/files', body },
  )
  const sent = (await requests()).filter((r) => r.url.startsWith(base + '/api/'))
  ok(sent.length === 1 && sent[0].method === 'POST',
    `a page on another site sends a create without a CORS preflight and sees ${seen}; whether the server acted is in its log`,
    sent.map((r) => r.method).join(', '))
  await page.close()
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
  console.log(`vault-share browser checks against ${base}`)
  for (const check of [checkFragment, checkPassword, checkCSP, checkUploadedScript, checkFraming, checkCrossSite]) {
    try {
      await check(context)
    } catch (error) {
      ok(false, `${check.name} stopped`, error.message.split('\n')[0])
    }
  }
  await browser.close()
  console.log(`\n${counts.PASS} passed, ${counts.FAIL} failed`)
  process.exit(counts.FAIL ? 1 : 0)
}

main()
