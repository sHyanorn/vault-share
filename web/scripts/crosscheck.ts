// The client's side of crosscheck/crosscheck.py: makes shares with the
// client's own code for the Python implementation to open, and opens the
// ones it made. Node 22 runs it as it is:
//
//   node scripts/crosscheck.ts generate FILE
//   node scripts/crosscheck.ts check FILE

import { readFile, writeFile } from 'node:fs/promises'
import {
  decryptMetadata,
  decryptStream,
  deriveKeys,
  encryptMetadata,
  encryptStream,
  exportAuthKey,
  signChallenge,
  unwrapSecret,
  wrapSecret,
} from '../src/crypto/index.ts'
import {
  collect,
  fromHex,
  randomBytes,
  streamOf,
  toHex,
} from '../src/crypto/testutil.ts'

const RS = 65536
const HEADER = 21
const DATA = RS - 17
const SIZES = [0, 1, DATA - 1, DATA, DATA + 1, 2 * DATA, 200_000]
const NAME = 'résumé 2026.pdf'
const PASSWORD = 'café horse 8chars'

interface Case {
  secret: string
  authKey: string
  body: string
  plain: string
  meta: string
  name: string
  type: string
  size: number
  challenge: string
  sig: string
}

interface Wrap {
  password: string
  wrapped: string
  secret: string
}

function require(condition: boolean, what: string) {
  if (!condition) throw new Error(`mismatch: ${what}`)
}

async function rejects(body: Uint8Array, fileKey: Uint8Array<ArrayBuffer>) {
  try {
    await collect(decryptStream(streamOf(body, 4099), fileKey))
    return false
  } catch {
    return true
  }
}

async function generate(path: string) {
  const cases: Case[] = []
  for (const size of SIZES) {
    const secret = randomBytes(16)
    const plain = randomBytes(size)
    const keys = await deriveKeys(secret)
    const body = await collect(
      encryptStream(streamOf(plain, 7777), keys.fileKey),
    )
    const meta = { name: NAME, type: 'application/pdf', size }
    const challenge = randomBytes(32)
    cases.push({
      secret: toHex(secret),
      authKey: toHex(await exportAuthKey(keys.authKey)),
      body: toHex(body),
      plain: toHex(plain),
      meta: toHex(await encryptMetadata(keys.metaKey, meta)),
      ...meta,
      challenge: toHex(challenge),
      sig: toHex(await signChallenge(keys.authKey, challenge)),
    })
  }
  const wraps: Wrap[] = []
  for (const form of ['NFC', 'NFD']) {
    const secret = randomBytes(16)
    const password = PASSWORD.normalize(form)
    const wrapped = await wrapSecret(secret, password)
    wraps.push({ password, wrapped: toHex(wrapped), secret: toHex(secret) })
  }
  await writeFile(path, JSON.stringify({ cases, wraps }))
  console.log(
    `wrote ${cases.length} shares and ${wraps.length} wrapped secrets to ${path}`,
  )
}

async function check(path: string) {
  const data = JSON.parse(await readFile(path, 'utf8')) as {
    cases: Case[]
    wraps: Wrap[]
  }
  require(data.cases.length === SIZES.length &&
    data.wraps.length === 2, 'counts')
  for (const c of data.cases) {
    const keys = await deriveKeys(fromHex(c.secret))
    const body = fromHex(c.body)
    require(toHex(await exportAuthKey(keys.authKey)) === c.authKey, 'auth key')
    const plain = await collect(
      decryptStream(streamOf(body, 4099), keys.fileKey),
    )
    require(plain.length === c.size && toHex(plain) === c.plain, 'body')
    const meta = await decryptMetadata(keys.metaKey, fromHex(c.meta))
    require(meta.name === c.name &&
      meta.type === c.type &&
      meta.size === c.size, 'metadata')
    const sig = await signChallenge(keys.authKey, fromHex(c.challenge))
    require(toHex(sig) === c.sig, 'signature')
    const changed = new Uint8Array(body)
    changed[changed.length - 1]! ^= 1
    require(await rejects(
      changed,
      keys.fileKey,
    ), 'a changed last byte was accepted')
    const records = Math.ceil((body.length - HEADER) / RS)
    if (records > 1)
      require(await rejects(
        body.subarray(0, HEADER + (records - 1) * RS),
        keys.fileKey,
      ), 'a cut body was accepted')
    console.log(
      `size ${c.size}: ${records} record(s), body, metadata, auth key and signature match; damage rejected`,
    )
  }
  for (const w of data.wraps) {
    const secret = await unwrapSecret(fromHex(w.wrapped), w.password)
    require(secret !== null && toHex(secret) === w.secret, 'wrapped secret')
  }
  console.log(`${data.wraps.length} wrapped secrets open with their passwords`)
}

const [command, path] = process.argv.slice(2)
if (command === 'generate' && path) await generate(path)
else if (command === 'check' && path) await check(path)
else {
  console.error('usage: node scripts/crosscheck.ts generate|check FILE')
  process.exit(2)
}
