// Runs Wycheproof vectors (testdata/wycheproof) through the Web Crypto calls
// the client makes, so the same checks run under Node and in each browser.
// Each runner returns how many vectors it applied and which of them failed.

import { hkdf, signChallenge } from './keys.ts'
import { fromHex, toHex } from './testutil.ts'

export interface Outcome {
  count: number
  failures: string[]
}

type Result = 'valid' | 'invalid' | 'acceptable'

interface Vectors<Group> {
  testGroups: Group[]
}

interface AeadGroup {
  keySize: number
  ivSize: number
  tagSize: number
  tests: {
    tcId: number
    comment: string
    key: string
    iv: string
    aad: string
    msg: string
    ct: string
    tag: string
    result: Result
  }[]
}

/**
 * AES-256-GCM with a 96-bit IV and a 128-bit tag, the only parameters the
 * client uses, with and without associated data as ece.ts and account.ts
 * call it. Valid vectors must encrypt to the published ciphertext and
 * decrypt back; invalid ones must fail to decrypt.
 */
export async function aesGcm(json: string): Promise<Outcome> {
  const file = JSON.parse(json) as Vectors<AeadGroup>
  const outcome: Outcome = { count: 0, failures: [] }
  for (const group of file.testGroups) {
    if (group.keySize !== 256 || group.ivSize !== 96 || group.tagSize !== 128)
      continue
    for (const t of group.tests) {
      outcome.count++
      const key = await crypto.subtle.importKey(
        'raw',
        fromHex(t.key),
        'AES-GCM',
        false,
        ['encrypt', 'decrypt'],
      )
      const aad = fromHex(t.aad)
      const params = {
        name: 'AES-GCM',
        iv: fromHex(t.iv),
        tagLength: 128,
        ...(aad.length > 0 ? { additionalData: aad } : {}),
      }
      const sealed = t.ct + t.tag
      let opened: string | null
      try {
        opened = toHex(
          new Uint8Array(
            await crypto.subtle.decrypt(params, key, fromHex(sealed)),
          ),
        )
      } catch {
        opened = null
      }
      const fail = (reason: string) =>
        outcome.failures.push(
          `AES-GCM tcId ${t.tcId} (${t.comment}): ${reason}`,
        )
      if (t.result === 'invalid') {
        if (opened !== null) fail('an invalid ciphertext decrypted')
        continue
      }
      if (opened !== t.msg) fail('decryption does not match')
      const out = toHex(
        new Uint8Array(
          await crypto.subtle.encrypt(params, key, fromHex(t.msg)),
        ),
      )
      if (out !== sealed) fail('encryption does not match')
    }
  }
  return outcome
}

interface HkdfGroup {
  tests: {
    tcId: number
    comment: string
    ikm: string
    salt: string
    info: string
    size: number
    okm: string
    result: Result
  }[]
}

/** HKDF-SHA256 through keys.ts, which derives every key of a share. */
export async function hkdfSha256(json: string): Promise<Outcome> {
  const file = JSON.parse(json) as Vectors<HkdfGroup>
  const outcome: Outcome = { count: 0, failures: [] }
  for (const group of file.testGroups) {
    for (const t of group.tests) {
      outcome.count++
      let okm: string | null
      try {
        okm = toHex(
          await hkdf(fromHex(t.ikm), fromHex(t.salt), fromHex(t.info), t.size),
        )
      } catch {
        okm = null
      }
      const fail = (reason: string) =>
        outcome.failures.push(`HKDF tcId ${t.tcId} (${t.comment}): ${reason}`)
      if (t.result === 'invalid') {
        if (okm !== null) fail('an invalid request produced output')
      } else if (okm !== t.okm) {
        fail(okm === null ? 'derivation failed' : 'output does not match')
      }
    }
  }
  return outcome
}

interface MacGroup {
  tagSize: number
  tests: {
    tcId: number
    comment: string
    key: string
    msg: string
    tag: string
    result: Result
  }[]
}

/**
 * HMAC-SHA256 through signChallenge, which signs the server's challenge.
 * A truncated tag is compared with the start of the full one; an invalid
 * vector's tag must not match.
 */
export async function hmacSha256(json: string): Promise<Outcome> {
  const file = JSON.parse(json) as Vectors<MacGroup>
  const outcome: Outcome = { count: 0, failures: [] }
  for (const group of file.testGroups) {
    for (const t of group.tests) {
      outcome.count++
      const key = await crypto.subtle.importKey(
        'raw',
        fromHex(t.key),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      )
      const tag = toHex(await signChallenge(key, fromHex(t.msg))).slice(
        0,
        group.tagSize / 4,
      )
      if ((tag === t.tag) !== (t.result === 'valid'))
        outcome.failures.push(
          `HMAC tcId ${t.tcId} (${t.comment}): tag ${tag === t.tag ? 'matches' : 'does not match'}`,
        )
    }
  }
  return outcome
}
