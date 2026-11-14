// Runs testdata/share_format_test.json through decryptStream as the
// download page reads a file. A valid vector must give the whole file. An
// invalid one must fail, after releasing at most the valid records in front
// of the error.

import { decryptStream } from './ece.ts'
import { deriveKeys } from './keys.ts'
import { collect, fromHex, streamOf, toHex } from './testutil.ts'
import type { Outcome } from './wycheproof.ts'

interface Test {
  tcId: number
  comment: string
  secret: string
  ct: string
  msgLength: number
  msgSha256: string
  result: 'valid' | 'invalid'
}

async function sha256(bytes: Uint8Array<ArrayBuffer>) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}

export async function shareFormat(json: string): Promise<Outcome> {
  const file = JSON.parse(json) as { testGroups: { tests: Test[] }[] }
  const outcome: Outcome = { count: 0, failures: [] }
  for (const t of file.testGroups.flatMap((g) => g.tests)) {
    outcome.count++
    const ct = await collect(
      new Blob([fromHex(t.ct)])
        .stream()
        .pipeThrough(new DecompressionStream('deflate')),
    )
    const { fileKey } = await deriveKeys(fromHex(t.secret))
    const reader = decryptStream(streamOf(ct, 16_384), fileKey).getReader()
    const parts: Uint8Array[] = []
    let failed = false
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        parts.push(value)
      }
    } catch {
      failed = true
    }
    const released = concat(parts)
    const matches =
      released.length === t.msgLength &&
      (await sha256(released)) === t.msgSha256
    const fail = (reason: string) =>
      outcome.failures.push(`tcId ${t.tcId} (${t.comment}): ${reason}`)
    if (t.result === 'valid') {
      if (failed) fail('a valid stream failed')
      else if (!matches) fail('the file does not match')
      continue
    }
    if (!failed) fail('an invalid stream decrypted')
    if (
      released.length > t.msgLength ||
      (released.length === t.msgLength && !matches)
    )
      fail(`released ${released.length} bytes beyond the valid records`)
  }
  return outcome
}

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}
