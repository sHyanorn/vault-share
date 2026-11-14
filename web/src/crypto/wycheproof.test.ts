import { describe, expect, it } from 'vitest'
import aesGcmJson from '../../../testdata/wycheproof/aes_gcm_test.json?raw'
import hkdfJson from '../../../testdata/wycheproof/hkdf_sha256_test.json?raw'
import hmacJson from '../../../testdata/wycheproof/hmac_sha256_test.json?raw'
import { aesGcm, hkdfSha256, hmacSha256, type Outcome } from './wycheproof.ts'

interface Test {
  tcId: number
  result: string
  [field: string]: unknown
}

/**
 * The same vectors with the first valid one's expected output changed and
 * the first invalid one marked valid: a runner that cannot fail would pass
 * these too.
 */
function corrupted(
  json: string,
  output: string,
  applies: (group: unknown) => boolean = () => true,
) {
  const file = JSON.parse(json) as { testGroups: { tests: Test[] }[] }
  const tests = file.testGroups.filter(applies).flatMap((g) => g.tests)
  const valid = tests.find((t) => t.result === 'valid')!
  const invalid = tests.find((t) => t.result === 'invalid')!
  const hex = valid[output] as string
  valid[output] = hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0')
  invalid.result = 'valid'
  return { json: JSON.stringify(file), ids: [valid.tcId, invalid.tcId] }
}

/** The vectors named in the failures are exactly those corrupted. */
function expectCaught(outcome: Outcome, ids: number[]) {
  const named = outcome.failures.map((f) => Number(/tcId (\d+) /.exec(f)?.[1]))
  expect(new Set(named)).toEqual(new Set(ids))
}

describe('Wycheproof AES-GCM (AES-256, 96-bit IV, 128-bit tag)', () => {
  const subset = (g: unknown) => {
    const { keySize, ivSize, tagSize } = g as Record<string, number>
    return keySize === 256 && ivSize === 96 && tagSize === 128
  }

  it('passes all 66 vectors', async () => {
    expect(await aesGcm(aesGcmJson)).toEqual({ count: 66, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(aesGcmJson, 'ct', subset)
    expectCaught(await aesGcm(json), ids)
  })
})

describe('Wycheproof HKDF-SHA256', () => {
  it('passes all 86 vectors', async () => {
    expect(await hkdfSha256(hkdfJson)).toEqual({ count: 86, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(hkdfJson, 'okm')
    expectCaught(await hkdfSha256(json), ids)
  })
})

describe('Wycheproof HMAC-SHA256', () => {
  it('passes all 174 vectors', async () => {
    expect(await hmacSha256(hmacJson)).toEqual({ count: 174, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(hmacJson, 'tag')
    expectCaught(await hmacSha256(json), ids)
  })
})
