import { describe, expect, it } from 'vitest'
import aesGcmJson from '../../../testdata/wycheproof/aes_gcm_test.json?raw'
import hkdfJson from '../../../testdata/wycheproof/hkdf_sha256_test.json?raw'
import hmacJson from '../../../testdata/wycheproof/hmac_sha256_test.json?raw'
import { corrupted, failedIds } from './testutil.ts'
import { aesGcm, hkdfSha256, hmacSha256 } from './wycheproof.ts'

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
    expect(failedIds((await aesGcm(json)).failures)).toEqual(new Set(ids))
  })
})

describe('Wycheproof HKDF-SHA256', () => {
  it('passes all 86 vectors', async () => {
    expect(await hkdfSha256(hkdfJson)).toEqual({ count: 86, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(hkdfJson, 'okm')
    expect(failedIds((await hkdfSha256(json)).failures)).toEqual(new Set(ids))
  })
})

describe('Wycheproof HMAC-SHA256', () => {
  it('passes all 174 vectors', async () => {
    expect(await hmacSha256(hmacJson)).toEqual({ count: 174, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(hmacJson, 'tag')
    expect(failedIds((await hmacSha256(json)).failures)).toEqual(new Set(ids))
  })
})
