import { argon2id } from 'hash-wasm'
import { describe, expect, it } from 'vitest'
import {
  ARGON2_PARAMS,
  WRAPPED_LENGTH,
  unwrapSecret,
  wrapSecret,
} from './password.ts'
import { fromHex, randomBytes, toHex } from './testutil.ts'

describe('password wrapping', () => {
  it('round-trips with the right password and fails closed with a wrong one', async () => {
    const secret = randomBytes(16)
    const wrapped = await wrapSecret(secret, 'correct horse battery staple')
    expect(wrapped).toHaveLength(WRAPPED_LENGTH)
    expect(await unwrapSecret(wrapped, 'correct horse battery staple')).toEqual(
      secret,
    )
    expect(
      await unwrapSecret(wrapped, 'correct horse battery stapl'),
    ).toBeNull()
    expect(await unwrapSecret(wrapped, '')).toBeNull()
  }, 30_000)

  it('uses a fresh salt and iv per wrap and rejects tampering', async () => {
    const secret = randomBytes(16)
    const a = await wrapSecret(secret, 'pw')
    const b = await wrapSecret(secret, 'pw')
    expect(toHex(a)).not.toBe(toHex(b))
    for (const index of [0, 16, 28, WRAPPED_LENGTH - 1]) {
      const bad = new Uint8Array(a)
      bad[index] ^= 1
      expect(await unwrapSecret(bad, 'pw'), `byte ${index}`).toBeNull()
    }
    await expect(unwrapSecret(a.subarray(1), 'pw')).rejects.toThrow('length')
  }, 30_000)

  it('derives the wrapping key with the pinned Argon2id parameters', async () => {
    // Known answer generated with hash-wasm for these parameters; guards the
    // parameters and the derivation against accidental change.
    expect(ARGON2_PARAMS).toEqual({
      memorySize: 65536,
      iterations: 2,
      parallelism: 1,
    })
    const bits = await argon2id({
      ...ARGON2_PARAMS,
      password: 'pw',
      salt: fromHex('000102030405060708090a0b0c0d0e0f'),
      hashLength: 32,
      outputType: 'hex',
    })
    expect(bits).toBe(
      '53d013a10853924e0101463e610b2ccebba475d2cac578125cf1aa876bf53a13',
    )
  }, 30_000)
})
