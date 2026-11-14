import { argon2id } from 'hash-wasm'
import { describe, expect, it } from 'vitest'
import {
  ARGON2_PARAMS,
  MIN_PASSWORD_LENGTH,
  WRAPPED_LENGTH,
  passwordTooShort,
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
    const a = await wrapSecret(secret, 'password')
    const b = await wrapSecret(secret, 'password')
    expect(toHex(a)).not.toBe(toHex(b))
    for (const index of [0, 16, 28, WRAPPED_LENGTH - 1]) {
      const bad = new Uint8Array(a)
      bad[index] ^= 1
      expect(await unwrapSecret(bad, 'password'), `byte ${index}`).toBeNull()
    }
    await expect(unwrapSecret(a.subarray(1), 'password')).rejects.toThrow(
      'length',
    )
  }, 30_000)

  it('wraps only under passwords of 8 code points or more', async () => {
    expect(MIN_PASSWORD_LENGTH).toBe(8)
    const secret = randomBytes(16)
    for (const short of ['', '1234567', '🔑'.repeat(7)]) {
      expect(passwordTooShort(short), short).toBe(true)
      await expect(wrapSecret(secret, short)).rejects.toThrow('8 characters')
    }
    // Eight emoji are 16 UTF-16 units but eight characters.
    expect(passwordTooShort('🔑'.repeat(8))).toBe(false)
    expect(await wrapSecret(secret, '🔑'.repeat(8))).toHaveLength(
      WRAPPED_LENGTH,
    )
  }, 30_000)

  it('still opens a link wrapped under a short password before the minimum', async () => {
    const legacy = fromHex(
      '917e83a7c3568b5e021ad6f62ee03b445a45b0dbdd7c025fa6d619af6bca29aaf55d798c834af312bfe095838bfeac268d183d2e546c7acd6214f5c5',
    )
    expect(await unwrapSecret(legacy, 'pw')).toEqual(
      fromHex('00112233445566778899aabbccddeeff'),
    )
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

describe('password normalization (F70)', () => {
  const nfc = 'café horse 8chars'.normalize('NFC')
  const nfd = nfc.normalize('NFD')

  it('opens a link wrapped under one Unicode form with the other', async () => {
    const secret = randomBytes(16)
    for (const [wrapAs, typed] of [
      [nfc, nfd],
      [nfd, nfc],
    ] as const) {
      const wrapped = await wrapSecret(secret, wrapAs)
      expect(await unwrapSecret(wrapped, typed)).toEqual(secret)
    }
  }, 60_000)

  it('folds compatibility characters such as full-width letters', async () => {
    const secret = randomBytes(16)
    const wrapped = await wrapSecret(secret, 'ｐａｓｓｗｏｒｄ１２')
    expect(await unwrapSecret(wrapped, 'password12')).toEqual(secret)
    expect(await unwrapSecret(wrapped, 'ｐａｓｓｗｏｒｄ１２')).toEqual(secret)
  }, 60_000)

  it('opens a link wrapped before normalization in either form', async () => {
    // Wrapped by crosscheck/vaultshare.py under the UTF-8 bytes of the NFD
    // form, as the client wrapped every password before F70.
    const legacy = fromHex(
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b3e7e8f0bd2ca036d3739f9ee55bbadfba9a94b81c8f13a2f832f2528cfade557',
    )
    for (const typed of [nfd, nfc])
      expect(await unwrapSecret(legacy, typed)).toEqual(
        fromHex('00112233445566778899aabbccddeeff'),
      )
  }, 60_000)

  it('counts the minimum length after normalization', () => {
    // Seven characters, nine code points in NFD.
    expect(passwordTooShort('caféé12'.normalize('NFD'))).toBe(true)
  })
})
