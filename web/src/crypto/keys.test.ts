import { describe, expect, it } from 'vitest'
import {
  SECRET_LENGTH,
  deriveKeys,
  exportAuthKey,
  generateSecret,
  signChallenge,
} from './keys.ts'
import { randomBytes, toHex } from './testutil.ts'

describe('secret', () => {
  it('is 16 random bytes', () => {
    const a = generateSecret()
    const b = generateSecret()
    expect(a).toHaveLength(SECRET_LENGTH)
    expect(toHex(a)).not.toBe(toHex(b))
  })

  it('must be exactly 16 bytes', async () => {
    await expect(deriveKeys(randomBytes(15))).rejects.toThrow('16 bytes')
    await expect(deriveKeys(randomBytes(32))).rejects.toThrow('16 bytes')
  })
})

describe('derived keys', () => {
  it('are deterministic and distinct per secret', async () => {
    const secret = generateSecret()
    const a = await deriveKeys(secret)
    const b = await deriveKeys(secret)
    const other = await deriveKeys(generateSecret())
    expect(toHex(a.fileKey)).toBe(toHex(b.fileKey))
    expect(toHex(await exportAuthKey(a.authKey))).toBe(
      toHex(await exportAuthKey(b.authKey)),
    )
    expect(toHex(a.fileKey)).not.toBe(toHex(other.fileKey))
    expect(toHex(await exportAuthKey(a.authKey))).not.toBe(
      toHex(await exportAuthKey(other.authKey)),
    )
  })

  it('are 256 bits and independent of each other', async () => {
    const keys = await deriveKeys(generateSecret())
    const authKey = await exportAuthKey(keys.authKey)
    expect(keys.fileKey).toHaveLength(32)
    expect(authKey).toHaveLength(32)
    expect(toHex(keys.fileKey)).not.toBe(toHex(authKey))
    expect(keys.metaKey.algorithm).toEqual({ name: 'AES-GCM', length: 256 })
    expect(keys.metaKey.extractable).toBe(false)
  })

  it('sign challenges with HMAC-SHA-256 under the exported key', async () => {
    const keys = await deriveKeys(generateSecret())
    const challenge = randomBytes(32)
    const signature = await signChallenge(keys.authKey, challenge)
    const verifier = await crypto.subtle.importKey(
      'raw',
      await exportAuthKey(keys.authKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    )
    expect(signature).toHaveLength(32)
    expect(
      await crypto.subtle.verify('HMAC', verifier, signature, challenge),
    ).toBe(true)
    expect(
      await crypto.subtle.verify('HMAC', verifier, signature, randomBytes(32)),
    ).toBe(false)
  })
})
