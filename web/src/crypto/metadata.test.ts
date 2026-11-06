import { describe, expect, it } from 'vitest'
import { deriveKeys, generateSecret } from './keys.ts'
import { decryptMetadata, encryptMetadata } from './metadata.ts'
import { randomBytes, toHex } from './testutil.ts'

const meta = {
  name: 'report (final).pdf',
  type: 'application/pdf',
  size: 1234567,
}

async function metaKey() {
  return (await deriveKeys(generateSecret())).metaKey
}

describe('metadata', () => {
  it('round-trips', async () => {
    const key = await metaKey()
    expect(
      await decryptMetadata(key, await encryptMetadata(key, meta)),
    ).toEqual(meta)
  })

  it('uses a fresh IV every time', async () => {
    const key = await metaKey()
    const a = await encryptMetadata(key, meta)
    const b = await encryptMetadata(key, meta)
    expect(toHex(a.subarray(0, 12))).not.toBe(toHex(b.subarray(0, 12)))
    expect(toHex(a)).not.toBe(toHex(b))
  })

  it('rejects tampering, another key and truncation', async () => {
    const key = await metaKey()
    const blob = await encryptMetadata(key, meta)
    for (const index of [0, 12, blob.length - 1]) {
      const bad = new Uint8Array(blob)
      bad[index] ^= 0x80
      await expect(decryptMetadata(key, bad)).rejects.toThrow(
        'authentication failed',
      )
    }
    await expect(decryptMetadata(await metaKey(), blob)).rejects.toThrow(
      'authentication failed',
    )
    await expect(decryptMetadata(key, blob.subarray(0, 27))).rejects.toThrow(
      'truncated',
    )
    await expect(decryptMetadata(key, randomBytes(40))).rejects.toThrow(
      'authentication failed',
    )
  })

  it('keeps only name, type and size and validates their shape', async () => {
    const key = await metaKey()
    const encrypt = async (value: unknown) => {
      const iv = randomBytes(12)
      const plain = new TextEncoder().encode(JSON.stringify(value))
      const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plain,
      )
      const out = new Uint8Array(12 + cipher.byteLength)
      out.set(iv)
      out.set(new Uint8Array(cipher), 12)
      return out
    }
    expect(
      await decryptMetadata(key, await encrypt({ ...meta, extra: 1 })),
    ).toEqual(meta)
    for (const bad of [
      null,
      'x',
      { name: 'a', type: 'b' },
      { name: 'a', type: 'b', size: -1 },
      { name: 1, type: 'b', size: 0 },
    ]) {
      await expect(decryptMetadata(key, await encrypt(bad))).rejects.toThrow(
        'malformed metadata',
      )
    }
  })
})

describe('errors', () => {
  it('keep the plaintext out of the message when it is not JSON', async () => {
    const key = await metaKey()
    const iv = randomBytes(12)
    const plain = new TextEncoder().encode('Q3 payroll (confidential).xlsx')
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain),
    )
    const blob = new Uint8Array(12 + cipher.length)
    blob.set(iv)
    blob.set(cipher, 12)
    const error = await decryptMetadata(key, blob).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe('malformed metadata')
  })
})
