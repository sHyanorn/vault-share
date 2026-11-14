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

/** iv | AES-GCM(plain), built by hand so a test can choose the plaintext. */
async function seal(key: CryptoKey, plain: Uint8Array<ArrayBuffer>) {
  const iv = randomBytes(12)
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain),
  )
  const out = new Uint8Array(12 + cipher.length)
  out.set(iv)
  out.set(cipher, 12)
  return out
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

  it('pads the plaintext, so the length shows nothing of a shorter name', async () => {
    const key = await metaKey()
    const length = async (name: string) =>
      (await encryptMetadata(key, { ...meta, name })).length
    const short = await length('a.pdf')
    expect(short).toBe(12 + 1024 + 16)
    expect(await length('salary-review-2026-final.pdf')).toBe(short)
    expect(await length('名'.repeat(255))).toBe(short)
    // A longer name takes the next KiB, and no blob passes the server's
    // limit of 4096 bytes.
    expect(await length('x'.repeat(1100))).toBe(12 + 2048 + 16)
    expect(await length('x'.repeat(4000))).toBe(4096)
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
    const encrypt = (value: unknown) =>
      seal(key, new TextEncoder().encode(JSON.stringify(value)))
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
    const blob = await seal(
      key,
      new TextEncoder().encode('Q3 payroll (confidential).xlsx'),
    )
    const error = await decryptMetadata(key, blob).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe('malformed metadata')
  })
})
