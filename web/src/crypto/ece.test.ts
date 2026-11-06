import { describe, expect, it } from 'vitest'
import {
  RECORD_SIZE,
  decryptStream,
  encryptStream,
  encryptedSize,
  recordNonce,
} from './ece.ts'
import { collect, randomBytes, streamOf, toHex } from './testutil.ts'

const PAYLOAD = RECORD_SIZE - 17
const HEADER = 21
const ikm = randomBytes(32)

async function encrypt(plaintext: Uint8Array, chunkSize?: number) {
  return collect(encryptStream(streamOf(plaintext, chunkSize), ikm))
}

async function decrypt(ciphertext: Uint8Array, chunkSize?: number, key = ikm) {
  return collect(decryptStream(streamOf(ciphertext, chunkSize), key))
}

function corrupted(bytes: Uint8Array, index: number): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes)
  copy[index] ^= 0x01
  return copy
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

describe('round trip', () => {
  const sizes = [
    0,
    1,
    17,
    PAYLOAD - 1,
    PAYLOAD,
    PAYLOAD + 1,
    RECORD_SIZE,
    3 * PAYLOAD,
    3 * PAYLOAD + 1,
    1_000_003,
  ]

  it.each(sizes)('%i bytes', async (size) => {
    const plaintext = randomBytes(size)
    const ciphertext = await encrypt(plaintext, 10_007)
    expect(ciphertext).toHaveLength(encryptedSize(size))
    expect(await decrypt(ciphertext, 65_536)).toEqual(plaintext)
  })

  it('does not depend on how the input is chunked', async () => {
    const plaintext = randomBytes(2 * PAYLOAD + 123)
    const reference = await encrypt(plaintext)
    for (const chunkSize of [1, 7, 1000, PAYLOAD, 100_000]) {
      const ciphertext = await encrypt(plaintext, chunkSize)
      expect(ciphertext).toHaveLength(reference.length)
      expect(await decrypt(ciphertext, chunkSize)).toEqual(plaintext)
    }
  })

  it('uses a fresh salt per stream, so equal files never share keys or nonces', async () => {
    const plaintext = randomBytes(100)
    const a = await encrypt(plaintext)
    const b = await encrypt(plaintext)
    expect(toHex(a.subarray(0, 16))).not.toBe(toHex(b.subarray(0, 16)))
    expect(toHex(a.subarray(HEADER))).not.toBe(toHex(b.subarray(HEADER)))
  })

  it('fails with another key', async () => {
    const ciphertext = await encrypt(randomBytes(10))
    await expect(
      decrypt(ciphertext, undefined, randomBytes(32)),
    ).rejects.toThrow('authentication failed')
  })
})

describe('tampering', () => {
  it('any flipped byte is detected', async () => {
    const ciphertext = await encrypt(randomBytes(PAYLOAD + 5))
    const positions = [
      ...Array.from({ length: HEADER }, (_, i) => i),
      HEADER,
      HEADER + 1000,
      HEADER + RECORD_SIZE - 17,
      HEADER + RECORD_SIZE - 1,
      HEADER + RECORD_SIZE,
      ciphertext.length - 17,
      ciphertext.length - 1,
    ]
    for (const index of positions) {
      await expect(
        decrypt(corrupted(ciphertext, index)),
        `byte ${index}`,
      ).rejects.toThrow()
    }
  })
})

describe('truncation', () => {
  it('rejects an empty stream and a cut header', async () => {
    await expect(decrypt(new Uint8Array(0))).rejects.toThrow('truncated header')
    await expect(decrypt(randomBytes(HEADER - 1))).rejects.toThrow(
      'truncated header',
    )
  })

  it('rejects a stream that stops after the header', async () => {
    const ciphertext = await encrypt(randomBytes(10))
    await expect(decrypt(ciphertext.subarray(0, HEADER))).rejects.toThrow(
      'no records',
    )
  })

  it('rejects a cut inside a record', async () => {
    const ciphertext = await encrypt(randomBytes(PAYLOAD + 5))
    await expect(
      decrypt(ciphertext.subarray(0, ciphertext.length - 1)),
    ).rejects.toThrow()
    await expect(decrypt(ciphertext.subarray(0, HEADER + 10))).rejects.toThrow()
  })

  it('rejects a cut at a record boundary', async () => {
    const ciphertext = await encrypt(randomBytes(2 * PAYLOAD + 5))
    const firstRecordOnly = ciphertext.subarray(0, HEADER + RECORD_SIZE)
    await expect(decrypt(firstRecordOnly)).rejects.toThrow('delimiter')
    const twoRecords = ciphertext.subarray(0, HEADER + 2 * RECORD_SIZE)
    await expect(decrypt(twoRecords)).rejects.toThrow('delimiter')
  })
})

describe('record order', () => {
  async function records() {
    const plaintext = randomBytes(2 * PAYLOAD + 5)
    const ciphertext = await encrypt(plaintext)
    const header = ciphertext.subarray(0, HEADER)
    const r0 = ciphertext.subarray(HEADER, HEADER + RECORD_SIZE)
    const r1 = ciphertext.subarray(
      HEADER + RECORD_SIZE,
      HEADER + 2 * RECORD_SIZE,
    )
    const r2 = ciphertext.subarray(HEADER + 2 * RECORD_SIZE)
    return { plaintext, header, r0, r1, r2 }
  }

  it('accepts the original order', async () => {
    const { plaintext, header, r0, r1, r2 } = await records()
    expect(await decrypt(concat(header, r0, r1, r2))).toEqual(plaintext)
  })

  it('rejects swapped, dropped, duplicated and appended records', async () => {
    const { header, r0, r1, r2 } = await records()
    for (const variant of [
      concat(header, r1, r0, r2),
      concat(header, r0, r2),
      concat(header, r0, r0, r1, r2),
      concat(header, r0, r1, r2, r2),
      concat(header, r0, r1, r2, r0),
    ]) {
      await expect(decrypt(variant)).rejects.toThrow()
    }
  })
})

describe('record nonce', () => {
  const base = randomBytes(12)

  it('differs for every sequence number', () => {
    const seen = new Set<string>()
    for (let seq = 0; seq < 5000; seq++) seen.add(toHex(recordNonce(base, seq)))
    seen.add(toHex(recordNonce(base, 0xffffffff)))
    expect(seen.size).toBe(5001)
  })

  it('xors the sequence number into the last four bytes only', () => {
    const nonce = recordNonce(base, 0x01020304)
    expect(toHex(nonce.subarray(0, 8))).toBe(toHex(base.subarray(0, 8)))
    expect(nonce[8]).toBe(base[8]! ^ 0x01)
    expect(nonce[11]).toBe(base[11]! ^ 0x04)
    expect(toHex(recordNonce(base, 0))).toBe(toHex(base))
  })

  it('refuses sequence numbers beyond 2^32 - 1', () => {
    expect(() => recordNonce(base, 0x100000000)).toThrow('out of range')
    expect(() => recordNonce(base, -1)).toThrow('out of range')
    expect(() => recordNonce(base, 1.5)).toThrow('out of range')
  })
})

describe('encryptedSize', () => {
  it('counts header, full records and the final record', () => {
    expect(encryptedSize(0)).toBe(HEADER + 17)
    expect(encryptedSize(1)).toBe(HEADER + 18)
    expect(encryptedSize(PAYLOAD)).toBe(HEADER + RECORD_SIZE)
    expect(encryptedSize(PAYLOAD + 1)).toBe(HEADER + RECORD_SIZE + 18)
    const gib = 1 << 30
    expect(encryptedSize(gib)).toBe(
      HEADER + gib + 17 * Math.ceil(gib / PAYLOAD),
    )
  })
})
