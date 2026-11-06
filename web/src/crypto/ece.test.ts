import { describe, expect, it } from 'vitest'
import {
  RECORD_SIZE,
  decryptStream,
  encryptStream,
  encryptedSize,
  recordNonce,
} from './ece.ts'
import { hkdf } from './keys.ts'
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

describe('zero bytes', () => {
  it('survive at the end of a record', async () => {
    const boundary = new Uint8Array(PAYLOAD + 10)
    boundary.set(randomBytes(PAYLOAD - 5))
    for (const plaintext of [
      new Uint8Array([1, 2, 3, 0, 0, 0]),
      new Uint8Array(PAYLOAD),
      new Uint8Array(PAYLOAD + 1),
      boundary,
    ]) {
      expect(await decrypt(await encrypt(plaintext))).toEqual(plaintext)
    }
  })
})

describe('delimiter rules (RFC 8188 section 2)', () => {
  // Builds a stream record by record from explicitly padded plaintexts, so
  // the decrypter's rules are exercised without the encrypter.
  async function build(records: Uint8Array<ArrayBuffer>[]) {
    const salt = randomBytes(16)
    const encoder = new TextEncoder()
    const [cek, nonceBase] = await Promise.all([
      hkdf(ikm, salt, encoder.encode('Content-Encoding: aes256gcm\0'), 32),
      hkdf(ikm, salt, encoder.encode('Content-Encoding: nonce\0'), 12),
    ])
    const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, [
      'encrypt',
    ])
    const header = new Uint8Array(HEADER)
    header.set(salt)
    new DataView(header.buffer).setUint32(16, RECORD_SIZE)
    const sealed = await Promise.all(
      records.map(async (plain, seq) => {
        const iv = recordNonce(nonceBase, seq)
        return new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain),
        )
      }),
    )
    return concat(header, ...sealed)
  }

  function padded(data: Uint8Array, delimiter: number, full = true) {
    const out = new Uint8Array(full ? RECORD_SIZE - 16 : data.length + 1)
    out.set(data)
    out[data.length] = delimiter
    return out
  }

  const first = randomBytes(10)
  const last = randomBytes(5)

  it('accepts zero padding after the delimiter of a non-last record', async () => {
    const stream = await build([padded(first, 1), padded(last, 2, false)])
    expect(await decrypt(stream)).toEqual(concat(first, last))
  })

  it('rejects a non-last record that ends like a last record', async () => {
    const stream = await build([padded(first, 2), padded(last, 2, false)])
    await expect(decrypt(stream)).rejects.toThrow('delimiter')
  })

  it('rejects a record without any delimiter', async () => {
    const stream = await build([
      new Uint8Array(RECORD_SIZE - 16),
      padded(last, 2, false),
    ])
    await expect(decrypt(stream)).rejects.toThrow('no delimiter')
  })

  it('rejects an unknown delimiter and a last record marked as non-last', async () => {
    await expect(
      decrypt(await build([padded(last, 3, false)])),
    ).rejects.toThrow('delimiter')
    await expect(
      decrypt(await build([padded(last, 1, false)])),
    ).rejects.toThrow('delimiter')
  })
})

describe('parameters', () => {
  it('refuse record sizes below the RFC minimum and short keys', () => {
    const input = () => streamOf(randomBytes(5))
    expect(() => encryptStream(input(), ikm, { rs: 17 })).toThrow('record size')
    expect(() => decryptStream(input(), ikm, { rs: 17 })).toThrow('record size')
    expect(() => encryptStream(input(), randomBytes(15))).toThrow(
      'key too short',
    )
    expect(() => decryptStream(input(), randomBytes(15))).toThrow(
      'key too short',
    )
  })
})

describe('stream behaviour', () => {
  it('propagates a source error to the consumer', async () => {
    const source = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('disk read failed'))
      },
    })
    await expect(collect(encryptStream(source, ikm))).rejects.toThrow(
      'disk read failed',
    )
  })

  it('propagates a consumer cancel back to the source', async () => {
    // The pipe cancels the source asynchronously, so wait for it (bounded).
    let sourceCancelled!: (reason: unknown) => void
    const cancelled = new Promise<unknown>((resolve) => {
      sourceCancelled = resolve
    })
    const source = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(randomBytes(1000))
      },
      cancel: sourceCancelled,
    })
    const reader = encryptStream(source, ikm).getReader()
    await reader.read()
    await reader.cancel('user left the page')
    const timeout = new Promise((resolve) =>
      setTimeout(resolve, 2000, 'timed out'),
    )
    expect(await Promise.race([cancelled, timeout])).toBe('user left the page')
  })
})
