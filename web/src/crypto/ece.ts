// Chunked AES-GCM in the record format of RFC 8188 (aes128gcm), used with a
// 256-bit key: header = salt(16) | rs(4) | idlen(1) = 0, then records of rs
// bytes. The content key and the nonce base come from HKDF over the file key
// and the salt; record i uses nonce base XOR i. Each record ends in a
// delimiter byte, 1 for every record but the last and 2 for the last, so a
// truncated, reordered or extended stream fails to decrypt.

import { hkdf } from './keys.ts'

export const RECORD_SIZE = 65536
const KEY_LENGTH = 32
const MIN_KEY_LENGTH = 16
const MIN_RECORD_SIZE = 18 // RFC 8188 section 2.1
const TAG_LENGTH = 16
const NONCE_LENGTH = 12
const SALT_LENGTH = 16
const HEADER_LENGTH = SALT_LENGTH + 4 + 1
const MAX_SEQ = 0xffffffff
const encoder = new TextEncoder()

export interface EceOptions {
  /** Record size in bytes. Fixed for vault-share; tests use the RFC value. */
  rs?: number
  /** AES key length in bytes: 32 for vault-share, 16 only for RFC 8188 vectors. */
  keyLength?: 16 | 32
  /** Header salt, random unless a test supplies one. */
  salt?: Uint8Array<ArrayBuffer>
}

/** Ciphertext size for a plaintext of the given size. */
export function encryptedSize(
  plaintextBytes: number,
  rs = RECORD_SIZE,
): number {
  const payload = rs - TAG_LENGTH - 1
  const records = Math.max(1, Math.ceil(plaintextBytes / payload))
  const lastPayload = plaintextBytes - (records - 1) * payload
  return HEADER_LENGTH + (records - 1) * rs + lastPayload + 1 + TAG_LENGTH
}

export function encryptStream(
  input: ReadableStream<Uint8Array>,
  ikm: Uint8Array<ArrayBuffer>,
  options: EceOptions = {},
): ReadableStream<Uint8Array<ArrayBuffer>> {
  const rs = options.rs ?? RECORD_SIZE
  checkParameters(ikm, rs)
  const salt =
    options.salt ?? crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const payload = rs - TAG_LENGTH - 1
  return input
    .pipeThrough(new TransformStream(new Slicer(payload, payload)))
    .pipeThrough(
      new TransformStream(
        new Encrypter(ikm, options.keyLength ?? KEY_LENGTH, rs, salt),
      ),
    )
}

export function decryptStream(
  input: ReadableStream<Uint8Array>,
  ikm: Uint8Array<ArrayBuffer>,
  options: EceOptions = {},
): ReadableStream<Uint8Array<ArrayBuffer>> {
  const rs = options.rs ?? RECORD_SIZE
  checkParameters(ikm, rs)
  return input
    .pipeThrough(new TransformStream(new Slicer(HEADER_LENGTH, rs)))
    .pipeThrough(
      new TransformStream(
        new Decrypter(ikm, options.keyLength ?? KEY_LENGTH, rs),
      ),
    )
}

/** Nonce of record `seq`: the HKDF nonce base XOR the sequence number. */
export function recordNonce(
  base: Uint8Array<ArrayBuffer>,
  seq: number,
): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(seq) || seq < 0 || seq > MAX_SEQ) {
    throw new Error('record sequence number out of range')
  }
  const nonce = new Uint8Array(base)
  const view = new DataView(nonce.buffer)
  view.setUint32(
    NONCE_LENGTH - 4,
    (view.getUint32(NONCE_LENGTH - 4) ^ seq) >>> 0,
  )
  return nonce
}

function checkParameters(ikm: Uint8Array, rs: number) {
  if (ikm.length < MIN_KEY_LENGTH) throw new Error('key too short')
  if (!Number.isInteger(rs) || rs < MIN_RECORD_SIZE)
    throw new Error('record size too small')
}

interface RecordKeys {
  key: CryptoKey
  nonceBase: Uint8Array<ArrayBuffer>
}

async function deriveRecordKeys(
  ikm: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  keyLength: number,
): Promise<RecordKeys> {
  const [cek, nonceBase] = await Promise.all([
    hkdf(
      ikm,
      salt,
      encoder.encode(`Content-Encoding: aes${keyLength * 8}gcm\0`),
      keyLength,
    ),
    hkdf(ikm, salt, encoder.encode('Content-Encoding: nonce\0'), NONCE_LENGTH),
  ])
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
  return { key, nonceBase }
}

function createHeader(
  salt: Uint8Array<ArrayBuffer>,
  rs: number,
): Uint8Array<ArrayBuffer> {
  const header = new Uint8Array(HEADER_LENGTH)
  header.set(salt)
  new DataView(header.buffer).setUint32(SALT_LENGTH, rs)
  return header
}

function parseHeader(chunk: Uint8Array, rs: number): Uint8Array<ArrayBuffer> {
  if (chunk.length !== HEADER_LENGTH) throw new Error('truncated header')
  const view = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength)
  if (view.getUint32(SALT_LENGTH) !== rs || chunk[SALT_LENGTH + 4] !== 0) {
    throw new Error('unsupported header')
  }
  return chunk.slice(0, SALT_LENGTH)
}

function pad(
  data: Uint8Array,
  isLast: boolean,
  rs: number,
): Uint8Array<ArrayBuffer> {
  if (data.length > rs - TAG_LENGTH - 1) throw new Error('record too large')
  const out = new Uint8Array(isLast ? data.length + 1 : rs - TAG_LENGTH)
  out.set(data)
  out[data.length] = isLast ? 2 : 1
  return out
}

function unpad(
  data: Uint8Array<ArrayBuffer>,
  isLast: boolean,
): Uint8Array<ArrayBuffer> {
  let i = data.length - 1
  while (i >= 0 && data[i] === 0) i--
  if (i < 0) throw new Error('record has no delimiter')
  if (data[i] !== (isLast ? 2 : 1))
    throw new Error('record delimiter does not match position')
  return data.subarray(0, i)
}

/** Re-chunks a byte stream into fixed sizes: `first` bytes, then `rest` bytes each. */
class Slicer implements Transformer<Uint8Array, Uint8Array<ArrayBuffer>> {
  private readonly rest: number
  private size: number
  private buffer: Uint8Array<ArrayBuffer>
  private offset = 0

  constructor(first: number, rest: number) {
    this.rest = rest
    this.size = first
    this.buffer = new Uint8Array(first)
  }

  transform(
    chunk: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    let i = 0
    while (i < chunk.length) {
      const take = Math.min(this.size - this.offset, chunk.length - i)
      this.buffer.set(chunk.subarray(i, i + take), this.offset)
      this.offset += take
      i += take
      if (this.offset === this.size) {
        controller.enqueue(this.buffer)
        this.size = this.rest
        this.buffer = new Uint8Array(this.size)
        this.offset = 0
      }
    }
  }

  flush(controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>) {
    if (this.offset > 0)
      controller.enqueue(this.buffer.subarray(0, this.offset))
  }
}

/**
 * Holds one record back so the last one can be marked as such when the
 * input ends. Every stream, even an empty one, ends with a last record.
 */
class Encrypter implements Transformer<
  Uint8Array<ArrayBuffer>,
  Uint8Array<ArrayBuffer>
> {
  private readonly ikm: Uint8Array<ArrayBuffer>
  private readonly keyLength: number
  private readonly rs: number
  private readonly salt: Uint8Array<ArrayBuffer>
  private derived!: RecordKeys // set by start, which the stream runs before transform
  private seq = 0
  private pending: Uint8Array<ArrayBuffer> | null = null

  constructor(
    ikm: Uint8Array<ArrayBuffer>,
    keyLength: number,
    rs: number,
    salt: Uint8Array<ArrayBuffer>,
  ) {
    this.ikm = ikm
    this.keyLength = keyLength
    this.rs = rs
    this.salt = salt
  }

  async start(
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    this.derived = await deriveRecordKeys(this.ikm, this.salt, this.keyLength)
    controller.enqueue(createHeader(this.salt, this.rs))
  }

  async transform(
    chunk: Uint8Array<ArrayBuffer>,
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    if (this.pending)
      controller.enqueue(await this.encryptRecord(this.pending, false))
    this.pending = chunk
  }

  async flush(
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    controller.enqueue(
      await this.encryptRecord(this.pending ?? new Uint8Array(0), true),
    )
  }

  private async encryptRecord(data: Uint8Array<ArrayBuffer>, isLast: boolean) {
    const { key, nonceBase } = this.derived
    const iv = recordNonce(nonceBase, this.seq++)
    const params = { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 }
    return new Uint8Array(
      await crypto.subtle.encrypt(params, key, pad(data, isLast, this.rs)),
    )
  }
}

class Decrypter implements Transformer<
  Uint8Array<ArrayBuffer>,
  Uint8Array<ArrayBuffer>
> {
  private readonly ikm: Uint8Array<ArrayBuffer>
  private readonly keyLength: number
  private readonly rs: number
  private derived: RecordKeys | null = null
  private seq = 0
  private pending: Uint8Array<ArrayBuffer> | null = null

  constructor(ikm: Uint8Array<ArrayBuffer>, keyLength: number, rs: number) {
    this.ikm = ikm
    this.keyLength = keyLength
    this.rs = rs
  }

  async transform(
    chunk: Uint8Array<ArrayBuffer>,
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    if (!this.derived) {
      const salt = parseHeader(chunk, this.rs)
      this.derived = await deriveRecordKeys(this.ikm, salt, this.keyLength)
      return
    }
    if (this.pending)
      controller.enqueue(
        await this.decryptRecord(this.derived, this.pending, false),
      )
    this.pending = chunk
  }

  async flush(
    controller: TransformStreamDefaultController<Uint8Array<ArrayBuffer>>,
  ) {
    if (!this.derived) throw new Error('truncated header')
    if (!this.pending) throw new Error('no records')
    controller.enqueue(
      await this.decryptRecord(this.derived, this.pending, true),
    )
  }

  private async decryptRecord(
    { key, nonceBase }: RecordKeys,
    data: Uint8Array<ArrayBuffer>,
    isLast: boolean,
  ) {
    if (data.length < TAG_LENGTH + 1) throw new Error('truncated record')
    const iv = recordNonce(nonceBase, this.seq++)
    const params = { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 }
    let plain: ArrayBuffer
    try {
      plain = await crypto.subtle.decrypt(params, key, data)
    } catch {
      throw new Error('record authentication failed')
    }
    return unpad(new Uint8Array(plain), isLast)
  }
}
