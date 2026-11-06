import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  decryptStream,
  deriveKeys,
  encryptStream,
  encryptedSize,
  exportAuthKey,
  fromBase64Url,
  toBase64Url,
} from '../crypto/index.ts'
import { collect, randomBytes, streamOf } from '../crypto/testutil.ts'
import * as api from './api.ts'
import { parseLocation } from './link.ts'
import type { Sink } from './save.ts'
import { downloadShare, openShare, uploadFile } from './share.ts'

vi.mock('./api.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./api.ts')>()),
  createFile: vi.fn(),
  uploadContent: vi.fn(),
  getMeta: vi.fn(),
  requestDownload: vi.fn(),
  downloadContent: vi.fn(),
  deleteFile: vi.fn(),
}))

afterEach(() => vi.restoreAllMocks())

const encoder = new TextEncoder()

describe('uploadFile', () => {
  it('sends only ciphertext and verifiers, and builds the link from the fragment', async () => {
    const plaintext = randomBytes(70_000)
    const file = new File([plaintext], 'notes.txt', { type: 'text/plain' })
    vi.mocked(api.createFile).mockResolvedValue({
      id: 'AAAAAAAAAAAAAAAAAAAAAA',
      owner_token: 'owner',
      upload_url: '/x',
      expires_at: 1_800_000_000,
    })
    vi.mocked(api.uploadContent).mockResolvedValue()
    vi.stubGlobal('window', { location: { origin: 'https://share.example' } })

    const phases: string[] = []
    const share = await uploadFile(
      file,
      { expiresIn: 3600, maxDownloads: 2 },
      (p) => phases.push(p.phase),
    )

    const request = vi.mocked(api.createFile).mock.calls[0]![0]
    expect(request.size).toBe(encryptedSize(plaintext.length))
    expect(request.expires_in).toBe(3600)
    expect(request.max_downloads).toBe(2)
    expect(fromBase64Url(request.auth_key)).toHaveLength(32)
    expect(JSON.stringify(request)).not.toContain('notes.txt')

    const [id, blob, ownerToken] = vi.mocked(api.uploadContent).mock.calls[0]!
    expect(id).toBe('AAAAAAAAAAAAAAAAAAAAAA')
    expect(ownerToken).toBe('owner')
    expect(blob.size).toBe(encryptedSize(plaintext.length))
    expect(phases).toContain('encrypting')

    const location = parseLocation(
      new URL(share.link).pathname,
      new URL(share.link).hash,
    )
    expect(location?.id).toBe('AAAAAAAAAAAAAAAAAAAAAA')
    // The secret in the link decrypts what was uploaded.
    const keys = await deriveKeys(location!.secret)
    const ciphertext = new Uint8Array(await blob.arrayBuffer())
    expect(
      await collect(decryptStream(streamOf(ciphertext), keys.fileKey)),
    ).toEqual(plaintext)
    expect(toBase64Url(await exportAuthKey(keys.authKey))).toBe(
      request.auth_key,
    )
    vi.unstubAllGlobals()
  })
})

async function sharedFile() {
  const secret = randomBytes(16)
  const keys = await deriveKeys(secret)
  const plaintext = encoder.encode('hello vault')
  const ciphertext = await collect(
    encryptStream(streamOf(plaintext), keys.fileKey),
  )
  const { encryptMetadata } = await import('../crypto/index.ts')
  const meta = await encryptMetadata(keys.metaKey, {
    name: 'hello.txt',
    type: 'text/plain',
    size: plaintext.length,
  })
  vi.mocked(api.getMeta).mockResolvedValue({
    meta: toBase64Url(meta),
    size: ciphertext.length,
    downloads_left: 2,
    expires_at: 1_800_000_000,
    challenge: toBase64Url(randomBytes(32)),
  })
  return { secret, plaintext, ciphertext }
}

function memorySink() {
  const chunks: Uint8Array[] = []
  const sink: Sink & { discarded: boolean } = {
    kind: 'download',
    discarded: false,
    async consume(stream) {
      const reader = stream.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
      }
    },
    async discard() {
      sink.discarded = true
    },
  }
  return { sink, chunks }
}

describe('downloadShare', () => {
  it('signs the challenge, spends one download and decrypts the stream', async () => {
    const { secret, plaintext, ciphertext } = await sharedFile()
    vi.mocked(api.requestDownload).mockResolvedValue({
      token: 'tok',
      downloads_left: 1,
    })
    vi.mocked(api.downloadContent).mockResolvedValue(streamOf(ciphertext, 7))

    const info = await openShare('AAAAAAAAAAAAAAAAAAAAAA', secret)
    expect(info.name).toBe('hello.txt')
    expect(info.ciphertextSize).toBe(ciphertext.length)

    const { sink, chunks } = memorySink()
    const granted: number[] = []
    let last = 0
    await downloadShare(
      info,
      sink,
      (p) => (last = p.fraction),
      (left) => granted.push(left),
    )
    expect(granted).toEqual([1])
    expect(last).toBe(1)
    const received = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
    chunks.reduce(
      (offset, c) => (received.set(c, offset), offset + c.length),
      0,
    )
    expect(received).toEqual(plaintext)
    const [, challenge, signature] = vi.mocked(api.requestDownload).mock
      .calls[0]!
    expect(fromBase64Url(signature)).toHaveLength(32)
    expect(challenge).toBe(
      vi.mocked(api.getMeta).mock.results.at(-1)!.value.challenge ?? challenge,
    )
  })

  it('discards the sink when no download was granted', async () => {
    const { secret } = await sharedFile()
    vi.mocked(api.requestDownload).mockRejectedValue(
      new api.ApiError(404, 'not_found'),
    )
    const info = await openShare('AAAAAAAAAAAAAAAAAAAAAA', secret)
    const { sink, chunks } = memorySink()
    await expect(downloadShare(info, sink, () => {})).rejects.toMatchObject({
      status: 404,
    })
    expect(sink.discarded).toBe(true)
    expect(chunks).toHaveLength(0)
  })

  it('fails on tampered ciphertext without handing over the partial file', async () => {
    const { secret, ciphertext } = await sharedFile()
    const bad = new Uint8Array(ciphertext)
    bad[bad.length - 1] ^= 1
    vi.mocked(api.requestDownload).mockResolvedValue({
      token: 'tok',
      downloads_left: 0,
    })
    vi.mocked(api.downloadContent).mockResolvedValue(streamOf(bad))
    const info = await openShare('AAAAAAAAAAAAAAAAAAAAAA', secret)
    const { sink } = memorySink()
    await expect(downloadShare(info, sink, () => {})).rejects.toThrow(
      'authentication failed',
    )
  })
})
