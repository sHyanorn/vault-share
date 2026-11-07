import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  deriveKeys,
  encryptMetadata,
  fromBase64Url,
  generateSecret,
  importAccountKey,
  newAccountKey,
  openEntry,
  sealEntry,
  toBase64Url,
  wrapSecret,
} from '../crypto/index.ts'
import { randomBytes } from '../crypto/testutil.ts'
import * as shareApi from '../share/api.ts'
import { uploadFile } from '../share/share.ts'
import type { Account } from './account.ts'
import * as api from './api.ts'
import { listKept } from './files.ts'

vi.mock('./api.ts', () => ({ listFiles: vi.fn(), keepFile: vi.fn() }))
vi.mock('../share/api.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../share/api.ts')>()),
  createFile: vi.fn(),
  uploadContent: vi.fn(),
}))

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

async function newAccount(): Promise<Account> {
  const raw = newAccountKey()
  return {
    username: 'alice',
    totp: false,
    key: await importAccountKey(raw),
    raw,
  }
}

const owner = toBase64Url(randomBytes(32))

async function keptFile(
  account: Account,
  id: string,
  name: string,
  linkKey?: (
    secret: Uint8Array<ArrayBuffer>,
  ) => Promise<Uint8Array<ArrayBuffer>>,
): Promise<api.KeptFileResponse> {
  const secret = generateSecret()
  const keys = await deriveKeys(secret)
  const entry = await sealEntry(account.key, id, {
    secret,
    linkKey: linkKey ? await linkKey(secret) : secret,
    ownerToken: owner,
  })
  return {
    id,
    size: 100,
    meta: toBase64Url(
      await encryptMetadata(keys.metaKey, {
        name,
        type: 'text/plain',
        size: 42,
      }),
    ),
    entry: toBase64Url(entry),
    downloads_left: 2,
    expires_at: 1_800_000_000,
    created_at: 1_799_990_000,
    uploaded: true,
  }
}

describe('listKept', () => {
  it('opens names and links, and marks what does not open', async () => {
    const account = await newAccount()
    const plain = await keptFile(account, 'A'.repeat(22), 'notes.txt')
    const locked = await keptFile(account, 'B'.repeat(22), 'keys.txt', (s) =>
      wrapSecret(s, 'a share password'),
    )
    // An entry moved from another file does not open there.
    const moved = {
      ...(await keptFile(account, 'C'.repeat(22), 'moved.txt')),
      id: 'D'.repeat(22),
    }
    const foreign = await keptFile(
      await newAccount(),
      'E'.repeat(22),
      'theirs.txt',
    )
    vi.mocked(api.listFiles).mockResolvedValue({
      files: [plain, locked, moved, foreign],
      more: false,
    })

    const { files } = await listKept(account, 'https://share.example')
    const [first, second, third, fourth] = files
    if (first?.unreadable || second?.unreadable) throw new Error('unreadable')
    expect(first).toMatchObject({
      name: 'notes.txt',
      size: 42,
      protected: false,
      ownerToken: owner,
      downloadsLeft: 2,
      uploaded: true,
    })
    expect(first.link).toMatch(
      /^https:\/\/share\.example\/f\/A{22}#[A-Za-z0-9_-]{22}$/,
    )
    expect(second).toMatchObject({ name: 'keys.txt', protected: true })
    expect(second.link).toMatch(/#[A-Za-z0-9_-]{80}$/)
    expect(third).toMatchObject({ id: 'D'.repeat(22), unreadable: true })
    expect(fourth).toMatchObject({ unreadable: true })
  }, 30_000)
})

describe('uploadFile with an account', () => {
  function created() {
    vi.mocked(shareApi.createFile).mockResolvedValue({
      id: 'F'.repeat(22),
      owner_token: owner,
      upload_url: '/x',
      expires_at: 1_800_000_000,
    })
    vi.mocked(shareApi.uploadContent).mockResolvedValue()
    vi.stubGlobal('window', { location: { origin: 'https://share.example' } })
  }

  it('keeps an entry bound to the file before the content goes up', async () => {
    created()
    const account = await newAccount()
    vi.mocked(api.keepFile).mockResolvedValue()
    const file = new File([randomBytes(1000)], 'report.pdf')
    const share = await uploadFile(
      file,
      { expiresIn: 3600, maxDownloads: 1, account },
      () => {},
    )
    expect(share.kept).toBe(true)
    const [id, token, sealed] = vi.mocked(api.keepFile).mock.calls[0]!
    expect(id).toBe('F'.repeat(22))
    expect(token).toBe(owner)
    const entry = await openEntry(account.key, id, fromBase64Url(sealed))
    expect(entry.ownerToken).toBe(owner)
    expect(share.link.endsWith('#' + toBase64Url(entry.linkKey))).toBe(true)
    expect(vi.mocked(api.keepFile).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(shareApi.uploadContent).mock.invocationCallOrder[0]!,
    )
  })

  it('still shares the file when keeping it fails, and keeps nothing without an account', async () => {
    created()
    vi.mocked(api.keepFile).mockRejectedValue(
      new shareApi.ApiError(500, 'internal'),
    )
    const file = new File([randomBytes(10)], 'a.txt')
    const share = await uploadFile(
      file,
      { expiresIn: 3600, maxDownloads: 1, account: await newAccount() },
      () => {},
    )
    expect(share.kept).toBe(false)
    expect(share.link).toContain('/f/')

    vi.mocked(api.keepFile).mockClear()
    const anonymous = await uploadFile(
      file,
      { expiresIn: 3600, maxDownloads: 1 },
      () => {},
    )
    expect(anonymous.kept).toBeUndefined()
    expect(api.keepFile).not.toHaveBeenCalled()
  })
})
