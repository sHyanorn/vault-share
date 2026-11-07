import { describe, expect, it } from 'vitest'
import {
  SEALED_KEY_LENGTH,
  accountPasswordTooShort,
  deriveAccountCredentials,
  importAccountKey,
  newAccountKey,
  newAccountSalt,
  openAccountKey,
  openEntry,
  openOnDevice,
  sealAccountKey,
  sealEntry,
  sealForDevice,
  type FileEntry,
} from './account.ts'
import { toBase64Url } from './encoding.ts'
import { wrapSecret } from './password.ts'
import { fromHex, randomBytes, toHex } from './testutil.ts'

const password = 'correct horse battery staple'
const seq = (start: number, n: number) =>
  Uint8Array.from({ length: n }, (_, i) => start + i)

// Computed once with hash-wasm and WebCrypto, and again with Go's
// golang.org/x/crypto/argon2, crypto/hkdf and crypto/cipher. A change to the
// derivation or the labels would lock every account out, so they are pinned.
const vector = {
  salt: seq(0, 16),
  auth: '0e801f3590877f251781d16e4df623303f60e9d581a1995c4527d6aaf9d8d23e',
  accountKey: seq(0x20, 32),
  sealedKey:
    'a0a1a2a3a4a5a6a7a8a9aaab123a1f310d2df9e18f2794d7c130b1b9d726eb399c31a39f' +
    '7d14735a5b6d63df2d094f48b1933fa0a51178783b218387',
  fileId: 'AAAAAAAAAAAAAAAAAAAAAA',
  sealedEntry:
    'b0b1b2b3b4b5b6b7b8b9babb4dd85922f151ad7a10373fbb4278de77e162e4d9ed2bdd72' +
    'b12be31c9417429b63ef7dd6be986f04fb465a4c99e2dd5786bfa418484449493750219061' +
    'f41b1f30f582a23bbaa00439a9a24f00175cc934e44d7917fc2d39906789f1e999157c0e90' +
    'd02b32acd20a41ad731cb7970e413afc845254a9f1899be5542997b279098ca393b9a8c65ed4',
}

function entryFor(secret = randomBytes(16)): FileEntry {
  return {
    secret,
    linkKey: secret,
    ownerToken: toBase64Url(randomBytes(32)),
  }
}

describe('account credentials', () => {
  it('match the pinned vector', async () => {
    const { authSecret, wrappingKey } = await deriveAccountCredentials(
      password,
      vector.salt,
    )
    expect(toHex(authSecret)).toBe(vector.auth)
    expect(
      await openAccountKey(wrappingKey, fromHex(vector.sealedKey)),
    ).toEqual(vector.accountKey)
    // The wrapping key stays in the browser, even for code on the page.
    expect(wrappingKey.extractable).toBe(false)
  }, 30_000)

  it('depend on the salt and normalize the password', async () => {
    const salt = newAccountSalt()
    const a = await deriveAccountCredentials('café au lait, extra hot', salt)
    const b = await deriveAccountCredentials('café au lait, extra hot', salt)
    const c = await deriveAccountCredentials(
      'café au lait, extra hot',
      newAccountSalt(),
    )
    expect(toHex(a.authSecret)).toBe(toHex(b.authSecret))
    expect(toHex(a.authSecret)).not.toBe(toHex(c.authSecret))
    await expect(
      deriveAccountCredentials(password, new Uint8Array(15)),
    ).rejects.toThrow('salt')
  }, 30_000)

  it('need 15 code points after normalization', () => {
    expect(accountPasswordTooShort('a'.repeat(14))).toBe(true)
    expect(accountPasswordTooShort('a'.repeat(15))).toBe(false)
    // Fourteen ligatures normalize to twenty-eight letters.
    expect(accountPasswordTooShort('ﬁ'.repeat(14))).toBe(false)
    expect(accountPasswordTooShort('\u{1f512}'.repeat(14))).toBe(true)
  })
})

describe('account key', () => {
  it('opens only with the password that sealed it', async () => {
    const salt = newAccountSalt()
    const right = await deriveAccountCredentials(password, salt)
    const wrong = await deriveAccountCredentials(password + '!', salt)
    const raw = newAccountKey()
    const sealed = await sealAccountKey(right.wrappingKey, raw)
    expect(sealed).toHaveLength(SEALED_KEY_LENGTH)
    expect(await openAccountKey(right.wrappingKey, sealed)).toEqual(raw)
    expect(await openAccountKey(wrong.wrappingKey, sealed)).toBeNull()
    for (const index of [0, 12, SEALED_KEY_LENGTH - 1]) {
      const bad = new Uint8Array(sealed)
      bad[index] ^= 1
      expect(
        await openAccountKey(right.wrappingKey, bad),
        `byte ${index}`,
      ).toBeNull()
    }
    await expect(
      openAccountKey(right.wrappingKey, sealed.subarray(1)),
    ).rejects.toThrow('length')
    // A fresh IV per seal, so the same key never seals to the same bytes.
    expect(toHex(await sealAccountKey(right.wrappingKey, raw))).not.toBe(
      toHex(sealed),
    )
  }, 30_000)

  it('opens on the device only with the device key it was sealed for', async () => {
    const raw = newAccountKey()
    const deviceKey = randomBytes(32)
    const sealed = await sealForDevice(deviceKey, raw)
    expect(await openOnDevice(deviceKey, sealed)).toEqual(raw)
    expect(await openOnDevice(randomBytes(32), sealed)).toBeNull()
    await expect(sealForDevice(randomBytes(16), raw)).rejects.toThrow(
      'device key',
    )
  })
})

describe('file entries', () => {
  it('match the pinned vector', async () => {
    const key = await importAccountKey(vector.accountKey)
    const entry = await openEntry(
      key,
      vector.fileId,
      fromHex(vector.sealedEntry),
    )
    expect(entry.secret).toEqual(seq(0, 16))
    expect(entry.linkKey).toEqual(seq(0, 16))
    expect(entry.ownerToken).toBe('A'.repeat(43))
  })

  it('round-trip, also with a password-wrapped link key', async () => {
    const key = await importAccountKey(newAccountKey())
    const plain = entryFor()
    expect(
      await openEntry(
        key,
        'f'.repeat(22),
        await sealEntry(key, 'f'.repeat(22), plain),
      ),
    ).toEqual(plain)
    const secret = randomBytes(16)
    const wrapped = {
      ...entryFor(secret),
      linkKey: await wrapSecret(secret, 'a long password'),
    }
    expect(
      await openEntry(
        key,
        'g'.repeat(22),
        await sealEntry(key, 'g'.repeat(22), wrapped),
      ),
    ).toEqual(wrapped)
  }, 30_000)

  it('are bound to their file and their account', async () => {
    const key = await importAccountKey(newAccountKey())
    const other = await importAccountKey(newAccountKey())
    const sealed = await sealEntry(key, 'f'.repeat(22), entryFor())
    await expect(openEntry(key, 'g'.repeat(22), sealed)).rejects.toThrow(
      'authentication',
    )
    await expect(openEntry(other, 'f'.repeat(22), sealed)).rejects.toThrow(
      'authentication',
    )
    await expect(
      openEntry(key, 'f'.repeat(22), sealed.subarray(0, 20)),
    ).rejects.toThrow('authentication')
  })

  it('refuse malformed contents', async () => {
    const key = await importAccountKey(newAccountKey())
    const secret = randomBytes(16)
    const bad: FileEntry[] = [
      { ...entryFor(secret), secret: randomBytes(15) },
      { ...entryFor(secret), linkKey: randomBytes(16) },
      { ...entryFor(secret), linkKey: randomBytes(40) },
      { ...entryFor(secret), ownerToken: 'short' },
    ]
    for (const entry of bad) {
      await expect(sealEntry(key, 'f'.repeat(22), entry)).rejects.toThrow(
        'malformed',
      )
    }
    // What decrypts must still be a well-formed entry.
    const raw = newAccountKey()
    const sealRaw = async (text: string) => {
      const iv = randomBytes(12)
      const cipher = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: new TextEncoder().encode(
            `vault-share/entry/${'f'.repeat(22)}`,
          ),
        },
        await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
          'encrypt',
        ]),
        new TextEncoder().encode(text),
      )
      return new Uint8Array([...iv, ...new Uint8Array(cipher)])
    }
    const opener = await importAccountKey(raw)
    for (const text of [
      'not json',
      'null',
      '{"secret":1,"key":2,"owner":3}',
      `{"secret":"${toBase64Url(secret)}","key":"${toBase64Url(secret)}"}`,
    ]) {
      await expect(
        openEntry(opener, 'f'.repeat(22), await sealRaw(text)),
        text,
      ).rejects.toThrow('malformed')
    }
  })
})
