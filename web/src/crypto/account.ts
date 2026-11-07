// Account keys (D026). The account password never leaves the browser:
// Argon2id turns it into a master key, and HKDF splits that into the auth
// secret the server checks at sign-in and the key that wraps the account
// key. The server keeps the wrapped account key and an Argon2id hash of the
// auth secret, neither of which decrypts anything. The account key seals one
// entry per file, which holds what the link needs.

import { argon2id } from 'hash-wasm'
import { fromBase64Url, toBase64Url } from './encoding.ts'
import { SECRET_LENGTH } from './keys.ts'
import { ARGON2_PARAMS, WRAPPED_LENGTH } from './password.ts'

export const ACCOUNT_SALT_LENGTH = 16
export const AUTH_SECRET_LENGTH = 32
export const DEVICE_KEY_LENGTH = 32
const ACCOUNT_KEY_LENGTH = 32
const IV_LENGTH = 12
const TAG_LENGTH = 16
/** iv | AES-256-GCM(account key) */
export const SEALED_KEY_LENGTH = IV_LENGTH + ACCOUNT_KEY_LENGTH + TAG_LENGTH

/**
 * In code points. NIST SP 800-63B-4 asks for 15 when the password is the
 * only factor, and two-factor sign-in is optional here.
 */
export const MIN_ACCOUNT_PASSWORD_LENGTH = 15

const encoder = new TextEncoder()
const noSalt = new Uint8Array(0)
const authLabel = encoder.encode('vault-share/account-auth')
const wrapLabel = encoder.encode('vault-share/account-wrap')
const accountKeyAad = 'vault-share/account-key'
const deviceAad = 'vault-share/device'
const ownerTokenPattern = /^[A-Za-z0-9_-]{43}$/

export interface AccountCredentials {
  /** Sent at sign-in; the server stores only its Argon2id hash. */
  authSecret: Uint8Array<ArrayBuffer>
  /** Seals and opens the account key; it never leaves the browser. */
  wrappingKey: CryptoKey
}

/**
 * NIST SP 800-63B-4 asks for Unicode normalization, so a password typed on
 * another keyboard or system still matches.
 */
function normalize(password: string): string {
  return password.normalize('NFKC')
}

export function accountPasswordTooShort(password: string): boolean {
  return Array.from(normalize(password)).length < MIN_ACCOUNT_PASSWORD_LENGTH
}

export function newAccountSalt(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(ACCOUNT_SALT_LENGTH))
}

export async function deriveAccountCredentials(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
): Promise<AccountCredentials> {
  if (salt.length !== ACCOUNT_SALT_LENGTH)
    throw new Error('salt must be 16 bytes')
  const master = await argon2id({
    ...ARGON2_PARAMS,
    password: normalize(password),
    salt,
    hashLength: 32,
    outputType: 'binary',
  })
  const ikm = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(master),
    'HKDF',
    false,
    ['deriveBits', 'deriveKey'],
  )
  const params = (info: Uint8Array<ArrayBuffer>) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: noSalt,
    info,
  })
  const [auth, wrappingKey] = await Promise.all([
    crypto.subtle.deriveBits(params(authLabel), ikm, AUTH_SECRET_LENGTH * 8),
    crypto.subtle.deriveKey(
      params(wrapLabel),
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    ),
  ])
  return { authSecret: new Uint8Array(auth), wrappingKey }
}

/** A fresh account key as raw bytes, to seal; use it through importAccountKey. */
export function newAccountKey(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(ACCOUNT_KEY_LENGTH))
}

export function importAccountKey(
  raw: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export async function sealAccountKey(
  wrappingKey: CryptoKey,
  raw: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (raw.length !== ACCOUNT_KEY_LENGTH)
    throw new Error('account key must be 32 bytes')
  return seal(wrappingKey, raw, accountKeyAad)
}

/** Returns null for a wrong password; throws only on a malformed input. */
export async function openAccountKey(
  wrappingKey: CryptoKey,
  sealed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (sealed.length !== SEALED_KEY_LENGTH)
    throw new Error('sealed account key has the wrong length')
  return open(wrappingKey, sealed, accountKeyAad)
}

/**
 * Seals the account key for this browser's storage under the device key,
 * which the server derives from the session token and hands out only while
 * the session lasts. A copy of the browser's storage alone opens nothing.
 */
export async function sealForDevice(
  deviceKey: Uint8Array<ArrayBuffer>,
  raw: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (raw.length !== ACCOUNT_KEY_LENGTH)
    throw new Error('account key must be 32 bytes')
  return seal(await importDeviceKey(deviceKey), raw, deviceAad)
}

/** Returns null when the device key does not match; throws on a malformed input. */
export async function openOnDevice(
  deviceKey: Uint8Array<ArrayBuffer>,
  sealed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (sealed.length !== SEALED_KEY_LENGTH)
    throw new Error('sealed account key has the wrong length')
  return open(await importDeviceKey(deviceKey), sealed, deviceAad)
}

function importDeviceKey(key: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (key.length !== DEVICE_KEY_LENGTH)
    throw new Error('device key must be 32 bytes')
  return crypto.subtle.importKey('raw', key, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

/** What the account keeps for one of its files. */
export interface FileEntry {
  /** The share secret, which opens the file's metadata. */
  secret: Uint8Array<ArrayBuffer>
  /** The link's key: the secret, or the secret wrapped under a password. */
  linkKey: Uint8Array<ArrayBuffer>
  /** The delete token. */
  ownerToken: string
}

/** The file id is bound in, so an entry cannot be moved to another file. */
export async function sealEntry(
  accountKey: CryptoKey,
  fileId: string,
  entry: FileEntry,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!validEntry(entry)) throw new Error('malformed entry')
  const plain = encoder.encode(
    JSON.stringify({
      secret: toBase64Url(entry.secret),
      key: toBase64Url(entry.linkKey),
      owner: entry.ownerToken,
    }),
  )
  return seal(accountKey, plain, entryAad(fileId))
}

export async function openEntry(
  accountKey: CryptoKey,
  fileId: string,
  sealed: Uint8Array<ArrayBuffer>,
): Promise<FileEntry> {
  const plain = await open(accountKey, sealed, entryAad(fileId))
  if (!plain) throw new Error('entry authentication failed')
  let entry: FileEntry
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plain))
    const { secret, key, owner } = parsed as Record<string, unknown>
    if (typeof secret !== 'string' || typeof key !== 'string')
      throw new Error('malformed entry')
    entry = {
      secret: fromBase64Url(secret),
      linkKey: fromBase64Url(key),
      ownerToken: owner as string,
    }
  } catch {
    throw new Error('malformed entry')
  }
  if (!validEntry(entry)) throw new Error('malformed entry')
  return entry
}

function validEntry(entry: FileEntry): boolean {
  const { secret, linkKey, ownerToken } = entry
  if (secret.length !== SECRET_LENGTH) return false
  if (typeof ownerToken !== 'string' || !ownerTokenPattern.test(ownerToken))
    return false
  if (linkKey.length === WRAPPED_LENGTH) return true
  return (
    linkKey.length === SECRET_LENGTH &&
    linkKey.every((byte, i) => byte === secret[i])
  )
}

function entryAad(fileId: string): string {
  return `vault-share/entry/${fileId}`
}

// iv(12) | AES-256-GCM(plain, aad). A random IV per seal: no key here seals
// anywhere near the 2^32 messages NIST SP 800-38D allows with random IVs.
async function seal(
  key: CryptoKey,
  plain: Uint8Array<ArrayBuffer>,
  aad: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: encoder.encode(aad),
        tagLength: TAG_LENGTH * 8,
      },
      key,
      plain,
    ),
  )
  const out = new Uint8Array(IV_LENGTH + cipher.length)
  out.set(iv)
  out.set(cipher, IV_LENGTH)
  return out
}

async function open(
  key: CryptoKey,
  sealed: Uint8Array<ArrayBuffer>,
  aad: string,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (sealed.length < IV_LENGTH + TAG_LENGTH) return null
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: sealed.subarray(0, IV_LENGTH),
          additionalData: encoder.encode(aad),
          tagLength: TAG_LENGTH * 8,
        },
        key,
        sealed.subarray(IV_LENGTH),
      ),
    )
  } catch {
    return null
  }
}
