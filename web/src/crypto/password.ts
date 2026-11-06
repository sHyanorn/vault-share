// Optional password protection: the link carries the secret wrapped under a
// key derived from the password with Argon2id, so the link alone is not
// enough. Guessing is offline (the wrapped secret is in the link), which is
// why the derivation is deliberately expensive.

import { argon2id } from 'hash-wasm'
import { SECRET_LENGTH } from './keys.ts'

/** Memory in KiB, passes and lanes: above the OWASP minimum (19 MiB, 2 passes). */
export const ARGON2_PARAMS = {
  memorySize: 65536,
  iterations: 2,
  parallelism: 1,
}

const SALT_LENGTH = 16
const IV_LENGTH = 12
const TAG_LENGTH = 16
/** salt | iv | AES-256-GCM(secret) */
export const WRAPPED_LENGTH =
  SALT_LENGTH + IV_LENGTH + SECRET_LENGTH + TAG_LENGTH

/** In code points. Offline guessing makes a short password nearly worthless. */
export const MIN_PASSWORD_LENGTH = 8

export function passwordTooShort(password: string): boolean {
  return Array.from(password).length < MIN_PASSWORD_LENGTH
}

export async function wrapSecret(
  secret: Uint8Array<ArrayBuffer>,
  password: string,
): Promise<Uint8Array<ArrayBuffer>> {
  if (secret.length !== SECRET_LENGTH)
    throw new Error('secret must be 16 bytes')
  if (passwordTooShort(password))
    throw new Error(
      `password must have at least ${MIN_PASSWORD_LENGTH} characters`,
    )
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const key = await wrappingKey(password, salt)
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 },
      key,
      secret,
    ),
  )
  const out = new Uint8Array(WRAPPED_LENGTH)
  out.set(salt)
  out.set(iv, SALT_LENGTH)
  out.set(sealed, SALT_LENGTH + IV_LENGTH)
  return out
}

/**
 * Returns null for a wrong password; throws only on a malformed input. Any
 * length is tried, so links made before the minimum length still open.
 */
export async function unwrapSecret(
  wrapped: Uint8Array<ArrayBuffer>,
  password: string,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (wrapped.length !== WRAPPED_LENGTH)
    throw new Error('wrapped secret has the wrong length')
  if (password === '') return null
  const salt = wrapped.subarray(0, SALT_LENGTH)
  const iv = wrapped.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
  const key = await wrappingKey(password, salt)
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 },
        key,
        wrapped.subarray(SALT_LENGTH + IV_LENGTH),
      ),
    )
  } catch {
    return null
  }
}

async function wrappingKey(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  const bits = await argon2id({
    ...ARGON2_PARAMS,
    password,
    salt,
    hashLength: 32,
    outputType: 'binary',
  })
  return crypto.subtle.importKey(
    'raw',
    new Uint8Array(bits),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  )
}
