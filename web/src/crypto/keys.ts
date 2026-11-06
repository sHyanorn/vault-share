// Key hierarchy of a share. The 16-byte secret travels only in the URL
// fragment; everything else is derived from it with HKDF-SHA256.

export const SECRET_LENGTH = 16

const encoder = new TextEncoder()
const noSalt = new Uint8Array(0)

export interface DerivedKeys {
  /** Input keying material of the file stream, see ece.ts. */
  fileKey: Uint8Array<ArrayBuffer>
  /** AES-256-GCM key for the file name and type. */
  metaKey: CryptoKey
  /** HMAC-SHA-256 key that proves possession of the link to the server. */
  authKey: CryptoKey
}

export function generateSecret(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(SECRET_LENGTH))
}

/** HKDF-SHA256 (RFC 5869) producing `length` bytes. */
export async function hkdf(
  ikm: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, [
    'deriveBits',
  ])
  const params = { name: 'HKDF', hash: 'SHA-256', salt, info }
  return new Uint8Array(await crypto.subtle.deriveBits(params, key, length * 8))
}

export async function deriveKeys(
  secret: Uint8Array<ArrayBuffer>,
): Promise<DerivedKeys> {
  if (secret.length !== SECRET_LENGTH)
    throw new Error('secret must be 16 bytes')
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ])
  const params = (label: string) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: noSalt,
    info: encoder.encode(label),
  })
  const [fileBits, metaKey, authKey] = await Promise.all([
    crypto.subtle.deriveBits(params('vault-share/file'), ikm, 256),
    crypto.subtle.deriveKey(
      params('vault-share/meta'),
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    ),
    crypto.subtle.deriveKey(
      params('vault-share/auth'),
      ikm,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign'],
    ),
  ])
  return { fileKey: new Uint8Array(fileBits), metaKey, authKey }
}

/** Signs a server challenge; the server verifies it with the stored auth key. */
export async function signChallenge(
  authKey: CryptoKey,
  challenge: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.sign('HMAC', authKey, challenge))
}

/** Raw auth key bytes, uploaded once so the server can verify challenges. */
export async function exportAuthKey(
  authKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', authKey))
}
