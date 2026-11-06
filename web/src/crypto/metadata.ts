// File name, type and size travel encrypted; the server sees only this blob.

export interface FileMetadata {
  name: string
  type: string
  size: number
}

const IV_LENGTH = 12
const TAG_LENGTH = 16

/** iv(12) | AES-256-GCM(JSON) */
export async function encryptMetadata(
  metaKey: CryptoKey,
  meta: FileMetadata,
): Promise<Uint8Array<ArrayBuffer>> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const plain = new TextEncoder().encode(
    JSON.stringify({ name: meta.name, type: meta.type, size: meta.size }),
  )
  const params = { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 }
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(params, metaKey, plain),
  )
  const out = new Uint8Array(IV_LENGTH + cipher.length)
  out.set(iv)
  out.set(cipher, IV_LENGTH)
  return out
}

export async function decryptMetadata(
  metaKey: CryptoKey,
  blob: Uint8Array<ArrayBuffer>,
): Promise<FileMetadata> {
  if (blob.length < IV_LENGTH + TAG_LENGTH)
    throw new Error('truncated metadata')
  const params = {
    name: 'AES-GCM',
    iv: blob.subarray(0, IV_LENGTH),
    tagLength: TAG_LENGTH * 8,
  }
  let plain: ArrayBuffer
  try {
    plain = await crypto.subtle.decrypt(
      params,
      metaKey,
      blob.subarray(IV_LENGTH),
    )
  } catch {
    throw new Error('metadata authentication failed')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(plain))
  } catch {
    throw new Error('malformed metadata')
  }
  if (!isFileMetadata(parsed)) throw new Error('malformed metadata')
  return { name: parsed.name, type: parsed.type, size: parsed.size }
}

function isFileMetadata(value: unknown): value is FileMetadata {
  if (typeof value !== 'object' || value === null) return false
  const { name, type, size } = value as Record<string, unknown>
  return (
    typeof name === 'string' &&
    typeof type === 'string' &&
    typeof size === 'number' &&
    Number.isInteger(size) &&
    size >= 0
  )
}
