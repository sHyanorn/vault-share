// Upload and download flows: everything the server receives is ciphertext.

import {
  decryptMetadata,
  decryptStream,
  deriveKeys,
  encryptMetadata,
  encryptStream,
  encryptedSize,
  exportAuthKey,
  fromBase64Url,
  generateSecret,
  signChallenge,
  toBase64Url,
  wrapSecret,
  type DerivedKeys,
} from '../crypto/index.ts'
import { ApiError } from '../http.ts'
import * as api from './api.ts'
import { buildDeleteLink, buildLink } from './link.ts'
import type { Sink } from './save.ts'

export type ExpiresIn = 3600 | 86400 | 604800

export interface UploadOptions {
  expiresIn: ExpiresIn
  maxDownloads: number
  /** When set, the link carries the secret wrapped under this password. */
  password?: string
  /**
   * When set, called before the content goes up, so a file whose upload
   * breaks off is already kept. Resolves to whether it was kept.
   */
  keep?: (share: NewShare) => Promise<boolean>
}

/** A file the server has a record of and no content for yet. */
export interface NewShare {
  id: string
  ownerToken: string
  secret: Uint8Array<ArrayBuffer>
  /** What the link carries: the secret, or the secret wrapped under a password. */
  linkKey: Uint8Array<ArrayBuffer>
}

export interface Progress {
  phase: 'encrypting' | 'uploading' | 'decrypting'
  fraction: number
}

export interface Share {
  id: string
  link: string
  deleteLink: string
  ownerToken: string
  expiresAt: Date
  protected: boolean
  /** What keep resolved to; unset without one. */
  kept?: boolean
}

export async function uploadFile(
  file: File,
  options: UploadOptions,
  onProgress: (progress: Progress) => void,
): Promise<Share> {
  const secret = generateSecret()
  // Wrapping happens first: a failure here must not leave a stored file behind.
  const key = options.password
    ? await wrapSecret(secret, options.password)
    : secret
  const keys = await deriveKeys(secret)
  const meta = await encryptMetadata(keys.metaKey, {
    name: file.name,
    type: file.type || 'application/octet-stream',
    size: file.size,
  })
  const created = await api.createFile({
    size: encryptedSize(file.size),
    meta: toBase64Url(meta),
    auth_key: toBase64Url(await exportAuthKey(keys.authKey)),
    expires_in: options.expiresIn,
    max_downloads: options.maxDownloads,
  })
  const kept = await options.keep?.({
    id: created.id,
    ownerToken: created.owner_token,
    secret,
    linkKey: key,
  })

  const counted = file
    .stream()
    .pipeThrough(
      counter(file.size, (fraction) =>
        onProgress({ phase: 'encrypting', fraction }),
      ),
    )
  // The browser streams the Blob into its own storage as records are sealed.
  const ciphertext = await new Response(encryptStream(counted, keys.fileKey), {
    headers: { 'Content-Type': 'application/octet-stream' },
  }).blob()
  await api.uploadContent(
    created.id,
    ciphertext,
    created.owner_token,
    (fraction) => onProgress({ phase: 'uploading', fraction }),
  )
  const origin = window.location.origin
  return {
    id: created.id,
    link: buildLink(origin, created.id, key),
    deleteLink: buildDeleteLink(origin, created.id, created.owner_token),
    ownerToken: created.owner_token,
    expiresAt: new Date(created.expires_at * 1000),
    protected: Boolean(options.password),
    kept,
  }
}

/**
 * Deletes the file. One that is already gone counts as deleted, and the
 * promise then resolves to false.
 */
export async function deleteShare(
  id: string,
  ownerToken: string,
): Promise<boolean> {
  try {
    await api.deleteFile(id, ownerToken)
    return true
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return false
    throw error
  }
}

export interface ShareInfo {
  id: string
  name: string
  size: number
  ciphertextSize: number
  downloadsLeft: number
  expiresAt: Date
  keys: DerivedKeys
}

export async function openShare(
  id: string,
  secret: Uint8Array<ArrayBuffer>,
): Promise<ShareInfo> {
  const [keys, meta] = await Promise.all([deriveKeys(secret), api.getMeta(id)])
  const file = await decryptMetadata(keys.metaKey, fromBase64Url(meta.meta))
  return {
    id,
    name: file.name,
    size: file.size,
    ciphertextSize: meta.size,
    downloadsLeft: meta.downloads_left,
    expiresAt: new Date(meta.expires_at * 1000),
    keys,
  }
}

/**
 * Takes one download and streams the file into the sink. onGranted reports
 * the downloads left once the count is spent, which happens before any byte
 * arrives; a failure after that point cannot be retried for free.
 */
export async function downloadShare(
  info: ShareInfo,
  sink: Sink,
  onProgress: (progress: Progress) => void,
  onGranted: (downloadsLeft: number) => void = () => {},
): Promise<void> {
  let body: ReadableStream<Uint8Array>
  try {
    const meta = await api.getMeta(info.id) // a fresh challenge
    const signature = await signChallenge(
      info.keys.authKey,
      fromBase64Url(meta.challenge),
    )
    const granted = await api.requestDownload(
      info.id,
      meta.challenge,
      toBase64Url(signature),
    )
    onGranted(granted.downloads_left)
    body = await api.downloadContent(info.id, granted.token)
  } catch (error) {
    await sink.discard().catch(() => {})
    throw error
  }
  const counted = body.pipeThrough(
    counter(info.ciphertextSize, (fraction) =>
      onProgress({ phase: 'decrypting', fraction }),
    ),
  )
  await sink.consume(decryptStream(counted, info.keys.fileKey))
}

function counter(total: number, onFraction: (fraction: number) => void) {
  let seen = 0
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.length
      onFraction(total > 0 ? Math.min(1, seen / total) : 1)
      controller.enqueue(chunk)
    },
  })
}
