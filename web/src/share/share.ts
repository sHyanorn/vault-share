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
  type DerivedKeys,
} from '../crypto/index.ts'
import * as api from './api.ts'
import { buildLink } from './link.ts'
import type { Sink } from './save.ts'

export type ExpiresIn = 3600 | 86400 | 604800

export interface UploadOptions {
  expiresIn: ExpiresIn
  maxDownloads: number
}

export interface Progress {
  phase: 'encrypting' | 'uploading' | 'downloading'
  fraction: number
}

export interface Share {
  id: string
  link: string
  ownerToken: string
  expiresAt: Date
}

export async function uploadFile(
  file: File,
  options: UploadOptions,
  onProgress: (progress: Progress) => void,
): Promise<Share> {
  const secret = generateSecret()
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

  const counted = file
    .stream()
    .pipeThrough(
      counter(file.size, (fraction) =>
        onProgress({ phase: 'encrypting', fraction }),
      ),
    )
  const ciphertext = await collect(encryptStream(counted, keys.fileKey))
  await api.uploadContent(
    created.upload_url,
    ciphertext,
    created.owner_token,
    (fraction) => onProgress({ phase: 'uploading', fraction }),
  )
  return {
    id: created.id,
    link: buildLink(window.location.origin, created.id, secret),
    ownerToken: created.owner_token,
    expiresAt: new Date(created.expires_at * 1000),
  }
}

export function deleteShare(share: Share): Promise<void> {
  return api.deleteFile(share.id, share.ownerToken)
}

export interface ShareInfo {
  id: string
  name: string
  type: string
  size: number
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
    type: file.type,
    size: file.size,
    downloadsLeft: meta.downloads_left,
    expiresAt: new Date(meta.expires_at * 1000),
    keys,
  }
}

export async function downloadShare(
  info: ShareInfo,
  sink: Sink,
  onProgress: (progress: Progress) => void,
): Promise<void> {
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
  const body = await api.downloadContent(info.id, granted.token)
  const counted = body.pipeThrough(
    counter(encryptedSize(info.size), (fraction) =>
      onProgress({ phase: 'downloading', fraction }),
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

/** Gathers the stream into a Blob; browsers page large Blobs out to disk. */
async function collect(
  stream: ReadableStream<Uint8Array<ArrayBuffer>>,
): Promise<Blob> {
  const parts: Uint8Array<ArrayBuffer>[] = []
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    parts.push(value)
  }
  return new Blob(parts, { type: 'application/octet-stream' })
}
