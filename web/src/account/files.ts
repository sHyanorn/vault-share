// My files (D030): the server lists the account's files with their sealed
// entries; only this browser opens the entries, and through them the names.

import {
  SECRET_LENGTH,
  decryptMetadata,
  deriveKeys,
  fromBase64Url,
  openEntry,
  sealEntry,
  toBase64Url,
} from '../crypto/index.ts'
import { buildLink } from '../share/link.ts'
import type { NewShare } from '../share/share.ts'
import type { Account } from './account.ts'
import * as api from './api.ts'

export interface KeptFile {
  id: string
  unreadable?: undefined
  name: string
  /** Plaintext size in bytes. */
  size: number
  link: string
  protected: boolean
  ownerToken: string
  downloadsLeft: number
  expiresAt: Date
  createdAt: Date
  /** False while the content is still on its way. */
  uploaded: boolean
}

/** A file whose entry or metadata does not open; it can only run out. */
export interface UnreadableFile {
  id: string
  unreadable: true
  expiresAt: Date
  createdAt: Date
}

/**
 * Keeps a new share in the account's list, so that it shows up there and
 * can be deleted. A failure costs the list entry, not the share.
 */
export async function keepShare(
  account: Account,
  share: NewShare,
): Promise<boolean> {
  try {
    const entry = await sealEntry(account.key, share.id, {
      secret: share.secret,
      linkKey: share.linkKey,
      ownerToken: share.ownerToken,
    })
    await api.keepFile(share.id, share.ownerToken, toBase64Url(entry))
    return true
  } catch {
    return false
  }
}

export async function listKept(
  account: Account,
  origin = window.location.origin,
): Promise<{ files: (KeptFile | UnreadableFile)[]; more: boolean }> {
  const { files, more } = await api.listFiles()
  return {
    files: await Promise.all(files.map((f) => open(account, f, origin))),
    more,
  }
}

async function open(
  account: Account,
  f: api.KeptFileResponse,
  origin: string,
): Promise<KeptFile | UnreadableFile> {
  const expiresAt = new Date(f.expires_at * 1000)
  const createdAt = new Date(f.created_at * 1000)
  try {
    const entry = await openEntry(account.key, f.id, fromBase64Url(f.entry))
    const keys = await deriveKeys(entry.secret)
    const meta = await decryptMetadata(keys.metaKey, fromBase64Url(f.meta))
    return {
      id: f.id,
      name: meta.name,
      size: meta.size,
      link: buildLink(origin, f.id, entry.linkKey),
      protected: entry.linkKey.length !== SECRET_LENGTH,
      ownerToken: entry.ownerToken,
      downloadsLeft: f.downloads_left,
      expiresAt,
      createdAt,
      uploaded: f.uploaded,
    }
  } catch {
    return { id: f.id, unreadable: true, expiresAt, createdAt }
  }
}
