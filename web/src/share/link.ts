// The share link is https://host/f/{id}#{key}; the fragment never reaches the
// server. The key is the 16-byte secret, or, for a password-protected share,
// the secret wrapped under the password (see crypto/password.ts).

import {
  SECRET_LENGTH,
  WRAPPED_LENGTH,
  fromBase64Url,
  toBase64Url,
} from '../crypto/index.ts'

export type ShareLocation =
  | { id: string; secret: Uint8Array<ArrayBuffer>; wrapped?: undefined }
  | { id: string; wrapped: Uint8Array<ArrayBuffer>; secret?: undefined }

const idPattern = /^[A-Za-z0-9_-]{22}$/

export function buildLink(origin: string, id: string, key: Uint8Array): string {
  return `${origin}/f/${id}#${toBase64Url(key)}`
}

/** Parses the download page location; null means the link is not usable. */
export function parseLocation(
  pathname: string,
  hash: string,
): ShareLocation | null {
  const match = /^\/f\/([^/]+)\/?$/.exec(pathname)
  if (!match || !idPattern.test(match[1]!)) return null
  let key: Uint8Array<ArrayBuffer>
  try {
    key = fromBase64Url(hash.replace(/^#/, ''))
  } catch {
    return null
  }
  if (key.length === SECRET_LENGTH) return { id: match[1]!, secret: key }
  if (key.length === WRAPPED_LENGTH) return { id: match[1]!, wrapped: key }
  return null
}

export function isDownloadPath(pathname: string): boolean {
  return pathname.startsWith('/f/')
}

/** The uploader's delete link: /d/{id}#{owner token}. */
export function buildDeleteLink(
  origin: string,
  id: string,
  ownerToken: string,
): string {
  return `${origin}/d/${id}#${ownerToken}`
}

export function parseDeleteLocation(
  pathname: string,
  hash: string,
): { id: string; ownerToken: string } | null {
  const match = /^\/d\/([^/]+)\/?$/.exec(pathname)
  const token = hash.replace(/^#/, '')
  if (
    !match ||
    !idPattern.test(match[1]!) ||
    !/^[A-Za-z0-9_-]{43}$/.test(token)
  )
    return null
  return { id: match[1]!, ownerToken: token }
}

export function isDeletePath(pathname: string): boolean {
  return pathname.startsWith('/d/')
}
