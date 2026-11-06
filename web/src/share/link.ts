// The share link is https://host/f/{id}#{secret}; the fragment never reaches the server.

import { SECRET_LENGTH, fromBase64Url, toBase64Url } from '../crypto/index.ts'

export interface ShareLocation {
  id: string
  secret: Uint8Array<ArrayBuffer>
}

const idPattern = /^[A-Za-z0-9_-]{22}$/

export function buildLink(
  origin: string,
  id: string,
  secret: Uint8Array,
): string {
  return `${origin}/f/${id}#${toBase64Url(secret)}`
}

/** Parses the download page location; null means the link is not usable. */
export function parseLocation(
  pathname: string,
  hash: string,
): ShareLocation | null {
  const match = /^\/f\/([^/]+)\/?$/.exec(pathname)
  if (!match || !idPattern.test(match[1]!)) return null
  let secret: Uint8Array<ArrayBuffer>
  try {
    secret = fromBase64Url(hash.replace(/^#/, ''))
  } catch {
    return null
  }
  if (secret.length !== SECRET_LENGTH) return null
  return { id: match[1]!, secret }
}

export function isDownloadPath(pathname: string): boolean {
  return pathname.startsWith('/f/')
}
