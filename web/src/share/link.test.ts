import { describe, expect, it } from 'vitest'
import {
  fromBase64Url,
  generateSecret,
  toBase64Url,
  wrapSecret,
} from '../crypto/index.ts'
import {
  buildDeleteLink,
  buildLink,
  isDeletePath,
  isDownloadPath,
  parseDeleteLocation,
  parseLocation,
} from './link.ts'

const id = 'AAAAAAAAAAAAAAAAAAAAAA'

describe('share link', () => {
  it('round-trips through the fragment', () => {
    const secret = generateSecret()
    const link = new URL(buildLink('https://share.example', id, secret))
    expect(link.origin).toBe('https://share.example')
    expect(link.search).toBe('')
    const parsed = parseLocation(link.pathname, link.hash)
    expect(parsed?.id).toBe(id)
    expect(parsed?.secret).toEqual(secret)
  })

  it('rejects anything that is not a valid id and a 16-byte secret', () => {
    const secret = toBase64Url(generateSecret())
    for (const [pathname, hash] of [
      ['/f/' + id, ''],
      ['/f/' + id, '#'],
      ['/f/' + id, '#' + secret.slice(1)],
      ['/f/' + id, '#' + secret + 'A'],
      ['/f/' + id, '#' + secret.slice(0, 21) + '+'],
      ['/f/short', '#' + secret],
      ['/f/' + id + '/x', '#' + secret],
      ['/g/' + id, '#' + secret],
    ]) {
      expect(parseLocation(pathname!, hash!), `${pathname} ${hash}`).toBeNull()
    }
    expect(parseLocation('/f/' + id + '/', '#' + secret)).not.toBeNull()
  })

  it('recognises download paths', () => {
    expect(isDownloadPath('/f/' + id)).toBe(true)
    expect(isDownloadPath('/')).toBe(false)
  })
})

describe('password-protected link', () => {
  it('carries the wrapped secret and never the secret itself', async () => {
    const secret = generateSecret()
    const wrapped = await wrapSecret(secret, 'open sesame')
    const link = new URL(buildLink('https://share.example', id, wrapped))
    // The secret's bytes are nowhere in the fragment, at any offset: its
    // base64 lines up with the fragment's only at offsets divisible by 3.
    const fragment = fromBase64Url(link.hash.slice(1))
    const at = fragment.findIndex((_, i) =>
      secret.every((byte, j) => fragment[i + j] === byte),
    )
    expect(at).toBe(-1)
    const parsed = parseLocation(link.pathname, link.hash)
    expect(parsed?.wrapped).toEqual(wrapped)
    expect(parsed?.secret).toBeUndefined()
  }, 30_000)
})

describe('delete link', () => {
  const token = toBase64Url(new Uint8Array(32))
  it('round-trips the owner token through the fragment', () => {
    const link = new URL(buildDeleteLink('https://share.example', id, token))
    expect(link.pathname).toBe('/d/' + id)
    expect(parseDeleteLocation(link.pathname, link.hash)).toEqual({
      id,
      ownerToken: token,
    })
    expect(isDeletePath(link.pathname)).toBe(true)
  })
  it('rejects malformed ids and tokens', () => {
    expect(parseDeleteLocation('/d/' + id, '#' + token.slice(1))).toBeNull()
    expect(parseDeleteLocation('/d/short', '#' + token)).toBeNull()
    expect(parseDeleteLocation('/f/' + id, '#' + token)).toBeNull()
  })
})
