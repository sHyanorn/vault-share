import { describe, expect, it } from 'vitest'
import { generateSecret, toBase64Url } from '../crypto/index.ts'
import { buildLink, isDownloadPath, parseLocation } from './link.ts'

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
