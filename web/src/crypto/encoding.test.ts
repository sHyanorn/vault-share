import { describe, expect, it } from 'vitest'
import { fromBase64Url, toBase64Url } from './encoding.ts'
import { randomBytes } from './testutil.ts'

describe('base64url', () => {
  it('round-trips every length', () => {
    for (let length = 0; length <= 40; length++) {
      const bytes = randomBytes(length)
      expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes)
    }
  })

  it('uses the url-safe alphabet without padding', () => {
    expect(toBase64Url(new Uint8Array([0xfb, 0xff]))).toBe('-_8')
    expect(fromBase64Url('-_8')).toEqual(new Uint8Array([0xfb, 0xff]))
  })

  it('rejects the standard alphabet, padding and impossible lengths', () => {
    for (const bad of ['+_8', '-/8', '-_8=', 'abcde', 'a b', 'ä']) {
      expect(() => fromBase64Url(bad)).toThrow('invalid base64url')
    }
  })
})

describe('canonical form', () => {
  it('accepts only one encoding per secret', () => {
    expect(fromBase64Url('AAAAAAAAAAAAAAAAAAAAAA')).toEqual(new Uint8Array(16))
    for (const bad of ['-_9', '-_-', 'AAAAAAAAAAAAAAAAAAAAAB']) {
      expect(() => fromBase64Url(bad)).toThrow('invalid base64url')
    }
  })
})
