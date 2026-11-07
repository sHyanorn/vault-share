import { describe, expect, it } from 'vitest'
import { formatBytes, formatExpiry, safeFileName } from './format.ts'

describe('safeFileName', () => {
  it('removes control characters and path separators', () => {
    expect(safeFileName('report.pdf')).toBe('report.pdf')
    expect(safeFileName('../../etc/passwd')).toBe('_.._etc_passwd')
    expect(safeFileName('a\u0000b\nc:d*e?f"g<h>i|j\\k')).toBe(
      'abc_d_e_f_g_h_i_j_k',
    )
    expect(safeFileName('   ')).toBe('download')
    expect(safeFileName('.hidden')).toBe('hidden')
    expect(safeFileName(' .env')).toBe('env')
    expect(safeFileName('\u00a0. ..bashrc')).toBe('bashrc')
    expect(safeFileName('x'.repeat(300))).toHaveLength(255)
  })

  it('removes format characters that spoof the extension', () => {
    expect(safeFileName('invoice\u202efdp.exe')).toBe('invoicefdp.exe')
    expect(safeFileName('photo\u200b\u200c.jpg\u2069.exe')).toBe(
      'photo.jpg.exe',
    )
    expect(safeFileName('\ufeffnotes.txt')).toBe('notes.txt')
    expect(safeFileName('\u200d\u200d')).toBe('download')
    expect(safeFileName('family \ud83d\udc68\u200d\ud83d\udc69.png')).toBe(
      'family \ud83d\udc68\u200d\ud83d\udc69.png',
    )
  })

  it('truncates by code point, never inside a surrogate pair', () => {
    const emoji = '\ud83d\ude00'.repeat(300)
    const cut = safeFileName(emoji)
    expect(Array.from(cut)).toHaveLength(255)
    expect(cut.endsWith('\ud83d\ude00')).toBe(true)
  })
})

describe('formatBytes', () => {
  it('uses decimal units with sensible precision', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(999)).toBe('999 B')
    expect(formatBytes(1234)).toBe('1.23 KB')
    expect(formatBytes(12_345)).toBe('12.3 KB')
    expect(formatBytes(123_456_789)).toBe('123 MB')
    expect(formatBytes(1_500_000_000)).toBe('1.50 GB')
    expect(formatBytes(999_600)).toBe('1.00 MB')
    expect(formatBytes(99_960)).toBe('100 KB')
    expect(formatBytes(9_996)).toBe('10.0 KB')
  })
})

describe('formatExpiry', () => {
  it('rounds to hours and days', () => {
    const now = new Date('2026-11-06T12:00:00Z')
    expect(formatExpiry(new Date('2026-11-06T12:20:00Z'), now)).toBe(
      'less than an hour',
    )
    expect(formatExpiry(new Date('2026-11-06T13:00:00Z'), now)).toBe('1 hour')
    expect(formatExpiry(new Date('2026-11-06T23:00:00Z'), now)).toBe('11 hours')
    expect(formatExpiry(new Date('2026-11-07T11:30:00Z'), now)).toBe('1 day')
    expect(formatExpiry(new Date('2026-11-13T12:00:00Z'), now)).toBe('7 days')
  })
})
