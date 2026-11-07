// Presentation helpers for uploader-controlled strings and numbers.

/**
 * Strips what a file system or a Content-Disposition header could misread,
 * and the invisible format characters (bidi overrides, zero-width marks)
 * that let "invoice\u202Efdp.exe" display as "invoiceexe.pdf". The joiner
 * stays so emoji sequences survive. Length is capped in code points.
 */
export function safeFileName(name: string): string {
  const cleaned = name
    .replace(/(?!\u200d)[\p{Cc}\p{Cf}]/gu, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/^[\s.]+/, '')
    .trim()
  const capped = Array.from(cleaned).slice(0, 255).join('')
  // A name of joiners alone would display as nothing.
  return /[^\s\u200d]/u.test(capped) ? capped : 'download'
}

const units = ['B', 'KB', 'MB', 'GB']

export function formatBytes(bytes: number): string {
  let value = bytes
  let unit = 0
  while (value >= 999.5 && unit < units.length - 1) {
    value /= 1000
    unit++
  }
  // Three significant digits (1.23, 12.3, 123); bytes are always whole.
  let digits = 2
  if (unit === 0 || value >= 99.95) digits = 0
  else if (value >= 9.995) digits = 1
  return `${value.toFixed(digits)} ${units[unit]}`
}

export function formatExpiry(expiresAt: Date, now = new Date()): string {
  const hours = Math.max(
    0,
    Math.round((expiresAt.getTime() - now.getTime()) / 3_600_000),
  )
  if (hours < 1) return 'less than an hour'
  if (hours < 24) return hours === 1 ? '1 hour' : `${hours} hours`
  const days = Math.round(hours / 24)
  return days === 1 ? '1 day' : `${days} days`
}
