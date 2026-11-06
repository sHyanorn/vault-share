// Presentation helpers for uploader-controlled strings and numbers.

/** Strips what a file system or a Content-Disposition header could misread. */
export function safeFileName(name: string): string {
  const cleaned = name
    .replace(/\p{Cc}/gu, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 255)
  return cleaned || 'download'
}

const units = ['B', 'KB', 'MB', 'GB']

export function formatBytes(bytes: number): string {
  let value = bytes
  let unit = 0
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit++
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2
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
