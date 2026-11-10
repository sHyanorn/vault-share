import { useState } from 'react'

/** Copies text to the clipboard; false without clipboard access. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/**
 * Copies text to the clipboard and reports it for a moment. Without
 * clipboard access copy resolves to false and the text stays on the page.
 */
export function useCopy(): {
  copied: boolean
  copy: (text: string) => Promise<boolean>
} {
  const [copied, setCopied] = useState(false)
  async function copy(text: string) {
    const ok = await copyText(text)
    if (ok) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    }
    return ok
  }
  return { copied, copy }
}
