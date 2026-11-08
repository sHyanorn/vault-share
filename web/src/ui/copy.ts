import { useState } from 'react'

/**
 * Copies text to the clipboard and reports it for a moment. Without
 * clipboard access nothing happens; the text stays on the page.
 */
export function useCopy(): {
  copied: boolean
  copy: (text: string) => Promise<void>
} {
  const [copied, setCopied] = useState(false)
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      // no clipboard access
    }
  }
  return { copied, copy }
}
