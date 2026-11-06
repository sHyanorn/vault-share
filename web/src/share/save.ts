// Where decrypted bytes go: straight to disk where the browser allows it,
// otherwise into a Blob that is offered as a download at the end.

export interface Sink {
  /** Consumes the stream; on error nothing is kept. */
  consume(stream: ReadableStream<Uint8Array<ArrayBuffer>>): Promise<void>
}

interface SaveFilePickerWindow {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<{
    createWritable(): Promise<WritableStream<Uint8Array>>
  }>
}

/** Returns null when the person dismissed the save dialog. */
export async function chooseSink(
  name: string,
  type: string,
): Promise<Sink | null> {
  const picker = (window as SaveFilePickerWindow).showSaveFilePicker
  if (!picker) return blobSink(name, type)
  try {
    const handle = await picker({ suggestedName: name })
    return {
      async consume(stream) {
        // pipeTo closes the writable on success, which commits the file, and
        // aborts it on failure, which discards the partial write.
        await stream.pipeTo(await handle.createWritable())
      },
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError')
      return null
    return blobSink(name, type)
  }
}

function blobSink(name: string, type: string): Sink {
  return {
    async consume(stream) {
      const parts: Uint8Array<ArrayBuffer>[] = []
      const reader = stream.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        parts.push(value)
      }
      const url = URL.createObjectURL(new Blob(parts, { type }))
      try {
        const anchor = document.createElement('a')
        anchor.href = url
        anchor.download = name
        anchor.click()
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 60_000)
      }
    },
  }
}
