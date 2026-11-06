// Where decrypted bytes go: straight to disk where the browser allows it,
// otherwise into a Blob that is offered as a download at the end.

export interface Sink {
  /** Where the bytes end up, for the final message. */
  kind: 'file' | 'download'
  /** Consumes the stream; on error nothing usable is kept. */
  consume(stream: ReadableStream<Uint8Array<ArrayBuffer>>): Promise<void>
  /** Gives up before anything was written. */
  discard(): Promise<void>
}

interface SaveFilePickerWindow {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<{
    createWritable(): Promise<WritableStream<Uint8Array>>
  }>
}

/**
 * Returns null when the person dismissed the save dialog. The file is opened
 * for writing here, before any download is spent, so a target that cannot
 * be written falls back to a Blob download instead of failing later.
 */
export async function chooseSink(name: string): Promise<Sink | null> {
  const picker = (window as SaveFilePickerWindow).showSaveFilePicker
  if (!picker) return blobSink(name)
  let writable: WritableStream<Uint8Array>
  try {
    const handle = await picker({ suggestedName: name })
    writable = await handle.createWritable()
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError')
      return null
    return blobSink(name)
  }
  return {
    kind: 'file',
    // pipeTo closes the writable on success, which commits the file, and
    // aborts it on failure, which discards the partial write.
    consume: (stream) => stream.pipeTo(writable),
    discard: () => writable.abort(),
  }
}

function blobSink(name: string): Sink {
  return {
    kind: 'download',
    async consume(stream) {
      // The browser streams the Blob into its own storage as chunks arrive.
      const blob = await new Response(stream, {
        headers: { 'Content-Type': 'application/octet-stream' },
      }).blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = name
      anchor.click()
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
    },
    discard: () => Promise.resolve(),
  }
}
