import { afterEach, describe, expect, it, vi } from 'vitest'
import { chooseSink } from './save.ts'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

/** The bytes in one chunk, then the end. */
function streamOf(bytes: number[]) {
  return new ReadableStream<Uint8Array<ArrayBuffer>>({
    start(controller) {
      controller.enqueue(new Uint8Array(bytes))
      controller.close()
    },
  })
}

/** One chunk, then the error decryption raises on a damaged record. */
function failingAfterOneChunk() {
  return new ReadableStream<Uint8Array<ArrayBuffer>>({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]))
    },
    pull(controller) {
      controller.error(new Error('authentication failed'))
    },
  })
}

describe('file sink', () => {
  /** A save dialog whose file records what reaches it. */
  function stubPicker() {
    const written: Uint8Array[] = []
    const calls = { close: 0, abort: 0 }
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        written.push(chunk)
      },
      close() {
        calls.close++
      },
      abort() {
        calls.abort++
      },
    })
    vi.stubGlobal('window', {
      showSaveFilePicker: async () => ({
        createWritable: async () => writable,
      }),
    })
    return { written, calls }
  }

  it('commits the file once the stream ends', async () => {
    const { written, calls } = stubPicker()
    const sink = await chooseSink('a.bin')
    expect(sink?.kind).toBe('file')
    await sink!.consume(streamOf([1, 2, 3]))
    expect(written).toHaveLength(1)
    expect(calls).toEqual({ close: 1, abort: 0 })
  })

  it('aborts the partial file when the stream fails', async () => {
    const { written, calls } = stubPicker()
    const sink = await chooseSink('a.bin')
    await expect(sink!.consume(failingAfterOneChunk())).rejects.toThrow(
      'authentication failed',
    )
    expect(written).toHaveLength(1) // the first record arrived, then was dropped
    expect(calls).toEqual({ close: 0, abort: 1 })
  })
})

describe('download sink', () => {
  /** A browser without a save dialog, recording the Blobs it is offered. */
  function stubDownloads() {
    const offered: Blob[] = []
    const anchor = { href: '', download: '', click: vi.fn() }
    vi.stubGlobal('window', {})
    vi.stubGlobal('document', { createElement: () => anchor })
    vi.spyOn(URL, 'createObjectURL').mockImplementation((blob) => {
      offered.push(blob as Blob)
      return 'blob:download'
    })
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    return { offered, anchor }
  }

  it('offers the whole file once the stream ends', async () => {
    const { offered, anchor } = stubDownloads()
    const sink = await chooseSink('a.bin')
    expect(sink?.kind).toBe('download')
    await sink!.consume(streamOf([1, 2, 3]))
    expect(offered).toHaveLength(1)
    expect(new Uint8Array(await offered[0]!.arrayBuffer())).toEqual(
      new Uint8Array([1, 2, 3]),
    )
    expect(anchor.download).toBe('a.bin')
    expect(anchor.click).toHaveBeenCalledOnce()
  })

  it('offers nothing when the stream fails', async () => {
    const { offered, anchor } = stubDownloads()
    const sink = await chooseSink('a.bin')
    await expect(sink!.consume(failingAfterOneChunk())).rejects.toThrow(
      'authentication failed',
    )
    expect(offered).toHaveLength(0)
    expect(anchor.click).not.toHaveBeenCalled()
  })
})
