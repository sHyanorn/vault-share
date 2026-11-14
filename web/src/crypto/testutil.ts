// Helpers shared by the unit tests.

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.replace(/\s+/g, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16)
  return out
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i += 65536) {
    crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, length)))
  }
  return out
}

/** A stream that yields `bytes` in pieces of `chunkSize` bytes. */
export function streamOf(
  bytes: Uint8Array,
  chunkSize = bytes.length || 1,
): ReadableStream<Uint8Array> {
  let offset = 0
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close()
        return
      }
      controller.enqueue(bytes.subarray(offset, offset + chunkSize))
      offset += chunkSize
    },
  })
}

export async function collect(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array<ArrayBuffer>> {
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of stream) {
    chunks.push(chunk)
    length += chunk.length
  }
  const out = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

interface VectorTest {
  tcId: number
  result: string
  [field: string]: unknown
}

/**
 * Vectors in Wycheproof's layout with the first valid test's expected
 * `field` changed, the first invalid test marked valid and the second
 * valid test marked invalid, so both of a runner's branches are tried. A
 * runner that checks both names all three tcIds.
 */
export function corrupted(
  json: string,
  field: string,
  applies: (group: unknown) => boolean = () => true,
) {
  const file = JSON.parse(json) as { testGroups: { tests: VectorTest[] }[] }
  const tests = file.testGroups.filter(applies).flatMap((g) => g.tests)
  const [valid, relabelled] = tests.filter((t) => t.result === 'valid')
  const invalid = tests.find((t) => t.result === 'invalid')!
  const hex = valid![field] as string
  valid![field] = hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0')
  invalid.result = 'valid'
  relabelled!.result = 'invalid'
  return {
    json: JSON.stringify(file),
    ids: [valid!.tcId, invalid.tcId, relabelled!.tcId],
  }
}

/** The tcIds named in a runner's failures. */
export function failedIds(failures: string[]): Set<number> {
  return new Set(failures.map((f) => Number(/tcId (\d+) /.exec(f)?.[1])))
}
