import { describe, expect, it } from 'vitest'

// The crypto module (M1) targets the browser's Web Crypto and Streams APIs.
// Tests run under Node, so this pins the assumption that Node provides the
// same globals and no DOM shim is needed.
describe('test runtime', () => {
  it('provides Web Crypto', () => {
    expect(globalThis.crypto.subtle).toBeDefined()
    expect(globalThis.crypto.getRandomValues(new Uint8Array(16))).toHaveLength(
      16,
    )
  })

  it('provides the Streams API', () => {
    expect(globalThis.ReadableStream).toBeDefined()
    expect(globalThis.TransformStream).toBeDefined()
  })
})
