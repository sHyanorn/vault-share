import { describe, expect, it } from 'vitest'
import vectors from '../../../testdata/share_format_test.json?raw'
import { shareFormat } from './shareformat.ts'
import { corrupted, failedIds } from './testutil.ts'

describe('share format vectors (testdata/share_format_test.json)', () => {
  it('passes all 33 vectors', async () => {
    expect(await shareFormat(vectors)).toEqual({ count: 33, failures: [] })
  })

  it('reports a wrong expectation', async () => {
    const { json, ids } = corrupted(vectors, 'msgSha256')
    expect(failedIds((await shareFormat(json)).failures)).toEqual(new Set(ids))
  })
})
