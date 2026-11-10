import { afterEach, describe, expect, it, vi } from 'vitest'
import { collect } from '../crypto/testutil.ts'
import { ApiError } from '../http.ts'
import { createFile, deleteFile, downloadContent, getMeta } from './api.ts'

function respond(status: number, body: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => vi.unstubAllGlobals())

describe('api client', () => {
  it('posts JSON and returns the parsed body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      respond(201, {
        id: 'x',
        owner_token: 't',
        upload_url: '/u',
        expires_at: 1,
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const created = await createFile({
      size: 38,
      meta: 'm',
      auth_key: 'a',
      expires_in: 3600,
      max_downloads: 1,
    })
    expect(created.id).toBe('x')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/files')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toMatchObject({
      size: 38,
      max_downloads: 1,
    })
  })

  it('turns the error envelope into an ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          respond(404, { error: { code: 'not_found', message: 'not found' } }),
        ),
    )
    await expect(getMeta('x')).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    })
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('<html>', { status: 502 })),
    )
    await expect(getMeta('x')).rejects.toMatchObject({
      status: 502,
      code: 'unknown',
    })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))
    await expect(getMeta('x')).rejects.toBeInstanceOf(ApiError)
  })

  it('sends the owner token only as a bearer header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(respond(204, undefined))
    vi.stubGlobal('fetch', fetchMock)
    await deleteFile('x', 'owner')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/files/x')
    expect((init.headers as Record<string, string>)['Authorization']).toBe(
      'Bearer owner',
    )
    expect(init.body).toBeUndefined()
  })

  it('returns the content body as a stream', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(new Uint8Array([1, 2, 3]))),
    )
    const body = await downloadContent('x', 'tok')
    expect(await collect(body)).toEqual(new Uint8Array([1, 2, 3]))
  })
})
