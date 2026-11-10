import { afterEach, expect, it, vi } from 'vitest'
import { onSessionEnded, request } from './http.ts'

afterEach(() => vi.unstubAllGlobals())

function refuseWith(status: number, code: string) {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () => new Response(JSON.stringify({ error: { code } }), { status }),
    ),
  )
}

it('tells the listener when the server says the session is gone', async () => {
  const ended = vi.fn()
  const stop = onSessionEnded(ended)

  refuseWith(401, 'login_failed')
  await expect(request('POST', '/session')).rejects.toMatchObject({
    code: 'login_failed',
  })
  expect(ended).not.toHaveBeenCalled()

  refuseWith(401, 'unauthenticated')
  await expect(request('GET', '/account/files')).rejects.toMatchObject({
    status: 401,
    code: 'unauthenticated',
  })
  expect(ended).toHaveBeenCalledTimes(1)

  stop()
  await expect(request('GET', '/account/files')).rejects.toThrow()
  expect(ended).toHaveBeenCalledTimes(1)
})
