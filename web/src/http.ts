// How the browser talks to vaultd: JSON requests under one base path, and
// the error envelope every failed one comes back with.

export const base = '/api/v1'

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(`${status} ${code}`)
    this.status = status
    this.code = code
  }
}

let sessionEnded: ((error: ApiError) => void) | null = null

/**
 * Calls handler when the server says this browser's session is gone,
 * whichever request finds out. Returns a function that stops the calls.
 */
export function onSessionEnded(handler: (error: ApiError) => void): () => void {
  sessionEnded = handler
  return () => {
    if (sessionEnded === handler) sessionEnded = null
  }
}

export async function request<T>(
  method: string,
  path: string,
  options: { body?: unknown; ownerToken?: string } = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (options.ownerToken)
    headers['Authorization'] = `Bearer ${options.ownerToken}`
  let res: Response
  try {
    res = await fetch(base + path, {
      method,
      headers,
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch {
    throw new ApiError(0, 'network')
  }
  if (!res.ok) {
    const error = new ApiError(res.status, errorCode(await res.text()))
    if (error.code === 'unauthenticated') sessionEnded?.(error)
    throw error
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** The code of an API error envelope, or 'unknown'. */
export function errorCode(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body)
    if (typeof parsed === 'object' && parsed !== null) {
      const error = (parsed as { error?: { code?: unknown } }).error
      if (error && typeof error.code === 'string') return error.code
    }
  } catch {
    // not an API envelope
  }
  return 'unknown'
}
