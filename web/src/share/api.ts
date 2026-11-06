// Typed client for the vaultd API (docs/SPEC.md section 7).

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(`${status} ${code}`)
    this.status = status
    this.code = code
  }
}

export interface CreateRequest {
  size: number
  meta: string
  auth_key: string
  expires_in: number
  max_downloads: number
}

export interface CreateResponse {
  id: string
  owner_token: string
  upload_url: string
  expires_at: number
}

export interface MetaResponse {
  meta: string
  size: number
  downloads_left: number
  expires_at: number
  challenge: string
}

export interface DownloadResponse {
  token: string
  downloads_left: number
}

const base = '/api/v1'

export function createFile(req: CreateRequest): Promise<CreateResponse> {
  return request('POST', '/files', { body: req })
}

/** Streams the ciphertext with XMLHttpRequest, the one transport with upload progress everywhere. */
export function uploadContent(
  url: string,
  body: Blob,
  ownerToken: string,
  onProgress: (fraction: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', url)
    xhr.setRequestHeader('Authorization', `Bearer ${ownerToken}`)
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total)
    }
    xhr.onload = () => {
      if (xhr.status === 204) resolve()
      else reject(new ApiError(xhr.status, errorCode(xhr.responseText)))
    }
    xhr.onerror = () => reject(new ApiError(0, 'network'))
    xhr.send(body)
  })
}

export function getMeta(id: string): Promise<MetaResponse> {
  return request('GET', `/files/${id}/meta`)
}

export function requestDownload(
  id: string,
  challenge: string,
  signature: string,
): Promise<DownloadResponse> {
  return request('POST', `/files/${id}/download`, {
    body: { challenge, signature },
  })
}

export async function downloadContent(
  id: string,
  token: string,
): Promise<ReadableStream<Uint8Array>> {
  const res = await fetch(`${base}/files/${id}/content?token=${token}`)
  if (!res.ok) throw new ApiError(res.status, errorCode(await res.text()))
  if (!res.body) throw new ApiError(0, 'no_body')
  return res.body
}

export function deleteFile(id: string, ownerToken: string): Promise<void> {
  return request('DELETE', `/files/${id}`, { ownerToken })
}

async function request<T>(
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
  if (!res.ok) throw new ApiError(res.status, errorCode(await res.text()))
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

function errorCode(body: string): string {
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
