// Typed client for the account endpoints of the vaultd API. Everything sent
// is derived in the browser (crypto/account.ts); the password never is.

import { request } from '../http.ts'

export interface SessionResponse {
  username: string
  device_key: string
  sealed_key?: string
  totp: boolean
  recovery_codes?: string[]
  recovery_codes_left?: number
  second_step_failures?: number
}

export interface SecondStepResponse {
  second_step: true
  ticket: string
}

export interface SignUpRequest {
  username: string
  salt: string
  auth: string
  sealed_key: string
}

export interface PasswordRequest {
  auth: string
  salt: string
  new_auth: string
  sealed_key: string
  code?: string
}

export interface TotpSetupResponse {
  secret: string
  uri: string
}

export interface KeptFileResponse {
  id: string
  size: number
  meta: string
  entry: string
  downloads_left: number
  expires_at: number
  created_at: number
  uploaded: boolean
}

export function signUp(req: SignUpRequest): Promise<SessionResponse> {
  return request('POST', '/account', { body: req })
}

export async function lookupSalt(username: string): Promise<string> {
  const { salt } = await request<{ salt: string }>('POST', '/account/salt', {
    body: { username },
  })
  return salt
}

export function signIn(
  username: string,
  auth: string,
): Promise<SessionResponse | SecondStepResponse> {
  return request('POST', '/session', { body: { username, auth } })
}

export function secondStep(
  ticket: string,
  code: string,
): Promise<SessionResponse> {
  return request('POST', '/session/totp', { body: { ticket, code } })
}

export function getSession(): Promise<SessionResponse> {
  return request('GET', '/session')
}

export function signOut(): Promise<void> {
  return request('DELETE', '/session')
}

export function changePassword(req: PasswordRequest): Promise<SessionResponse> {
  return request('POST', '/account/password', { body: req })
}

export function deleteAccount(auth: string, code?: string): Promise<void> {
  return request('DELETE', '/account', { body: { auth, code } })
}

export function setupTotp(): Promise<TotpSetupResponse> {
  return request('POST', '/account/totp/setup')
}

export function enableTotp(
  auth: string,
  code: string,
): Promise<SessionResponse> {
  return request('POST', '/account/totp', { body: { auth, code } })
}

export function disableTotp(
  auth: string,
  code: string,
): Promise<SessionResponse> {
  return request('DELETE', '/account/totp', { body: { auth, code } })
}

export function keepFile(
  id: string,
  ownerToken: string,
  entry: string,
): Promise<void> {
  return request('PUT', `/account/files/${id}`, {
    body: { entry },
    ownerToken,
  })
}

export function listFiles(): Promise<{
  files: KeptFileResponse[]
  more: boolean
}> {
  return request('GET', '/account/files')
}
