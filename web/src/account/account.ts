// Account flows (D026, D027). The password stays here: what leaves is the
// auth secret derived from it, a random salt, and the account key sealed
// under it. Between page loads this browser keeps the account key only
// sealed under the session's device key.

import {
  accountPasswordTooShort,
  deriveAccountCredentials,
  fromBase64Url,
  importAccountKey,
  newAccountKey,
  newAccountSalt,
  openAccountKey,
  openOnDevice,
  sealAccountKey,
  sealForDevice,
  toBase64Url,
  type AccountCredentials,
} from '../crypto/index.ts'
import { ApiError } from '../http.ts'
import * as api from './api.ts'

export interface Account {
  username: string
  totp: boolean
  /** Seals and opens the entries of the account's files. */
  key: CryptoKey
  /**
   * The same key as bytes, for sealing it again at a password change or
   * for this browser. Code on the page could reach it through the device
   * key anyway, so keeping it adds no exposure.
   */
  raw: Uint8Array<ArrayBuffer>
}

const usernamePattern = /^[a-z0-9][a-z0-9._-]{2,31}$/
const storageKey = 'vault-share/account'

/** Usernames are lowercase; what the user types is read that way. */
export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase()
}

export function validUsername(username: string): boolean {
  return usernamePattern.test(username)
}

export async function signUp(
  username: string,
  password: string,
): Promise<Account> {
  const name = normalizeUsername(username)
  if (!validUsername(name)) throw new Error('invalid username')
  if (accountPasswordTooShort(password)) throw new Error('password too short')
  const salt = newAccountSalt()
  const credentials = await deriveAccountCredentials(password, salt)
  const raw = newAccountKey()
  const resp = await api.signUp({
    username: name,
    salt: toBase64Url(salt),
    auth: toBase64Url(credentials.authSecret),
    sealed_key: toBase64Url(await sealAccountKey(credentials.wrappingKey, raw)),
  })
  return remember(resp, raw)
}

export type SignIn =
  | { kind: 'signed-in'; account: Account; notice: SignInNotice }
  | { kind: 'second-step'; pending: PendingSignIn }

export interface SignInNotice {
  /** Second steps that failed after a right password since the last sign-in. */
  failures: number
  /** Recovery codes left, after a sign-in with one. */
  recoveryCodesLeft?: number
}

/** A right password waiting for its second step. */
export interface PendingSignIn {
  ticket: string
  wrappingKey: CryptoKey
}

/** Throws ApiError 401 login_failed for a wrong username or password. */
export async function signIn(
  username: string,
  password: string,
): Promise<SignIn> {
  const name = normalizeUsername(username)
  if (!validUsername(name)) throw new ApiError(401, 'login_failed')
  const credentials = await credentialsFor(name, password)
  const resp = await api.signIn(name, toBase64Url(credentials.authSecret))
  if ('second_step' in resp)
    return {
      kind: 'second-step',
      pending: { ticket: resp.ticket, wrappingKey: credentials.wrappingKey },
    }
  return signedIn(resp, credentials.wrappingKey)
}

/** Throws ApiError 401 wrong_code, or ticket_expired to start over. */
export async function completeSignIn(
  pending: PendingSignIn,
  code: string,
): Promise<SignIn> {
  return signedIn(
    await api.secondStep(pending.ticket, code.replace(/\s+/g, '')),
    pending.wrappingKey,
  )
}

async function signedIn(
  resp: api.SessionResponse,
  wrappingKey: CryptoKey,
): Promise<SignIn> {
  const raw = resp.sealed_key
    ? await openAccountKey(wrappingKey, fromBase64Url(resp.sealed_key))
    : null
  // The server accepted the password, so its sealed key must open with it.
  if (!raw) throw new Error('the account key does not open')
  return {
    kind: 'signed-in',
    account: await remember(resp, raw),
    notice: {
      failures: resp.second_step_failures ?? 0,
      recoveryCodesLeft: resp.recovery_codes_left,
    },
  }
}

/** The account this browser is signed in to, or null. */
export async function restore(): Promise<Account | null> {
  const stored = load()
  if (!stored) return null
  let resp: api.SessionResponse
  try {
    resp = await api.getSession()
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) forget()
    if (error instanceof ApiError && error.status !== 0) return null
    throw error
  }
  let raw: Uint8Array<ArrayBuffer> | null = null
  try {
    raw = await openOnDevice(fromBase64Url(resp.device_key), stored)
  } catch {
    // malformed storage: start over
  }
  if (!raw) {
    forget()
    return null
  }
  return accountFrom(resp, raw)
}

export async function signOut(): Promise<void> {
  forget()
  await api.signOut()
}

/** Throws ApiError 403 wrong_password or wrong_code. */
export async function changePassword(
  account: Account,
  current: string,
  next: string,
  code?: string,
): Promise<Account> {
  if (accountPasswordTooShort(next)) throw new Error('password too short')
  const old = await credentialsFor(account.username, current)
  const salt = newAccountSalt()
  const fresh = await deriveAccountCredentials(next, salt)
  const resp = await api.changePassword({
    auth: toBase64Url(old.authSecret),
    salt: toBase64Url(salt),
    new_auth: toBase64Url(fresh.authSecret),
    sealed_key: toBase64Url(
      await sealAccountKey(fresh.wrappingKey, account.raw),
    ),
    code: code || undefined,
  })
  return remember(resp, account.raw)
}

/** Throws ApiError 403 wrong_password or wrong_code. */
export async function deleteAccount(
  account: Account,
  password: string,
  code?: string,
): Promise<void> {
  const credentials = await credentialsFor(account.username, password)
  await api.deleteAccount(
    toBase64Url(credentials.authSecret),
    code || undefined,
  )
  forget()
}

export const setupTotp = api.setupTotp

/** Returns the recovery codes, shown this once. */
export async function enableTotp(
  account: Account,
  password: string,
  code: string,
): Promise<{ account: Account; recoveryCodes: string[] }> {
  const credentials = await credentialsFor(account.username, password)
  const resp = await api.enableTotp(
    toBase64Url(credentials.authSecret),
    code.replace(/\s+/g, ''),
  )
  return {
    account: await remember(resp, account.raw),
    recoveryCodes: resp.recovery_codes ?? [],
  }
}

export async function disableTotp(
  account: Account,
  password: string,
  code: string,
): Promise<Account> {
  const credentials = await credentialsFor(account.username, password)
  const resp = await api.disableTotp(
    toBase64Url(credentials.authSecret),
    code.replace(/\s+/g, ''),
  )
  return remember(resp, account.raw)
}

async function credentialsFor(
  username: string,
  password: string,
): Promise<AccountCredentials> {
  const salt = fromBase64Url(await api.lookupSalt(username))
  return deriveAccountCredentials(password, salt)
}

// Keeps the account key for this browser under the session's device key.
async function remember(
  resp: api.SessionResponse,
  raw: Uint8Array<ArrayBuffer>,
): Promise<Account> {
  const sealed = await sealForDevice(fromBase64Url(resp.device_key), raw)
  try {
    localStorage.setItem(storageKey, toBase64Url(sealed))
  } catch {
    // Storage may be off; the account then lasts until the page closes.
  }
  return accountFrom(resp, raw)
}

async function accountFrom(
  resp: api.SessionResponse,
  raw: Uint8Array<ArrayBuffer>,
): Promise<Account> {
  return {
    username: resp.username,
    totp: resp.totp,
    key: await importAccountKey(raw),
    raw,
  }
}

function load(): Uint8Array<ArrayBuffer> | null {
  try {
    const value = localStorage.getItem(storageKey)
    return value ? fromBase64Url(value) : null
  } catch {
    return null
  }
}

/** Drops the account key this browser keeps. */
export function forget(): void {
  try {
    localStorage.removeItem(storageKey)
  } catch {
    // nothing stored
  }
}
