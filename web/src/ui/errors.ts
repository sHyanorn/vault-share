import { ApiError } from '../http.ts'

/** What the user was doing when a request failed. */
export type Task = 'account' | 'upload' | 'download' | 'delete'

const unreachable = 'The server could not be reached.'

const byCode: Record<Task, Record<string, string>> = {
  account: {
    login_failed: 'Wrong username or password.',
    wrong_password: 'Wrong password.',
    wrong_code: 'Wrong code. Try again.',
    locked: 'Too many attempts. Try again in 15 minutes.',
    rate_limited: 'Too many attempts from your network. Try again later.',
    busy: 'The server is busy. Try again in a moment.',
    username_taken: 'That username is taken.',
    invalid_username:
      'Use 3 to 32 letters, digits, dots, dashes or underscores.',
    signup_closed: 'This server is not taking new accounts.',
    capacity: 'This server is not taking new accounts.',
    ticket_expired: 'That took too long. Sign in again.',
    unauthenticated: 'Your session ended. Sign in again.',
    network: unreachable,
  },
  upload: {
    too_large: 'This file is larger than the limit.',
    capacity: 'The service is full right now. Try again later.',
    rate_limited: 'Too many uploads from your network. Try again later.',
    network: unreachable,
  },
  download: {},
  delete: {},
}

/** What to tell the user when task fails with error. */
export function describeError(error: unknown, task: Task): string {
  if (error instanceof ApiError && Object.hasOwn(byCode[task], error.code))
    return byCode[task][error.code]!
  switch (task) {
    case 'account':
      // Argon2id needs 64 MiB, which a low-memory device may not grant.
      if (
        error instanceof RangeError ||
        error instanceof WebAssembly.RuntimeError
      )
        return 'Could not check the password on this device.'
      return 'Something went wrong. Try again.'
    case 'upload':
      return 'Something went wrong. Nothing was shared.'
    case 'download':
      if (error instanceof ApiError) return unreachable
      if (error instanceof TypeError)
        return 'The connection was interrupted. The download was discarded.'
      return 'The file could not be decrypted. The download was discarded.'
    case 'delete':
      return unreachable
  }
}
