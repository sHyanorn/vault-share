import { ApiError } from '../share/api.ts'

/** What to tell the user when an account request fails. */
export function describeAccountError(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'login_failed':
        return 'Wrong username or password.'
      case 'wrong_password':
        return 'Wrong password.'
      case 'wrong_code':
        return 'Wrong code. Try again.'
      case 'locked':
        return 'Too many attempts. Try again in 15 minutes.'
      case 'rate_limited':
        return 'Too many attempts from your network. Try again later.'
      case 'busy':
        return 'The server is busy. Try again in a moment.'
      case 'username_taken':
        return 'That username is taken.'
      case 'invalid_username':
        return 'Use 3 to 32 letters, digits, dots, dashes or underscores.'
      case 'signup_closed':
      case 'capacity':
        return 'This server is not taking new accounts.'
      case 'ticket_expired':
        return 'That took too long. Sign in again.'
      case 'unauthenticated':
        return 'Your session ended. Sign in again.'
      case 'network':
        return 'The server could not be reached.'
    }
  }
  // Argon2id needs 64 MiB, which a low-memory device may not grant.
  if (error instanceof RangeError || error instanceof WebAssembly.RuntimeError)
    return 'Could not check the password on this device.'
  return 'Something went wrong. Try again.'
}
