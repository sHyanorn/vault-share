import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  deriveAccountCredentials,
  fromBase64Url,
  openAccountKey,
  openOnDevice,
  toBase64Url,
} from '../crypto/index.ts'
import { randomBytes } from '../crypto/testutil.ts'
import { ApiError } from '../http.ts'
import {
  changePassword,
  completeSignIn,
  deleteAccount,
  disableTotp,
  enableTotp,
  restore,
  signIn,
  signOut,
  signOutOwed,
  signUp,
} from './account.ts'
import * as api from './api.ts'

vi.mock('./api.ts', () => ({
  signUp: vi.fn(),
  lookupSalt: vi.fn(),
  signIn: vi.fn(),
  secondStep: vi.fn(),
  getSession: vi.fn(),
  signOut: vi.fn(),
  changePassword: vi.fn(),
  deleteAccount: vi.fn(),
  setupTotp: vi.fn(),
  enableTotp: vi.fn(),
  disableTotp: vi.fn(),
}))

const password = 'correct horse battery staple'
let storage: Map<string, string>

beforeEach(() => {
  storage = new Map()
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => storage.get(k) ?? null,
    setItem: (k: string, v: string) => void storage.set(k, v),
    removeItem: (k: string) => void storage.delete(k),
  })
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function session(over: Partial<api.SessionResponse> = {}): api.SessionResponse {
  return {
    username: 'alice',
    device_key: toBase64Url(randomBytes(32)),
    totp: false,
    ...over,
  }
}

/** Signs up alice and returns what the server was sent. */
async function signedUp() {
  const deviceKey = toBase64Url(randomBytes(32))
  vi.mocked(api.signUp).mockImplementation(async (req) =>
    session({ device_key: deviceKey, sealed_key: req.sealed_key }),
  )
  const account = await signUp('  Alice ', password)
  const sent = vi.mocked(api.signUp).mock.calls[0]![0]
  vi.mocked(api.lookupSalt).mockResolvedValue(sent.salt)
  return { account, sent, deviceKey }
}

describe('sign-up', () => {
  it('sends derived values only and keeps the key sealed for this browser', async () => {
    const { account, sent, deviceKey } = await signedUp()
    expect(sent.username).toBe('alice')
    expect(fromBase64Url(sent.salt)).toHaveLength(16)
    expect(fromBase64Url(sent.auth)).toHaveLength(32)
    expect(fromBase64Url(sent.sealed_key)).toHaveLength(60)
    expect(JSON.stringify(sent)).not.toContain('horse')

    const credentials = await deriveAccountCredentials(
      password,
      fromBase64Url(sent.salt),
    )
    expect(toBase64Url(credentials.authSecret)).toBe(sent.auth)
    expect(
      await openAccountKey(
        credentials.wrappingKey,
        fromBase64Url(sent.sealed_key),
      ),
    ).toEqual(account.raw)
    const stored = fromBase64Url(storage.get('vault-share/account')!)
    expect(await openOnDevice(fromBase64Url(deviceKey), stored)).toEqual(
      account.raw,
    )
    expect(account.key.extractable).toBe(false)
  }, 30_000)

  it('refuses a short password and a malformed username before sending', async () => {
    await expect(signUp('alice', 'fourteen chars')).rejects.toThrow('short')
    await expect(signUp('a', password)).rejects.toThrow('username')
    expect(api.signUp).not.toHaveBeenCalled()
  })
})

describe('sign-in', () => {
  it('opens the account key with the password', async () => {
    const { account, sent } = await signedUp()
    vi.mocked(api.signIn).mockResolvedValue(
      session({ sealed_key: sent.sealed_key, second_step_failures: 2 }),
    )
    const result = await signIn('ALICE', password)
    expect(vi.mocked(api.signIn).mock.calls[0]).toEqual(['alice', sent.auth])
    expect(result.kind === 'signed-in' && result.account.raw).toEqual(
      account.raw,
    )
    expect(result.kind === 'signed-in' && result.notice.failures).toBe(2)
  }, 30_000)

  it('waits for the second step and strips spaces from the code', async () => {
    const { account, sent } = await signedUp()
    vi.mocked(api.signIn).mockResolvedValue({ second_step: true, ticket: 'tk' })
    const first = await signIn('alice', password)
    if (first.kind !== 'second-step') throw new Error('no second step')
    vi.mocked(api.secondStep).mockResolvedValue(
      session({
        sealed_key: sent.sealed_key,
        totp: true,
        recovery_codes_left: 9,
      }),
    )
    const done = await completeSignIn(first.pending, '123 456')
    expect(vi.mocked(api.secondStep).mock.calls[0]).toEqual(['tk', '123456'])
    if (done.kind !== 'signed-in') throw new Error('not signed in')
    expect(done.account.raw).toEqual(account.raw)
    expect(done.account.totp).toBe(true)
    expect(done.notice.recoveryCodesLeft).toBe(9)
  }, 30_000)

  it('passes on a refusal and sends nothing for a malformed username', async () => {
    await signedUp()
    vi.mocked(api.signIn).mockRejectedValue(new ApiError(401, 'login_failed'))
    await expect(signIn('alice', 'wrong password here')).rejects.toThrow(
      'login_failed',
    )
    await expect(signIn('no', password)).rejects.toThrow('login_failed')
    expect(api.signIn).toHaveBeenCalledTimes(1)
  }, 30_000)
})

describe('restore', () => {
  it('reopens the account while the session lasts', async () => {
    const { account, deviceKey } = await signedUp()
    vi.mocked(api.getSession).mockResolvedValue(
      session({ device_key: deviceKey }),
    )
    expect((await restore())?.raw).toEqual(account.raw)
  }, 30_000)

  it('forgets the key once the session is gone or no longer matches', async () => {
    await signedUp()
    vi.mocked(api.getSession).mockResolvedValueOnce(session())
    expect(await restore()).toBeNull()
    expect(storage.size).toBe(0)

    await signedUp()
    vi.mocked(api.getSession).mockRejectedValueOnce(
      new ApiError(401, 'unauthenticated'),
    )
    expect(await restore()).toBeNull()
    expect(storage.size).toBe(0)
  }, 30_000)

  it('asks the server nothing without a stored key', async () => {
    expect(await restore()).toBeNull()
    expect(api.getSession).not.toHaveBeenCalled()
  })

  it('takes a check that failed for no sign-out, and keeps the key', async () => {
    await signedUp()
    for (const failure of [
      new ApiError(0, 'network'),
      new ApiError(429, 'rate_limited'),
      new ApiError(500, 'internal'),
    ]) {
      vi.mocked(api.getSession).mockRejectedValueOnce(failure)
      await expect(restore()).rejects.toBe(failure)
      expect([...storage.keys()]).toEqual(['vault-share/account'])
    }
  }, 30_000)

  it('forgets the key at sign-out', async () => {
    await signedUp()
    await signOut()
    expect(storage.size).toBe(0)
    expect(api.signOut).toHaveBeenCalled()
  }, 30_000)
})

describe('a sign-out the server did not confirm', () => {
  // No answer queued by one test is left for the next.
  beforeEach(() => void vi.mocked(api.signOut).mockReset())

  const failures = [
    new ApiError(0, 'network'),
    new ApiError(429, 'rate_limited'),
  ]

  it('is sent once more, a second later, and stays owed', async () => {
    await signedUp()
    for (const failure of failures)
      vi.mocked(api.signOut).mockRejectedValueOnce(failure)
    vi.useFakeTimers()
    const confirmed = signOut()
    await vi.advanceTimersByTimeAsync(999)
    expect(api.signOut).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(await confirmed).toBe(false)
    expect(api.signOut).toHaveBeenCalledTimes(2)
    expect([...storage.keys()]).toEqual(['vault-share/sign-out'])
    expect(storage.get('vault-share/sign-out')).toBe('1')
    expect(signOutOwed()).toBe(true)
  }, 30_000)

  it('leaves nothing owed once the second attempt is confirmed', async () => {
    await signedUp()
    vi.mocked(api.signOut).mockRejectedValueOnce(new ApiError(500, 'internal'))
    vi.useFakeTimers()
    const confirmed = signOut()
    await vi.advanceTimersByTimeAsync(1000)
    expect(await confirmed).toBe(true)
    expect(api.signOut).toHaveBeenCalledTimes(2)
    expect(storage.size).toBe(0)
  }, 30_000)

  it('is owed from before its request, in case the page closes', async () => {
    await signedUp()
    let owedAtRequest = false
    vi.mocked(api.signOut).mockImplementationOnce(async () => {
      owedAtRequest = signOutOwed()
    })
    expect(await signOut()).toBe(true)
    expect(owedAtRequest).toBe(true)
    expect(signOutOwed()).toBe(false)
  }, 30_000)

  it('is no longer owed after a sign-in, which ends the old session', async () => {
    const { sent } = await signedUp()
    for (const failure of failures)
      vi.mocked(api.signOut).mockRejectedValueOnce(failure)
    vi.useFakeTimers()
    const confirmed = signOut()
    await vi.advanceTimersByTimeAsync(1000)
    expect(await confirmed).toBe(false)
    vi.useRealTimers()
    vi.mocked(api.signIn).mockResolvedValueOnce(
      session({ sealed_key: sent.sealed_key }),
    )
    await signIn('alice', password)
    expect([...storage.keys()]).toEqual(['vault-share/account'])
  }, 30_000)
})

describe('changes that ask for the password again', () => {
  it('seal the same account key under the new password', async () => {
    const { account, sent } = await signedUp()
    const next = 'a different passphrase, longer'
    vi.mocked(api.changePassword).mockImplementation(async () => session())
    const changed = await changePassword(account, password, next, '654 321')
    const req = vi.mocked(api.changePassword).mock.calls[0]![0]
    expect(req.auth).toBe(sent.auth)
    expect(req.code).toBe('654 321')
    const fresh = await deriveAccountCredentials(next, fromBase64Url(req.salt))
    expect(req.new_auth).toBe(toBase64Url(fresh.authSecret))
    expect(
      await openAccountKey(fresh.wrappingKey, fromBase64Url(req.sealed_key)),
    ).toEqual(account.raw)
    expect(changed.raw).toEqual(account.raw)
    await expect(
      changePassword(account, password, 'too short'),
    ).rejects.toThrow('short')
  }, 30_000)

  it('turn two-factor sign-in on and off, and delete the account', async () => {
    const { account, sent } = await signedUp()
    vi.mocked(api.enableTotp).mockResolvedValue(
      session({ totp: true, recovery_codes: ['aaaa-bbbb-cccc-dddd'] }),
    )
    const on = await enableTotp(account, password, ' 123 456 ')
    expect(vi.mocked(api.enableTotp).mock.calls[0]).toEqual([
      sent.auth,
      '123456',
    ])
    expect(on.account.totp).toBe(true)
    expect(on.recoveryCodes).toEqual(['aaaa-bbbb-cccc-dddd'])

    vi.mocked(api.disableTotp).mockResolvedValue(session())
    expect((await disableTotp(on.account, password, '111111')).totp).toBe(false)

    await deleteAccount(account, password)
    expect(vi.mocked(api.deleteAccount).mock.calls[0]).toEqual([
      sent.auth,
      undefined,
    ])
    expect(storage.size).toBe(0)
  }, 30_000)
})
