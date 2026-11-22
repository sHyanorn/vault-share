import { useEffect, useState, type ReactNode } from 'react'
import { onSessionEnded } from '../http.ts'
import { describeError } from '../ui/errors.ts'
import {
  forget,
  remembered,
  restore,
  signOut,
  signOutOwed,
  type Account,
} from './account.ts'
import { SessionContext, type AccountState } from './session.ts'

/** A state to show and, with it, something to tell the user once. */
interface Found {
  state: AccountState
  notice?: string
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AccountState>({ status: 'loading' })
  const [notice, setNotice] = useState<string | null>(null)

  function show(found: Found) {
    setState(found.state)
    if (found.notice) setNotice(found.notice)
  }

  useEffect(() => {
    let cancelled = false
    void find().then((found) => {
      if (!cancelled) show(found)
    })
    return () => {
      cancelled = true
    }
  }, [])

  // The server ends a session that sat idle. Whichever request finds out,
  // the browser is signed out, so no page goes on as if it were signed in.
  const signedIn = state.status === 'signed-in'
  useEffect(() => {
    if (!signedIn) return
    return onSessionEnded((error) => {
      forget()
      setState({ status: 'signed-out' })
      setNotice(describeError(error, 'account'))
    })
  }, [signedIn])

  return (
    <SessionContext.Provider
      value={{
        state,
        setAccount: (account) => setState(stateOf(account)),
        check: async () => show(await find()),
        signOut: async () => {
          // Signed out, this repeats a pending sign-out. A key stored since
          // then is a sign-in from another tab, whose session it would end.
          const overtaken = state.status === 'signed-out' && remembered()
          show(await (overtaken ? find() : leave()))
        },
        notice,
        setNotice,
      }}
    >
      {children}
    </SessionContext.Provider>
  )
}

function stateOf(account: Account | null): AccountState {
  return account ? { status: 'signed-in', account } : { status: 'signed-out' }
}

/** What a page load finds: an owed sign-out is sent before anything else. */
async function find(): Promise<Found> {
  if (signOutOwed()) return leave()
  try {
    return { state: stateOf(await restore()) }
  } catch {
    return { state: { status: 'unchecked' } }
  }
}

/**
 * Signs out. Of a sign-out that was owed the user has been told that it
 * did not finish, so they are told when it does.
 */
async function leave(): Promise<Found> {
  const owed = signOutOwed()
  const confirmed = await signOut()
  return {
    state: { status: 'signed-out', pending: !confirmed },
    notice: owed && confirmed ? 'You are signed out.' : undefined,
  }
}
