import { useEffect, useState, type ReactNode } from 'react'
import { onSessionEnded } from '../http.ts'
import { describeError } from '../ui/errors.ts'
import { forget, restore, type Account } from './account.ts'
import { SessionContext, type AccountState } from './session.ts'

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AccountState>({ status: 'loading' })
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    restore()
      .catch(() => null)
      .then((account) => {
        if (!cancelled) setState(stateOf(account))
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
