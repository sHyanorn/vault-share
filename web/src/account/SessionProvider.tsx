import { useEffect, useState, type ReactNode } from 'react'
import { restore, type Account } from './account.ts'
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
