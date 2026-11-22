// The signed-in account for every page; SessionProvider restores it once.

import { createContext, useContext } from 'react'
import type { Account } from './account.ts'

export type AccountState =
  | { status: 'loading' }
  /** pending: the server has not confirmed the sign-out (D040). */
  | { status: 'signed-out'; pending?: boolean }
  | { status: 'signed-in'; account: Account }

export interface Session {
  state: AccountState
  /** Signs in to account, or out with null. */
  setAccount: (account: Account | null) => void
  /** Signs this browser out; the state tells if the server confirmed it. */
  signOut: () => Promise<void>
  /** Something to tell the user once, above the page. */
  notice: string | null
  setNotice: (notice: string | null) => void
}

export const SessionContext = createContext<Session>({
  state: { status: 'loading' },
  setAccount: () => {},
  signOut: async () => {},
  notice: null,
  setNotice: () => {},
})

export function useSession(): Session {
  return useContext(SessionContext)
}

/** The signed-in account, if any. */
export function useAccount(): Account | null {
  const { state } = useSession()
  return state.status === 'signed-in' ? state.account : null
}
