// In-page navigation between the app's own pages, so moving between them
// keeps the account open instead of reloading. vaultd serves the app for
// every path, so each of these URLs also works when opened directly.

import { createContext, useContext } from 'react'

export interface Router {
  path: string
  navigate: (to: string) => void
}

export const RouterContext = createContext<Router>({
  path: '/',
  navigate: () => {},
})

export function useRouter(): Router {
  return useContext(RouterContext)
}
