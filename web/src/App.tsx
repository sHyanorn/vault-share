import { useEffect } from 'react'
import { SessionProvider } from './account/SessionProvider.tsx'
import { useSession } from './account/session.ts'
import AccountPage from './pages/AccountPage.tsx'
import DeletePage from './pages/DeletePage.tsx'
import DownloadPage from './pages/DownloadPage.tsx'
import FilesPage from './pages/FilesPage.tsx'
import SignInPage from './pages/SignInPage.tsx'
import SignUpPage from './pages/SignUpPage.tsx'
import UploadPage from './pages/UploadPage.tsx'
import { isDeletePath, isDownloadPath } from './share/link.ts'
import { Link, RouterProvider } from './ui/RouterProvider.tsx'
import { useRouter } from './ui/router.ts'

export default function App() {
  // A file dropped outside the drop zone must not replace the app.
  useEffect(() => {
    const swallow = (event: DragEvent) => event.preventDefault()
    window.addEventListener('dragover', swallow)
    window.addEventListener('drop', swallow)
    return () => {
      window.removeEventListener('dragover', swallow)
      window.removeEventListener('drop', swallow)
    }
  }, [])

  return (
    <RouterProvider>
      <SessionProvider>
        <Shell />
      </SessionProvider>
    </RouterProvider>
  )
}

function Shell() {
  const { path } = useRouter()
  const { state, notice, setNotice } = useSession()
  const signedIn = state.status === 'signed-in'

  return (
    <div className="app">
      <header className="brand">
        <Link to="/" className="logo">
          vault-share
        </Link>
        {!isDownloadPath(path) && !isDeletePath(path) && (
          <nav aria-label="Account" className={`nav ${state.status}`}>
            {state.status === 'signed-out' && (
              <Link
                to="/signin"
                aria-current={
                  path === '/signin' || path === '/signup' ? 'page' : undefined
                }
              >
                Sign in
              </Link>
            )}
            {signedIn && (
              <>
                <Link
                  to="/files"
                  aria-current={path === '/files' ? 'page' : undefined}
                >
                  My files
                </Link>
                <Link
                  to="/account"
                  className="who"
                  aria-current={path === '/account' ? 'page' : undefined}
                >
                  {state.account.username}
                </Link>
              </>
            )}
          </nav>
        )}
      </header>
      <main className="stage">
        {notice && (
          <div className="notice enter" role="status">
            <span>{notice}</span>
            <button
              type="button"
              aria-label="Dismiss"
              onClick={() => setNotice(null)}
            >
              ×
            </button>
          </div>
        )}
        <Page path={path} />
      </main>
    </div>
  )
}

function Page({ path }: { path: string }) {
  const { state } = useSession()
  const { navigate } = useRouter()
  const account = state.status === 'signed-in' ? state.account : null
  const accountPage = path === '/signin' || path === '/signup'

  // Signed in, the sign-in pages have nothing to offer.
  useEffect(() => {
    if (account && accountPage) navigate('/')
  }, [account, accountPage, navigate])

  if (isDownloadPath(path)) return <DownloadPage />
  if (isDeletePath(path)) return <DeletePage />
  const gated = path === '/files' || path === '/account'
  if ((gated || accountPage) && state.status === 'loading')
    return <div className="card placeholder-card" aria-busy="true" />
  if (path === '/signin') return account ? null : <SignInPage then="/" />
  if (path === '/signup') return account ? null : <SignUpPage />
  if (gated && !account) return <SignInPage />
  if (path === '/files' && account) return <FilesPage account={account} />
  if (path === '/account' && account) return <AccountPage account={account} />
  return <UploadPage />
}
