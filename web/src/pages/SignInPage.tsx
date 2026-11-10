import { useState, type FormEvent } from 'react'
import {
  completeSignIn,
  signIn,
  type PendingSignIn,
  type SignIn,
} from '../account/account.ts'
import { useSession } from '../account/session.ts'
import { ApiError } from '../http.ts'
import { useAction } from '../ui/action.ts'
import { Button, Hero } from '../ui/controls.tsx'
import { CodeField, PasswordField } from '../ui/form.tsx'
import { ShieldIcon, UserIcon } from '../ui/icons.tsx'
import { useRouter } from '../ui/router.ts'

/**
 * Signs in, with the second step when the account has one. then names the
 * page to show afterwards; without it the page shown stays.
 */
export default function SignInPage({ then }: { then?: string }) {
  const { setAccount, setNotice } = useSession()
  const { navigate } = useRouter()
  const [pending, setPending] = useState<PendingSignIn | null>(null)
  const [recovery, setRecovery] = useState(false)
  const { busy, error, setError, run } = useAction('account')

  function finish(result: SignIn) {
    if (result.kind === 'second-step') {
      setPending(result.pending)
      return
    }
    const { failures, recoveryCodesLeft } = result.notice
    const notices: string[] = []
    if (failures > 0)
      notices.push(
        `Your password was entered ${failures === 1 ? 'once' : `${failures} times`} without the right code since you last signed in. If that was not you, change your password.`,
      )
    if (recoveryCodesLeft !== undefined)
      notices.push(
        `${recoveryCodesLeft} recovery ${recoveryCodesLeft === 1 ? 'code' : 'codes'} left.`,
      )
    setNotice(notices.length ? notices.join(' ') : null)
    setAccount(result.account)
    if (then) navigate(then)
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    void run(async () => {
      try {
        if (pending) {
          finish(await completeSignIn(pending, String(form.get('code'))))
        } else {
          finish(
            await signIn(
              String(form.get('username')),
              String(form.get('password')),
            ),
          )
        }
      } catch (failure) {
        if (failure instanceof ApiError && failure.code === 'ticket_expired') {
          setPending(null)
          setRecovery(false)
        }
        throw failure
      }
    })
  }

  if (pending)
    return (
      <section key="second" className="card stack enter">
        <Hero icon={<ShieldIcon />} title="Two-factor sign-in" />
        <form className="stack" onSubmit={submit}>
          <CodeField
            key={recovery ? 'recovery' : 'code'}
            label={recovery ? 'Recovery code' : 'Code'}
            error={error}
            autoFocus
            autoComplete={recovery ? 'off' : 'one-time-code'}
            inputMode={recovery ? 'text' : 'numeric'}
          />
          <Button type="submit" disabled={busy}>
            {busy ? 'Checking…' : 'Sign in'}
          </Button>
        </form>
        <button
          type="button"
          className="link-btn"
          onClick={() => {
            setRecovery(!recovery)
            setError(null)
          }}
        >
          {recovery ? 'Use the code from the app' : 'Use a recovery code'}
        </button>
      </section>
    )

  return (
    <section key="password" className="card stack enter">
      <Hero icon={<UserIcon />} title="Sign in" />
      <form className="stack" onSubmit={submit}>
        <label className="field">
          <span id="username-label">Username</span>
          <input
            className="text"
            name="username"
            required
            autoFocus
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            aria-labelledby="username-label"
          />
        </label>
        <PasswordField
          name="password"
          label="Password"
          autoComplete="current-password"
          error={error}
        />
        <Button type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      <button
        type="button"
        className="link-btn"
        onClick={() => navigate('/signup')}
      >
        Create an account
      </button>
    </section>
  )
}
