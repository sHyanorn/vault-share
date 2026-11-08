import { useState, type FormEvent } from 'react'
import { normalizeUsername, signUp, validUsername } from '../account/account.ts'
import { describeAccountError } from '../account/errors.ts'
import { useSession } from '../account/session.ts'
import {
  MIN_ACCOUNT_PASSWORD_LENGTH,
  accountPasswordTooShort,
} from '../crypto/index.ts'
import { Button, Hero } from '../ui/controls.tsx'
import { UserIcon } from '../ui/icons.tsx'
import { useRouter } from '../ui/router.ts'

export default function SignUpPage() {
  const { setAccount } = useSession()
  const { navigate } = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const name = normalizeUsername(username)
  const nameOk = validUsername(name)
  // Only a name that cannot become valid by typing on is flagged.
  const nameWrong =
    username !== '' && !nameOk && (name.length > 2 || !/^[a-z0-9]/.test(name))
  const passwordOk = !accountPasswordTooShort(password)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!nameOk || !passwordOk) return
    setBusy(true)
    setError(null)
    try {
      setAccount(await signUp(username, password))
      navigate('/')
    } catch (failure) {
      setError(describeAccountError(failure))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card stack enter">
      <Hero icon={<UserIcon />} title="Create an account" />
      <form className="stack" onSubmit={submit}>
        <label className="field">
          <span id="new-username-label">Username</span>
          <input
            className="text"
            name="username"
            required
            autoFocus
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={32}
            aria-labelledby="new-username-label"
            aria-invalid={nameWrong ? true : undefined}
            aria-describedby={nameWrong ? 'new-username-hint' : undefined}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
          {nameWrong && (
            <span id="new-username-hint" className="error">
              3 to 32 letters, digits, dots, dashes or underscores
            </span>
          )}
        </label>
        <label className="field">
          <span id="new-password-label">Password</span>
          <input
            className="text"
            type="password"
            name="password"
            required
            autoComplete="new-password"
            aria-labelledby="new-password-label"
            aria-describedby="new-password-hint"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <span id="new-password-hint" className="hint">
            At least {MIN_ACCOUNT_PASSWORD_LENGTH} characters
          </span>
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" disabled={busy || !nameOk || !passwordOk}>
          {busy ? 'Creating account…' : 'Create account'}
        </Button>
        <p className="fine">
          There is no password reset. A lost password loses the account; links
          you shared keep working.
        </p>
      </form>
      <button
        type="button"
        className="link-btn"
        onClick={() => navigate('/signin')}
      >
        I have an account
      </button>
    </section>
  )
}
