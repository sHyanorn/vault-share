import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import {
  changePassword,
  deleteAccount,
  disableTotp,
  enableTotp,
  setupTotp,
  signOut,
  type Account,
} from '../account/account.ts'
import { describeAccountError } from '../account/errors.ts'
import { useSession } from '../account/session.ts'
import {
  MIN_ACCOUNT_PASSWORD_LENGTH,
  accountPasswordTooShort,
} from '../crypto/index.ts'
import { Button, Collapse, Hero } from '../ui/controls.tsx'
import { useCopy } from '../ui/copy.ts'
import { ChevronIcon, ShieldIcon, UserIcon } from '../ui/icons.tsx'
import { QrCode } from '../ui/qr.tsx'
import { useRouter } from '../ui/router.ts'

type Panel = 'totp' | 'password' | 'delete' | null

export default function AccountPage({ account }: { account: Account }) {
  const { setAccount, setNotice } = useSession()
  const { navigate } = useRouter()
  const [panel, setPanel] = useState<Panel>(null)
  const [codes, setCodes] = useState<string[] | null>(null)

  function toggle(next: Panel) {
    setPanel(panel === next ? null : next)
  }

  async function leave() {
    await signOut().catch(() => {})
    setAccount(null)
    navigate('/')
  }

  if (codes)
    return <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />

  return (
    <section className="card stack enter">
      <Hero icon={<UserIcon />} title={account.username} />
      <div className="settings">
        <Setting
          title="Two-factor sign-in"
          value={account.totp ? 'On' : 'Off'}
          open={panel === 'totp'}
          onToggle={() => toggle('totp')}
        >
          {account.totp ? (
            <TotpOff
              account={account}
              onDone={(next) => {
                setAccount(next)
                setPanel(null)
                setNotice('Two-factor sign-in is off.')
              }}
            />
          ) : (
            <TotpOn
              account={account}
              onDone={(next, recoveryCodes) => {
                setAccount(next)
                setPanel(null)
                setCodes(recoveryCodes)
              }}
            />
          )}
        </Setting>
        <Setting
          title="Password"
          open={panel === 'password'}
          onToggle={() => toggle('password')}
        >
          <PasswordChange
            account={account}
            onDone={(next) => {
              setAccount(next)
              setPanel(null)
              setNotice('Password changed. Your other devices were signed out.')
            }}
          />
        </Setting>
      </div>
      <div className="footer-actions">
        <button type="button" className="link-btn" onClick={leave}>
          Sign out
        </button>
        <button
          type="button"
          className="link-btn danger"
          aria-expanded={panel === 'delete'}
          onClick={() => toggle('delete')}
        >
          Delete account
        </button>
      </div>
      <Collapse open={panel === 'delete'}>
        <DeleteAccount
          account={account}
          onCancel={() => setPanel(null)}
          onDone={() => {
            setAccount(null)
            setNotice('Your account and its files are deleted.')
            navigate('/')
          }}
        />
      </Collapse>
    </section>
  )
}

interface SettingProps {
  title: string
  value?: string
  open: boolean
  onToggle: () => void
  children: ReactNode
}

function Setting({ title, value, open, onToggle, children }: SettingProps) {
  return (
    <div className={`setting ${open ? 'open' : ''}`}>
      <button
        type="button"
        className="setting-head"
        aria-expanded={open}
        onClick={onToggle}
      >
        <span className="title">{title}</span>
        {value && <span className="value">{value}</span>}
        <ChevronIcon />
      </button>
      <Collapse open={open}>
        <div className="setting-body">{children}</div>
      </Collapse>
    </div>
  )
}

/** The username field password managers look for next to a password. */
function UsernameField({ account }: { account: Account }) {
  return (
    <input
      type="text"
      name="username"
      autoComplete="username"
      value={account.username}
      readOnly
      hidden
    />
  )
}

function PasswordField({
  name,
  label,
  autoComplete,
  hint,
}: {
  name: string
  label: string
  autoComplete: string
  hint?: string
}) {
  return (
    <label className="field">
      <span id={`${name}-label`}>{label}</span>
      <input
        className="text"
        type="password"
        name={name}
        required
        autoComplete={autoComplete}
        aria-labelledby={`${name}-label`}
        aria-describedby={hint ? `${name}-hint` : undefined}
      />
      {hint && (
        <span id={`${name}-hint`} className="hint">
          {hint}
        </span>
      )}
    </label>
  )
}

function CodeField({ label = 'Code' }: { label?: string }) {
  return (
    <label className="field">
      <span id="totp-code-label">{label}</span>
      <input
        className="text code"
        name="code"
        required
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        aria-labelledby="totp-code-label"
      />
    </label>
  )
}

/** Runs a form's action and keeps its busy state and error. */
function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await action()
    } catch (failure) {
      setError(describeAccountError(failure))
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, run }
}

function FormError({ error }: { error: string | null }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null
}

function TotpOn({
  account,
  onDone,
}: {
  account: Account
  onDone: (account: Account, codes: string[]) => void
}) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(
    null,
  )
  const [loadError, setLoadError] = useState<string | null>(null)
  const { copied, copy } = useCopy()
  const { busy, error, run } = useAction()
  const started = useRef(false)

  // One setup per opening: each call draws a new secret, and the page
  // must show the one the server keeps.
  useEffect(() => {
    if (started.current) return
    started.current = true
    setupTotp().then(setSetup, (failure: unknown) =>
      setLoadError(describeAccountError(failure)),
    )
  }, [])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    void run(async () => {
      const result = await enableTotp(
        account,
        String(form.get('password')),
        String(form.get('code')),
      )
      onDone(result.account, result.recoveryCodes)
    })
  }

  if (!setup) return <FormError error={loadError} />
  return (
    <form className="stack" onSubmit={submit}>
      <div className="totp-setup">
        <QrCode value={setup.uri} label="QR code for your authenticator app" />
        <div className="secret">
          <code>{setup.secret.match(/.{1,4}/g)?.join(' ')}</code>
          <Button variant="quiet" onClick={() => copy(setup.secret)}>
            {copied ? 'Copied' : 'Copy key'}
          </Button>
        </div>
      </div>
      <UsernameField account={account} />
      <CodeField label="Code from the app" />
      <PasswordField
        name="password"
        label="Password"
        autoComplete="current-password"
      />
      <FormError error={error} />
      <Button type="submit" disabled={busy}>
        {busy ? 'Checking…' : 'Turn on'}
      </Button>
    </form>
  )
}

function TotpOff({
  account,
  onDone,
}: {
  account: Account
  onDone: (account: Account) => void
}) {
  const { busy, error, run } = useAction()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    void run(async () =>
      onDone(
        await disableTotp(
          account,
          String(form.get('password')),
          String(form.get('code')),
        ),
      ),
    )
  }
  return (
    <form className="stack" onSubmit={submit}>
      <UsernameField account={account} />
      <CodeField label="Code or recovery code" />
      <PasswordField
        name="password"
        label="Password"
        autoComplete="current-password"
      />
      <FormError error={error} />
      <Button type="submit" variant="danger" disabled={busy}>
        {busy ? 'Checking…' : 'Turn off'}
      </Button>
    </form>
  )
}

function PasswordChange({
  account,
  onDone,
}: {
  account: Account
  onDone: (account: Account) => void
}) {
  const [next, setNext] = useState('')
  const { busy, error, run } = useAction()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    void run(async () =>
      onDone(
        await changePassword(
          account,
          String(form.get('current')),
          next,
          account.totp ? String(form.get('code')) : undefined,
        ),
      ),
    )
  }
  return (
    <form className="stack" onSubmit={submit}>
      <UsernameField account={account} />
      <PasswordField
        name="current"
        label="Current password"
        autoComplete="current-password"
      />
      <label className="field">
        <span id="next-label">New password</span>
        <input
          className="text"
          type="password"
          name="next"
          required
          autoComplete="new-password"
          aria-labelledby="next-label"
          aria-describedby="next-hint"
          value={next}
          onChange={(event) => setNext(event.target.value)}
        />
        <span id="next-hint" className="hint">
          At least {MIN_ACCOUNT_PASSWORD_LENGTH} characters
        </span>
      </label>
      {account.totp && <CodeField />}
      <FormError error={error} />
      <Button type="submit" disabled={busy || accountPasswordTooShort(next)}>
        {busy ? 'Changing…' : 'Change password'}
      </Button>
    </form>
  )
}

function DeleteAccount({
  account,
  onCancel,
  onDone,
}: {
  account: Account
  onCancel: () => void
  onDone: () => void
}) {
  const { busy, error, run } = useAction()
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    void run(async () => {
      await deleteAccount(
        account,
        String(form.get('password')),
        account.totp ? String(form.get('code')) : undefined,
      )
      onDone()
    })
  }
  return (
    <form className="stack danger-zone" onSubmit={submit}>
      <p>
        This deletes your account and every file in My files. Their links stop
        working.
      </p>
      <UsernameField account={account} />
      <PasswordField
        name="password"
        label="Password"
        autoComplete="current-password"
      />
      {account.totp && <CodeField label="Code or recovery code" />}
      <FormError error={error} />
      <div className="confirm-actions">
        <Button variant="quiet" onClick={onCancel}>
          Keep account
        </Button>
        <Button type="submit" variant="danger" disabled={busy}>
          {busy ? 'Deleting…' : 'Delete account'}
        </Button>
      </div>
    </form>
  )
}

function RecoveryCodes({
  codes,
  onDone,
}: {
  codes: string[]
  onDone: () => void
}) {
  const { copied, copy } = useCopy()
  const text = codes.join('\n') + '\n'

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'vault-share-recovery-codes.txt'
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <section className="card stack enter">
      <Hero
        icon={<ShieldIcon />}
        title="Two-factor sign-in is on"
        text="Keep these codes. Each signs you in once without your phone. They are shown only now."
        tone="ok"
      />
      <ol className="codes">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ol>
      <div className="code-actions">
        <Button variant="quiet" onClick={() => copy(text)}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
        <Button variant="quiet" onClick={download}>
          Download
        </Button>
      </div>
      <Button onClick={onDone}>Done</Button>
    </section>
  )
}
