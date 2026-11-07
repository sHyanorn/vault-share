import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
} from 'react'
import { useAccount } from '../account/session.ts'
import { MIN_PASSWORD_LENGTH, passwordTooShort } from '../crypto/index.ts'
import { ApiError } from '../share/api.ts'
import { formatBytes, formatExpiry } from '../share/format.ts'
import {
  deleteShareById,
  uploadFile,
  type ExpiresIn,
  type Progress as ShareProgress,
  type Share,
} from '../share/share.ts'
import { Button, Hero, Progress, Segmented, Stepper } from '../ui/controls.tsx'
import { CheckIcon, FileIcon, LinkOffIcon, UploadIcon } from '../ui/icons.tsx'
import { Link } from '../ui/RouterProvider.tsx'

type Phase =
  | { kind: 'pick' }
  | { kind: 'working'; progress: ShareProgress }
  | { kind: 'done'; share: Share }
  | { kind: 'deleted' }
  | { kind: 'error'; message: string }

const expiryOptions: { value: ExpiresIn; label: string }[] = [
  { value: 3600, label: '1 hour' },
  { value: 86400, label: '1 day' },
  { value: 604800, label: '7 days' },
]

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null)
  const [expiresIn, setExpiresIn] = useState<ExpiresIn>(86400)
  const [maxDownloads, setMaxDownloads] = useState(1)
  const [password, setPassword] = useState<string | null>(null)
  const [phase, setPhase] = useState<Phase>({ kind: 'pick' })
  const account = useAccount()
  const shortPassword = password !== null && passwordTooShort(password)

  async function start() {
    if (!file) return
    setPhase({
      kind: 'working',
      progress: { phase: 'encrypting', fraction: 0 },
    })
    try {
      const share = await uploadFile(
        file,
        {
          expiresIn,
          maxDownloads,
          password: password || undefined,
          account: account ?? undefined,
        },
        (progress) => setPhase({ kind: 'working', progress }),
      )
      setPhase({ kind: 'done', share })
    } catch (error) {
      setPhase({ kind: 'error', message: describe(error) })
    }
  }

  function reset() {
    setFile(null)
    setPhase({ kind: 'pick' })
  }

  switch (phase.kind) {
    case 'working':
      return (
        <section key="working" className="card stack enter">
          <FileRow file={file!} />
          <Progress
            label={
              phase.progress.phase === 'encrypting' ? 'Encrypting' : 'Uploading'
            }
            fraction={phase.progress.fraction}
          />
        </section>
      )
    case 'done':
      return (
        <Result
          key="done"
          share={phase.share}
          maxDownloads={maxDownloads}
          onDeleted={() => setPhase({ kind: 'deleted' })}
          onReset={reset}
        />
      )
    case 'deleted':
      return (
        <section key="deleted" className="card stack enter">
          <Hero
            icon={<LinkOffIcon />}
            title="Deleted"
            text="The link no longer works."
            tone="muted"
          />
          <button type="button" className="link-btn" onClick={reset}>
            Share another file
          </button>
        </section>
      )
    case 'error':
      return (
        <section key="error" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="Upload failed"
            text={phase.message}
            tone="muted"
          />
          <Button onClick={start}>Try again</Button>
          <button type="button" className="link-btn" onClick={reset}>
            Choose another file
          </button>
        </section>
      )
    default:
      return (
        <section key="pick" className="card stack enter">
          {file ? (
            <FileRow file={file} onChange={() => setFile(null)} />
          ) : (
            <DropZone onFile={setFile} />
          )}
          <div className="options">
            <Segmented
              label="Expires"
              options={expiryOptions}
              value={expiresIn}
              onChange={setExpiresIn}
            />
            <Stepper
              label="Downloads"
              value={maxDownloads}
              min={1}
              max={100}
              onChange={setMaxDownloads}
            />
          </div>
          {password === null ? (
            <button
              type="button"
              className="link-btn"
              onClick={() => setPassword('')}
            >
              Add a password
            </button>
          ) : (
            <label className="field">
              <span id="password-label">Password</span>
              <input
                className="text"
                type="password"
                autoComplete="new-password"
                autoFocus
                aria-labelledby="password-label"
                aria-describedby="password-hint"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <span id="password-hint" className="hint">
                At least {MIN_PASSWORD_LENGTH} characters
              </span>
            </label>
          )}
          <Button onClick={start} disabled={!file || shortPassword}>
            Create link
          </Button>
        </section>
      )
  }
}

function DropZone({ onFile }: { onFile: (file: File) => void }) {
  const [active, setActive] = useState(false)

  function drop(event: DragEvent) {
    event.preventDefault()
    setActive(false)
    const dropped = event.dataTransfer.files[0]
    if (dropped) onFile(dropped)
  }

  function pick(event: ChangeEvent<HTMLInputElement>) {
    const picked = event.target.files?.[0]
    if (picked) onFile(picked)
  }

  return (
    <label
      className={`drop ${active ? 'active' : ''}`}
      onDragOver={(event) => {
        event.preventDefault()
        setActive(true)
      }}
      onDragLeave={() => setActive(false)}
      onDrop={drop}
    >
      <input type="file" onChange={pick} />
      <UploadIcon />
      <strong>Choose a file</strong>
      <span>or drop it here</span>
    </label>
  )
}

function FileRow({ file, onChange }: { file: File; onChange?: () => void }) {
  return (
    <div className="file">
      <FileIcon />
      <div>
        <div className="name">{file.name}</div>
        <div className="meta">{formatBytes(file.size)}</div>
      </div>
      {onChange && (
        <button type="button" className="change" onClick={onChange}>
          Change
        </button>
      )}
    </div>
  )
}

interface ResultProps {
  share: Share
  maxDownloads: number
  onDeleted: () => void
  onReset: () => void
}

function Result({ share, maxDownloads, onDeleted, onReset }: ResultProps) {
  const [copied, setCopied] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [deleteError, setDeleteError] = useState(false)
  const linkRef = useRef<HTMLElement>(null)
  const deleteRef = useRef<HTMLButtonElement>(null)
  const returnFocus = useRef(false)

  useEffect(() => {
    if (!confirming && returnFocus.current) {
      returnFocus.current = false
      deleteRef.current?.focus()
    }
  }, [confirming])

  async function copy() {
    try {
      await navigator.clipboard.writeText(share.link)
    } catch {
      // No clipboard access: leave the link selected for a manual copy.
      if (linkRef.current)
        window.getSelection()?.selectAllChildren(linkRef.current)
      return
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }

  function openConfirm() {
    setDeleteError(false)
    setConfirming(true)
  }

  function keep() {
    returnFocus.current = true
    setConfirming(false)
  }

  async function remove() {
    try {
      await deleteShareById(share.id, share.ownerToken)
      onDeleted()
    } catch (error) {
      // Already gone counts as deleted.
      if (error instanceof ApiError && error.status === 404) onDeleted()
      else setDeleteError(true)
    }
  }

  function onConfirmKey(event: KeyboardEvent) {
    if (event.key === 'Escape') keep()
  }

  const downloads =
    maxDownloads === 1 ? '1 download' : `${maxDownloads} downloads`
  return (
    <section className="card stack enter">
      <Hero icon={<CheckIcon />} title="Your link is ready" tone="ok" />
      <div className="share-link">
        <code ref={linkRef}>{share.link}</code>
        <Button variant="quiet" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <div className="summary">
        <span>
          Expires in {formatExpiry(share.expiresAt)} · {downloads}
          {share.protected && ' · Password'}
        </span>
      </div>
      {share.kept === true && (
        <Link to="/files" className="kept-note">
          Saved to My files
        </Link>
      )}
      {share.kept === false && (
        <p className="fine">Could not save it to My files.</p>
      )}
      <div className="field">
        <span>Delete link</span>
        <div className="share-link">
          <code>{share.deleteLink}</code>
          <Button variant="quiet" onClick={() => copyText(share.deleteLink)}>
            Copy
          </Button>
        </div>
      </div>
      {confirming ? (
        <div
          className="confirm"
          role="alertdialog"
          aria-label="Delete this file"
          aria-describedby="confirm-text"
          onKeyDown={onConfirmKey}
        >
          <span id="confirm-text">
            {deleteError
              ? 'Could not delete. Try again.'
              : 'Delete now? The link stops working.'}
          </span>
          <div>
            <Button variant="quiet" onClick={keep} autoFocus>
              Keep
            </Button>
            <Button variant="danger" onClick={remove}>
              Delete
            </Button>
          </div>
        </div>
      ) : (
        <div className="footer-actions">
          <button type="button" className="link-btn" onClick={onReset}>
            Share another file
          </button>
          <button
            type="button"
            className="link-btn danger"
            ref={deleteRef}
            onClick={openConfirm}
          >
            Delete file
          </button>
        </div>
      )}
    </section>
  )
}

function copyText(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'too_large') return 'This file is larger than the limit.'
    if (error.code === 'capacity')
      return 'The service is full right now. Try again later.'
    if (error.code === 'rate_limited')
      return 'Too many uploads from your network. Try again later.'
    if (error.code === 'network') return 'The server could not be reached.'
  }
  return 'Something went wrong. Nothing was shared.'
}
