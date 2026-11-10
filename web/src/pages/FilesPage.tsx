import { useEffect, useState, type CSSProperties } from 'react'
import type { Account } from '../account/account.ts'
import {
  listKept,
  type KeptFile,
  type UnreadableFile,
} from '../account/files.ts'
import { formatBytes, formatExpiry, safeFileName } from '../share/format.ts'
import { deleteShare } from '../share/share.ts'
import { Button, Hero } from '../ui/controls.tsx'
import { useCopy } from '../ui/copy.ts'
import { describeError } from '../ui/errors.ts'
import { FileIcon, LockIcon, TrashIcon } from '../ui/icons.tsx'
import { useRouter } from '../ui/router.ts'

type Listing =
  | { kind: 'loading' }
  | { kind: 'failed'; message: string }
  | { kind: 'ready'; files: (KeptFile | UnreadableFile)[]; more: boolean }

export default function FilesPage({ account }: { account: Account }) {
  const { navigate } = useRouter()
  const [listing, setListing] = useState<Listing>({ kind: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    listKept(account)
      .then(({ files, more }) => {
        if (!cancelled) setListing({ kind: 'ready', files, more })
      })
      .catch((error: unknown) => {
        if (!cancelled)
          setListing({
            kind: 'failed',
            message: describeError(error, 'account'),
          })
      })
    return () => {
      cancelled = true
    }
  }, [account, attempt])

  function removed(id: string) {
    setListing((current) =>
      current.kind === 'ready'
        ? { ...current, files: current.files.filter((f) => f.id !== id) }
        : current,
    )
  }

  const share = (
    <Button variant="quiet" onClick={() => navigate('/')}>
      Share a file
    </Button>
  )

  return (
    <section className="card stack enter wide">
      <div className="list-head">
        <h1>My files</h1>
        {listing.kind === 'ready' && listing.files.length > 0 && share}
      </div>
      {listing.kind === 'loading' && (
        <div className="kept-list" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <div key={i} className="kept placeholder">
              <FileIcon />
              <div className="skeleton" />
            </div>
          ))}
        </div>
      )}
      {listing.kind === 'failed' && (
        <div className="stack" role="alert">
          <Hero icon={<FileIcon />} title={listing.message} tone="muted" />
          <Button
            onClick={() => {
              setListing({ kind: 'loading' })
              setAttempt((n) => n + 1)
            }}
          >
            Try again
          </Button>
        </div>
      )}
      {listing.kind === 'ready' && listing.files.length === 0 && (
        <div className="stack empty">
          <Hero icon={<FileIcon />} title="No files yet" tone="muted" />
          <Button onClick={() => navigate('/')}>Share a file</Button>
        </div>
      )}
      {listing.kind === 'ready' && listing.files.length > 0 && (
        <ul className="kept-list">
          {listing.files.map((file, index) => (
            <Row
              key={file.id}
              file={file}
              index={index}
              onRemoved={() => removed(file.id)}
            />
          ))}
        </ul>
      )}
      {listing.kind === 'ready' && listing.more && (
        <p className="fine">Showing your newest 1,000 files.</p>
      )}
    </section>
  )
}

/** How long a deleted row takes to leave; index.css reads it as --leave. */
const leaveMs = 200

interface RowProps {
  file: KeptFile | UnreadableFile
  index: number
  onRemoved: () => void
}

function Row({ file, index, onRemoved }: RowProps) {
  const [confirming, setConfirming] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const [failed, setFailed] = useState(false)
  const { copied, copy } = useCopy()
  const delay = { animationDelay: `${Math.min(index, 8) * 30}ms` }

  if (file.unreadable)
    return (
      <li className="kept unreadable enter" style={delay}>
        <FileIcon />
        <div className="info">
          <div className="name">Unreadable file</div>
          <div className="meta">Expires in {formatExpiry(file.expiresAt)}</div>
        </div>
      </li>
    )

  async function remove() {
    if (file.unreadable) return
    setFailed(false)
    try {
      await deleteShare(file.id, file.ownerToken)
    } catch {
      setFailed(true)
      return
    }
    setLeaving(true)
    setTimeout(onRemoved, leaveMs + 20)
  }

  const name = safeFileName(file.name)
  const downloads =
    file.downloadsLeft === 1
      ? '1 download left'
      : `${file.downloadsLeft} downloads left`
  return (
    <li
      className={`kept enter ${leaving ? 'leaving' : ''}`}
      style={{ ...delay, '--leave': `${leaveMs}ms` } as CSSProperties}
    >
      <FileIcon />
      <div className="info">
        <div className="name" title={name}>
          <span className="title">{name}</span>
          {file.protected && (
            <span className="badge" aria-label="Password protected">
              <LockIcon />
            </span>
          )}
        </div>
        <div className="meta">
          {formatBytes(file.size)} ·{' '}
          {file.uploaded
            ? `${downloads} · Expires in ${formatExpiry(file.expiresAt)}`
            : 'Not uploaded'}
        </div>
      </div>
      {confirming ? (
        <div
          className="row-confirm"
          role="alertdialog"
          aria-label={`Delete ${name}`}
          onKeyDown={(event) => {
            if (event.key === 'Escape') setConfirming(false)
          }}
        >
          <span>{failed ? 'Could not delete' : 'Delete?'}</span>
          <Button
            variant="quiet"
            onClick={() => setConfirming(false)}
            autoFocus
          >
            Keep
          </Button>
          <Button variant="danger" onClick={remove}>
            Delete
          </Button>
        </div>
      ) : (
        <div className="row-actions">
          {file.uploaded && (
            <Button
              variant="quiet"
              onClick={() => copy(file.link)}
              aria-label={copied ? 'Copied' : `Copy link to ${name}`}
            >
              {copied ? (
                'Copied'
              ) : (
                <>
                  <span className="wide-only">Copy link</span>
                  <span className="narrow-only">Copy</span>
                </>
              )}
            </Button>
          )}
          <button
            type="button"
            className="icon-btn"
            aria-label={`Delete ${name}`}
            onClick={() => setConfirming(true)}
          >
            <TrashIcon />
          </button>
        </div>
      )}
    </li>
  )
}
