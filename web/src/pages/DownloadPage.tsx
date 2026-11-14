import { useEffect, useRef, useState, type FormEvent } from 'react'
import { unwrapSecret } from '../crypto/index.ts'
import { ApiError } from '../http.ts'
import { formatBytes, formatExpiry, safeFileName } from '../share/format.ts'
import { parseLocation, type ShareLocation } from '../share/link.ts'
import { chooseSink, type Sink } from '../share/save.ts'
import {
  downloadShare,
  openShare,
  type Progress as ShareProgress,
  type ShareInfo,
} from '../share/share.ts'
import { Button, Hero, Progress } from '../ui/controls.tsx'
import { describeError } from '../ui/errors.ts'
import { CheckIcon, DownloadIcon, FileIcon, LinkOffIcon } from '../ui/icons.tsx'

type Phase =
  | { kind: 'loading' }
  | { kind: 'locked'; error?: string; busy: boolean }
  | { kind: 'invalid' }
  | { kind: 'unavailable' }
  | { kind: 'offline' }
  | { kind: 'ready'; info: ShareInfo }
  | { kind: 'downloading'; info: ShareInfo; progress: ShareProgress }
  | { kind: 'done'; info: ShareInfo; sink: Sink['kind'] }
  | { kind: 'failed'; info: ShareInfo; message: string; retry: boolean }

export default function DownloadPage() {
  const [location] = useState(() =>
    parseLocation(window.location.pathname, window.location.hash),
  )
  const [secret, setSecret] = useState(location?.secret ?? null)
  const [phase, setPhase] = useState(() => initialPhase(location))
  const [attempt, setAttempt] = useState(0)
  const busy = useRef(false)
  const granted = useRef<number | null>(null)

  // A corrected link pasted into the same tab changes only the fragment.
  useEffect(() => {
    const reload = () => window.location.reload()
    window.addEventListener('hashchange', reload)
    return () => window.removeEventListener('hashchange', reload)
  }, [])

  useEffect(() => {
    if (!location || !secret) return
    let cancelled = false
    openShare(location.id, secret)
      .then((info) => {
        if (!cancelled) setPhase({ kind: 'ready', info })
      })
      .catch((error: unknown) => {
        if (!cancelled) setPhase(openFailure(error))
      })
    return () => {
      cancelled = true
    }
  }, [location, secret, attempt])

  async function unlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!location?.wrapped) return
    const password = new FormData(event.currentTarget).get('password')
    if (typeof password !== 'string' || password === '') return
    setPhase({ kind: 'locked', busy: true })
    let unwrapped: Uint8Array<ArrayBuffer> | null
    try {
      unwrapped = await unwrapSecret(location.wrapped, password)
    } catch {
      // Argon2id needs 64 MiB, which a low-memory device may not grant.
      setPhase({
        kind: 'locked',
        error: 'Could not check the password on this device. Try again.',
        busy: false,
      })
      return
    }
    if (!unwrapped) {
      setPhase({
        kind: 'locked',
        error: 'Wrong password. Try again.',
        busy: false,
      })
      return
    }
    setPhase({ kind: 'loading' })
    setSecret(unwrapped)
  }

  function retryOpen() {
    setPhase({ kind: 'loading' })
    setAttempt((n) => n + 1)
  }

  async function download(info: ShareInfo) {
    if (busy.current) return
    busy.current = true
    granted.current = null
    try {
      const sink = await chooseSink(safeFileName(info.name))
      if (!sink) return
      setPhase({
        kind: 'downloading',
        info,
        progress: { phase: 'decrypting', fraction: 0 },
      })
      await downloadShare(
        info,
        sink,
        (progress) => {
          if (busy.current) setPhase({ kind: 'downloading', info, progress })
        },
        (left) => {
          granted.current = left
        },
      )
      setPhase({ kind: 'done', info, sink: sink.kind })
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        setPhase({ kind: 'unavailable' })
      } else {
        // After the last permitted download a retry would only get a 404,
        // but the failure itself, such as a damaged file, is still reported.
        setPhase({
          kind: 'failed',
          info,
          message: describeError(error, 'download'),
          retry: granted.current !== 0,
        })
      }
    } finally {
      busy.current = false
    }
  }

  switch (phase.kind) {
    case 'loading':
      return (
        <section key="loading" className="card stack" aria-busy="true">
          <div className="hero">
            <FileIcon />
            <div className="skeleton" />
          </div>
        </section>
      )
    case 'locked':
      return (
        <section key="locked" className="card stack enter">
          <Hero
            icon={<FileIcon />}
            title="This file is password protected"
            tone="muted"
          />
          <form className="stack" onSubmit={unlock}>
            <label className="field">
              <span id="unlock-label">Password</span>
              <input
                className="text"
                type="password"
                name="password"
                autoComplete="current-password"
                autoFocus
                required
                aria-labelledby="unlock-label"
                aria-invalid={phase.error ? true : undefined}
                aria-describedby={phase.error ? 'password-error' : undefined}
              />
              {phase.error && (
                <span id="password-error" className="error" role="alert">
                  {phase.error}
                </span>
              )}
            </label>
            <Button type="submit" disabled={phase.busy}>
              {phase.busy ? 'Unlocking…' : 'Unlock'}
            </Button>
          </form>
        </section>
      )
    case 'invalid':
      return (
        <section key="invalid" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="This link is incomplete"
            text="The key after # is missing or damaged. Ask for the link again."
            tone="muted"
          />
        </section>
      )
    case 'unavailable':
      return (
        <section key="unavailable" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="This file is no longer available"
            text="It expired, was downloaded the maximum number of times, or was deleted."
            tone="muted"
          />
        </section>
      )
    case 'offline':
      return (
        <section key="offline" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="The server could not be reached"
            tone="muted"
          />
          <Button onClick={retryOpen}>Try again</Button>
        </section>
      )
    case 'ready':
      return (
        <section key="ready" className="card stack enter">
          <FileHero info={phase.info} />
          <Button onClick={() => download(phase.info)}>
            <DownloadIcon /> Download
          </Button>
        </section>
      )
    case 'downloading':
      return (
        <section key="downloading" className="card stack">
          <FileHero info={phase.info} />
          <Progress label="Decrypting" fraction={phase.progress.fraction} />
        </section>
      )
    case 'done':
      return (
        <section key="done" className="card stack enter">
          <Hero
            icon={<CheckIcon />}
            title={safeFileName(phase.info.name)}
            text={
              phase.sink === 'file' ? 'Saved to your device.' : 'Downloaded.'
            }
            tone="ok"
          />
        </section>
      )
    case 'failed':
      return (
        <section key="failed" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="Download failed"
            text={
              phase.retry
                ? phase.message
                : `${phase.message} No downloads are left, so the link no longer works.`
            }
            tone="muted"
          />
          {phase.retry && (
            <Button onClick={() => download(phase.info)}>Try again</Button>
          )}
        </section>
      )
  }
}

function FileHero({ info }: { info: ShareInfo }) {
  const downloads =
    info.downloadsLeft === 1
      ? 'Last download'
      : `${info.downloadsLeft} downloads left`
  return (
    <Hero
      icon={<FileIcon />}
      title={safeFileName(info.name)}
      text={`${formatBytes(info.size)} · ${downloads} · Expires in ${formatExpiry(info.expiresAt)}`}
    />
  )
}

function initialPhase(location: ShareLocation | null): Phase {
  if (!location) return { kind: 'invalid' }
  if (location.wrapped) return { kind: 'locked', busy: false }
  return { kind: 'loading' }
}

function openFailure(error: unknown): Phase {
  if (error instanceof ApiError)
    return error.status === 404 ? { kind: 'unavailable' } : { kind: 'offline' }
  return { kind: 'invalid' }
}
