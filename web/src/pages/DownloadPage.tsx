import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../share/api.ts'
import { formatBytes, formatExpiry, safeFileName } from '../share/format.ts'
import { parseLocation } from '../share/link.ts'
import { chooseSink, type Sink } from '../share/save.ts'
import {
  downloadShare,
  openShare,
  type Progress as ShareProgress,
  type ShareInfo,
} from '../share/share.ts'
import { Button, Hero, Progress } from '../ui/controls.tsx'
import { CheckIcon, DownloadIcon, FileIcon, LinkOffIcon } from '../ui/icons.tsx'

type Phase =
  | { kind: 'loading' }
  | { kind: 'invalid' }
  | { kind: 'unavailable' }
  | { kind: 'offline' }
  | { kind: 'ready'; info: ShareInfo }
  | { kind: 'downloading'; info: ShareInfo; progress: ShareProgress }
  | { kind: 'done'; info: ShareInfo; sink: Sink['kind'] }
  | { kind: 'failed'; info: ShareInfo; message: string }

export default function DownloadPage() {
  const [location] = useState(() =>
    parseLocation(window.location.pathname, window.location.hash),
  )
  const [phase, setPhase] = useState<Phase>(
    location ? { kind: 'loading' } : { kind: 'invalid' },
  )
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
    if (!location) return
    let cancelled = false
    openShare(location.id, location.secret)
      .then((info) => {
        if (!cancelled) setPhase({ kind: 'ready', info })
      })
      .catch((error: unknown) => {
        if (!cancelled) setPhase(openFailure(error))
      })
    return () => {
      cancelled = true
    }
  }, [location, attempt])

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
      // Gone, or this was the last permitted download: nothing to retry.
      if (
        (error instanceof ApiError && error.status === 404) ||
        granted.current === 0
      ) {
        setPhase({ kind: 'unavailable' })
      } else {
        setPhase({ kind: 'failed', info, message: describe(error) })
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
            text={phase.message}
            tone="muted"
          />
          <Button onClick={() => download(phase.info)}>Try again</Button>
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

function openFailure(error: unknown): Phase {
  if (error instanceof ApiError)
    return error.status === 404 ? { kind: 'unavailable' } : { kind: 'offline' }
  return { kind: 'invalid' }
}

function describe(error: unknown): string {
  if (error instanceof ApiError) return 'The server could not be reached.'
  if (error instanceof TypeError)
    return 'The connection was interrupted. The download was discarded.'
  return 'The file could not be decrypted. The download was discarded.'
}
