import { useEffect, useState } from 'react'
import { ApiError } from '../share/api.ts'
import { formatBytes, formatExpiry, safeFileName } from '../share/format.ts'
import { parseLocation } from '../share/link.ts'
import { chooseSink } from '../share/save.ts'
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
  | { kind: 'ready'; info: ShareInfo }
  | { kind: 'downloading'; info: ShareInfo; progress: ShareProgress }
  | { kind: 'done'; info: ShareInfo }
  | { kind: 'failed'; info: ShareInfo; message: string }

export default function DownloadPage() {
  const [location] = useState(() =>
    parseLocation(window.location.pathname, window.location.hash),
  )
  const [phase, setPhase] = useState<Phase>(
    location ? { kind: 'loading' } : { kind: 'invalid' },
  )

  useEffect(() => {
    if (!location) return
    let cancelled = false
    openShare(location.id, location.secret)
      .then((info) => {
        if (!cancelled) setPhase({ kind: 'ready', info })
      })
      .catch((error: unknown) => {
        if (cancelled) return
        setPhase(
          error instanceof ApiError
            ? { kind: 'unavailable' }
            : { kind: 'invalid' },
        )
      })
    return () => {
      cancelled = true
    }
  }, [location])

  async function download(info: ShareInfo) {
    const sink = await chooseSink(safeFileName(info.name), info.type)
    if (!sink) return
    setPhase({
      kind: 'downloading',
      info,
      progress: { phase: 'downloading', fraction: 0 },
    })
    try {
      await downloadShare(info, sink, (progress) =>
        setPhase({ kind: 'downloading', info, progress }),
      )
      setPhase({ kind: 'done', info })
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        setPhase({ kind: 'unavailable' })
        return
      }
      setPhase({ kind: 'failed', info, message: describe(error) })
    }
  }

  switch (phase.kind) {
    case 'loading':
      return (
        <section className="card stack" aria-busy="true">
          <div className="hero">
            <FileIcon />
            <div className="skeleton" />
          </div>
        </section>
      )
    case 'invalid':
      return (
        <section className="card stack enter" role="alert">
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
        <section className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="This file is no longer available"
            text="It expired, was downloaded the maximum number of times, or was deleted."
            tone="muted"
          />
        </section>
      )
    case 'ready':
      return (
        <section className="card stack enter">
          <FileHero info={phase.info} />
          <Button onClick={() => download(phase.info)}>
            <DownloadIcon /> Download
          </Button>
        </section>
      )
    case 'downloading':
      return (
        <section className="card stack" aria-live="polite">
          <FileHero info={phase.info} />
          <Progress label="Decrypting" fraction={phase.progress.fraction} />
        </section>
      )
    case 'done':
      return (
        <section className="card stack enter">
          <Hero
            icon={<CheckIcon />}
            title={safeFileName(phase.info.name)}
            text="Saved to your device."
            tone="ok"
          />
        </section>
      )
    case 'failed':
      return (
        <section className="card stack enter" role="alert">
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

function describe(error: unknown): string {
  if (error instanceof ApiError && error.code === 'network')
    return 'The server could not be reached.'
  return 'The file could not be decrypted. Nothing was saved.'
}
