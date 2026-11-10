import { useState } from 'react'
import { parseDeleteLocation } from '../share/link.ts'
import { deleteShare } from '../share/share.ts'
import { Button, Hero } from '../ui/controls.tsx'
import { describeError } from '../ui/errors.ts'
import { CheckIcon, LinkOffIcon, FileIcon } from '../ui/icons.tsx'

type Phase = 'confirm' | 'working' | 'deleted' | 'gone' | 'invalid' | 'failed'

export default function DeletePage() {
  const [location] = useState(() =>
    parseDeleteLocation(window.location.pathname, window.location.hash),
  )
  const [phase, setPhase] = useState<Phase>(location ? 'confirm' : 'invalid')
  const [failure, setFailure] = useState('')

  async function remove() {
    if (!location) return
    setPhase('working')
    try {
      const deleted = await deleteShare(location.id, location.ownerToken)
      setPhase(deleted ? 'deleted' : 'gone')
    } catch (error) {
      setFailure(describeError(error, 'delete'))
      setPhase('failed')
    }
  }

  switch (phase) {
    case 'invalid':
      return (
        <section key="invalid" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="This link is incomplete"
            text="The token after # is missing or damaged."
            tone="muted"
          />
        </section>
      )
    case 'deleted':
      return (
        <section key="deleted" className="card stack enter">
          <Hero
            icon={<CheckIcon />}
            title="Deleted"
            text="The share link no longer works."
            tone="ok"
          />
        </section>
      )
    case 'gone':
      return (
        <section key="gone" className="card stack enter">
          <Hero
            icon={<LinkOffIcon />}
            title="Already gone"
            text="This file had expired, was downloaded the maximum number of times, or was deleted."
            tone="muted"
          />
        </section>
      )
    case 'failed':
      return (
        <section key="failed" className="card stack enter" role="alert">
          <Hero
            icon={<LinkOffIcon />}
            title="Could not delete"
            text={failure}
            tone="muted"
          />
          <Button onClick={remove}>Try again</Button>
        </section>
      )
    default:
      return (
        <section key="confirm" className="card stack enter">
          <Hero
            icon={<FileIcon />}
            title="Delete this file?"
            text="The share link stops working immediately. This cannot be undone."
            tone="muted"
          />
          <Button
            variant="danger"
            onClick={remove}
            disabled={phase === 'working'}
          >
            Delete file
          </Button>
        </section>
      )
  }
}
