import { useState } from 'react'
import { describeError, type Task } from './errors.ts'

/** Runs a form's action and keeps its busy state and error. */
export function useAction(task: Task) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await action()
    } catch (failure) {
      setError(describeError(failure, task))
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, setError, run }
}
