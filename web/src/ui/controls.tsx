import {
  useEffect,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from 'react'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'quiet' | 'danger'
}

export function Button({ variant = 'primary', ...props }: ButtonProps) {
  return <button type="button" className={`btn ${variant}`} {...props} />
}

interface SegmentedProps<T extends string | number> {
  label: string
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
}

export function Segmented<T extends string | number>({
  label,
  options,
  value,
  onChange,
}: SegmentedProps<T>) {
  return (
    <div className="field">
      <span>{label}</span>
      <div className="segmented" role="group" aria-label={label}>
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            aria-pressed={option.value === value}
            onClick={() => onChange(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  )
}

interface StepperProps {
  label: string
  value: number
  min: number
  max: number
  onChange: (value: number) => void
}

export function Stepper({ label, value, min, max, onChange }: StepperProps) {
  // The field is uncontrolled while typing and commits on blur or Enter;
  // the key remounts it when the buttons change the value.
  function commit(input: HTMLInputElement) {
    const n = Number(input.value)
    if (input.value !== '' && Number.isInteger(n))
      onChange(Math.min(max, Math.max(min, n)))
    else input.value = String(value)
  }

  return (
    <label className="field">
      <span>{label}</span>
      <div className="stepper">
        <button
          type="button"
          aria-label="Fewer"
          disabled={value <= min}
          onClick={() => onChange(value - 1)}
        >
          −
        </button>
        <input
          key={value}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          defaultValue={value}
          onBlur={(event) => commit(event.target)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') event.currentTarget.blur()
          }}
        />
        <button
          type="button"
          aria-label="More"
          disabled={value >= max}
          onClick={() => onChange(value + 1)}
        >
          +
        </button>
      </div>
    </label>
  )
}

interface ProgressProps {
  label: string
  fraction: number
}

export function Progress({ label, fraction }: ProgressProps) {
  const percent = Math.round(fraction * 100)
  return (
    <div
      className="progress"
      role="progressbar"
      aria-label={label}
      aria-valuenow={percent}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className="row">
        <span>{label}</span>
        <span>{percent}%</span>
      </div>
      <div className="track">
        <div className="fill" style={{ transform: `scaleX(${fraction})` }} />
      </div>
    </div>
  )
}

interface HeroProps {
  icon: ReactNode
  title: string
  text?: ReactNode
  tone?: 'accent' | 'muted' | 'ok'
}

export function Hero({ icon, title, text, tone = 'accent' }: HeroProps) {
  return (
    <div className={`hero ${tone}`}>
      {icon}
      <h1>{title}</h1>
      {text && <p>{text}</p>}
    </div>
  )
}

/** How long a Collapse takes to close; index.css reads it as --collapse. */
const collapseMs = 240

/**
 * Opens and closes its content by its height. Closed content stays a
 * moment for the animation, then leaves, so a form opened again is fresh.
 */
export function Collapse({
  open,
  children,
}: {
  open: boolean
  children: ReactNode
}) {
  const [wasOpen, setWasOpen] = useState(open)
  const [closing, setClosing] = useState(false)
  // Whether the closed state has been painted, so opening can animate.
  const [raised, setRaised] = useState(open)
  if (open !== wasOpen) {
    setWasOpen(open)
    setClosing(!open)
    if (open) setRaised(false)
  }

  useEffect(() => {
    if (!open || raised) return
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => setRaised(true))
    })
    return () => cancelAnimationFrame(frame)
  }, [open, raised])

  useEffect(() => {
    if (!closing) return
    const timer = setTimeout(() => setClosing(false), collapseMs + 20)
    return () => clearTimeout(timer)
  }, [closing])

  if (!open && !closing) return null
  return (
    <div
      className={`collapse ${open && raised ? 'shown' : ''}`}
      style={{ '--collapse': `${collapseMs}ms` } as CSSProperties}
      inert={!open}
    >
      <div className="collapse-inner">{children}</div>
    </div>
  )
}
