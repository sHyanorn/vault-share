import type { ButtonHTMLAttributes, ReactNode } from 'react'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'quiet' | 'danger'
}

export function Button({
  variant = 'primary',
  className = '',
  ...props
}: ButtonProps) {
  return (
    <button
      type="button"
      className={`btn ${variant} ${className}`}
      {...props}
    />
  )
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
    <label className="field">
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
    </label>
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
  return (
    <div className="field">
      <span>{label}</span>
      <div className="stepper" role="group" aria-label={label}>
        <button
          type="button"
          aria-label="Fewer"
          disabled={value <= min}
          onClick={() => onChange(value - 1)}
        >
          −
        </button>
        <output aria-live="polite">{value}</output>
        <button
          type="button"
          aria-label="More"
          disabled={value >= max}
          onClick={() => onChange(value + 1)}
        >
          +
        </button>
      </div>
    </div>
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
