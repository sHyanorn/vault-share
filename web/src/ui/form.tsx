import type { InputHTMLAttributes, ReactNode } from 'react'

type InputProps = InputHTMLAttributes<HTMLInputElement>

interface PasswordFieldProps extends InputProps {
  name: string
  label: string
  hint?: ReactNode
  error?: string | null
}

export function PasswordField({
  name,
  label,
  hint,
  error,
  ...input
}: PasswordFieldProps) {
  const described = error ? `${name}-error` : hint && `${name}-hint`
  return (
    <label className="field">
      <span id={`${name}-label`}>{label}</span>
      <input
        className="text"
        type="password"
        name={name}
        required
        aria-labelledby={`${name}-label`}
        aria-invalid={error ? true : undefined}
        aria-describedby={described || undefined}
        {...input}
      />
      {hint && (
        <span id={`${name}-hint`} className="hint">
          {hint}
        </span>
      )}
      <FieldError id={`${name}-error`} error={error} />
    </label>
  )
}

interface CodeFieldProps extends InputProps {
  label?: string
  error?: string | null
}

/** A code from an authenticator app, or a recovery code. */
export function CodeField({ label = 'Code', error, ...input }: CodeFieldProps) {
  return (
    <label className="field">
      <span id="code-label">{label}</span>
      <input
        className="text code"
        name="code"
        required
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        aria-labelledby="code-label"
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? 'code-error' : undefined}
        {...input}
      />
      <FieldError id="code-error" error={error} />
    </label>
  )
}

function FieldError({ id, error }: { id: string; error?: string | null }) {
  return error ? (
    <span id={id} className="error" role="alert">
      {error}
    </span>
  ) : null
}

export function FormError({ error }: { error: string | null }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null
}
