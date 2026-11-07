const base = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
  className: 'icon',
} as const

export function UploadIcon() {
  return (
    <svg {...base}>
      <circle cx="12" cy="12" r="9.5" />
      <path d="M12 16.5v-9M8.5 11 12 7.5l3.5 3.5" />
    </svg>
  )
}

export function FileIcon() {
  return (
    <svg {...base}>
      <path d="M7 3.5h6.5L18 8v11a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 6 19V5A1.5 1.5 0 0 1 7.5 3.5Z" />
      <path d="M13.5 3.5V8H18" />
    </svg>
  )
}

export function DownloadIcon() {
  return (
    <svg {...base}>
      <circle cx="12" cy="12" r="9.5" />
      <path d="M12 7.5v9M8.5 13l3.5 3.5 3.5-3.5" />
    </svg>
  )
}

export function CheckIcon() {
  return (
    <svg {...base}>
      <circle cx="12" cy="12" r="9.5" />
      <path d="m8 12.5 2.5 2.5L16 9.5" />
    </svg>
  )
}

export function LinkOffIcon() {
  return (
    <svg {...base}>
      <path d="M10 14a4 4 0 0 0 5.7 0l2-2a4 4 0 0 0-5.7-5.7l-1 1" />
      <path d="M14 10a4 4 0 0 0-5.7 0l-2 2a4 4 0 0 0 5.7 5.7l1-1" />
      <path d="m4 4 16 16" />
    </svg>
  )
}
