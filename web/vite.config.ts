import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': 'http://localhost:8080' },
    // vectors.html reads the test vectors kept beside web/.
    fs: { allow: ['.', '../testdata'] },
  },
  test: {
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
