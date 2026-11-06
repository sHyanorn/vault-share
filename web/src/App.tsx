import { useEffect } from 'react'
import DownloadPage from './pages/DownloadPage.tsx'
import UploadPage from './pages/UploadPage.tsx'
import { isDownloadPath } from './share/link.ts'

export default function App() {
  const download = isDownloadPath(window.location.pathname)

  // A file dropped outside the drop zone must not replace the app.
  useEffect(() => {
    const swallow = (event: DragEvent) => event.preventDefault()
    window.addEventListener('dragover', swallow)
    window.addEventListener('drop', swallow)
    return () => {
      window.removeEventListener('dragover', swallow)
      window.removeEventListener('drop', swallow)
    }
  }, [])

  return (
    <div className="app">
      <header className="brand">
        <a href="/">vault-share</a>
      </header>
      <main className="stage">
        {download ? <DownloadPage /> : <UploadPage />}
      </main>
    </div>
  )
}
