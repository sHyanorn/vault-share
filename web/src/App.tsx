import DownloadPage from './pages/DownloadPage.tsx'
import UploadPage from './pages/UploadPage.tsx'
import { isDownloadPath } from './share/link.ts'

export default function App() {
  const download = isDownloadPath(window.location.pathname)
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
