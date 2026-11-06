import UploadPage from './pages/UploadPage.tsx'

export default function App() {
  return (
    <div className="app">
      <header className="brand">
        <a href="/">vault-share</a>
      </header>
      <main className="stage">
        <UploadPage />
      </main>
    </div>
  )
}
