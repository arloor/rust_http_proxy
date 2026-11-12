import { connection, isExtension, loadConnection } from './connection'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles.css'

void loadConnection().then(() => {
  if (isExtension) {
    document.title = `MITM · ${connection.origin}`
    const icon = document.createElement('link')
    icon.rel = 'icon'
    icon.href = chrome.runtime.getURL('icons/icon-32.png')
    document.head.append(icon)
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
})
