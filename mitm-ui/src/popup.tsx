import { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, ApiError, type Settings } from './api'
import { connection, downloadCa, hostPermission, loadConnection, normalizeOrigin, saveConnection } from './connection'
import { StubRulesDialog } from './StubRules'
import './styles.css'
import './popup.css'

function Popup() {
  const requestVersion = useRef(0)
  const [draft, setDraft] = useState({ ...connection })
  const [settings, setSettings] = useState<Settings | null>(null)
  const [status, setStatus] = useState('正在连接…')
  const [busy, setBusy] = useState(false)
  const [networkError, setNetworkError] = useState(false)
  const [caBusy, setCaBusy] = useState(false)
  const [caError, setCaError] = useState('')
  const [editing, setEditing] = useState(!connection.username || !connection.password)
  const error = (value: unknown) => { setNetworkError(value instanceof TypeError); setSettings(null); setStatus(value instanceof ApiError && value.status === 401 ? '认证失败，请检查用户名和密码' : value instanceof TypeError ? '连接失败，请检查服务地址、访问权限及 HTTPS 证书信任' : value instanceof Error ? value.message : String(value)) }
  async function refresh() {
    const version = ++requestVersion.current
    try {
      const value = await api<Settings>('/settings', { signal: AbortSignal.timeout(8000) })
      if (version === requestVersion.current) { setSettings(value); setStatus('已连接'); setNetworkError(false) }
    } catch (value) { if (version === requestVersion.current) error(value) }
  }
  useEffect(() => { void refresh() }, [])
  async function connect(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    requestVersion.current++
    setSettings(null)
    setStatus('正在连接…')
    setNetworkError(false)
    setCaError('')
    try {
      const origin = normalizeOrigin(draft.origin)
      if (draft.username.includes(':')) throw new Error('用户名不能包含冒号')
      if (!await chrome.permissions.request({ origins: [hostPermission(origin)] })) throw new Error('未获得服务地址访问权限')
      await saveConnection({ ...draft, origin })
      setDraft({ ...connection })
      await refresh()
    } catch (value) { error(value) } finally { setBusy(false) }
  }
  async function downloadCertificate() {
    setCaBusy(true)
    setCaError('')
    try { await downloadCa() } catch (value) {
      setCaError(value instanceof TypeError
        ? 'CA 下载失败：请检查网络、访问权限及服务端 HTTPS 证书信任。服务证书未受信任时，扩展也无法下载 CA，请先在浏览器中检查服务地址。'
        : value instanceof Error ? value.message : String(value))
    } finally { setCaBusy(false) }
  }
  return <main className="popup-shell">
    <header className="popup-header">
      <img src="icons/icon-48.png" width="28" height="28" alt="MITM" />
      <strong>MITM · Stub 规则</strong>
      <span role="status" className={`popup-status ${settings ? 'online' : 'offline'}`} title={status}>{settings ? '● 已连接' : status === '正在连接…' ? '连接中…' : '○ 未连接'}</span>
      <span className="popup-origin" title={connection.origin}>{connection.origin}</span>
      <button disabled={caBusy || busy || !connection.username || settings?.ca_available === false} title={settings?.ca_available === false ? '服务端未提供 CA 证书' : '下载 MITM CA 证书'} onClick={() => void downloadCertificate()}>{caBusy ? '下载中…' : '下载 CA 证书'}</button>
      <button aria-expanded={editing} onClick={() => setEditing(!editing)}>{editing ? '收起连接设置' : '连接设置'}</button>
    </header>
    {!settings && status !== '正在连接…' && <div role="alert" className="popup-error">
      <div>{status}</div>
      {networkError && connection.origin.startsWith('https:') && <div>
        HTTPS 证书未受信任也会导致此错误，扩展无法区分证书、网络或权限问题。
        请先打开服务地址检查证书信任；MITM CA 下载后需导入系统并信任，服务端 HTTPS 证书也需单独确认。
        <button onClick={() => void chrome.tabs.create({ url: connection.origin }).catch(error)}>检查服务证书 ↗</button>
      </div>}
    </div>}
    {caError && <div role="alert" className="popup-error">{caError}</div>}
    {editing && <form className="popup-connection" onSubmit={event => void connect(event)}>
      <label>服务地址<input required type="url" value={draft.origin} onChange={event => setDraft({ ...draft, origin: event.target.value })} placeholder="https://127.0.0.1:444" /></label>
      <label>用户名<input required autoComplete="username" value={draft.username} onChange={event => setDraft({ ...draft, username: event.target.value })} /></label>
      <label>密码<input type="password" autoComplete="current-password" value={draft.password} onChange={event => setDraft({ ...draft, password: event.target.value })} /></label>
      <button disabled={busy} type="submit">{busy ? '连接中…' : '保存并连接'}</button>
      <small>密码仅保留在本次浏览器会话中。重新连接会重载规则，请先保存编辑。</small>
    </form>}
    {settings && !busy ? <StubRulesDialog standalone onClose={() => {}} /> : <div className="popup-empty">{busy ? '正在连接服务…' : '请在连接设置中配置服务地址和认证信息。'}</div>}
  </main>
}

document.documentElement.classList.add('stub-popup')
void loadConnection().then(() => createRoot(document.getElementById('root')!).render(<Popup />))
