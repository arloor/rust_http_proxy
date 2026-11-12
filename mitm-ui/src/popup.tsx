import { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, ApiError, type Settings } from './api'
import { connection, hostPermission, loadConnection, normalizeOrigin, saveConnection } from './connection'
import './popup.css'

function Popup() {
  const requestVersion = useRef(0)
  const [draft, setDraft] = useState({ ...connection })
  const [settings, setSettings] = useState<Settings | null>(null)
  const [status, setStatus] = useState('正在连接…')
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState(!connection.username || !connection.password)
  const error = (value: unknown) => { setSettings(null); setStatus(value instanceof ApiError && value.status === 401 ? '认证失败，请检查用户名和密码' : value instanceof TypeError ? '连接失败，请检查服务地址、访问权限及 HTTPS 证书信任' : value instanceof Error ? value.message : String(value)) }
  async function refresh() {
    const version = ++requestVersion.current
    try {
      const value = await api<Settings>('/settings', { signal: AbortSignal.timeout(8000) })
      if (version === requestVersion.current) { setSettings(value); setStatus('已连接') }
    } catch (value) { if (version === requestVersion.current) error(value) }
  }
  useEffect(() => { void refresh() }, [])
  async function connect(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    requestVersion.current++
    setSettings(null)
    setStatus('正在连接…')
    try {
      const origin = normalizeOrigin(draft.origin)
      if (draft.username.includes(':')) throw new Error('用户名不能包含冒号')
      if (!await chrome.permissions.request({ origins: [hostPermission(origin)] })) throw new Error('未获得服务地址访问权限')
      await saveConnection({ ...draft, origin })
      setDraft({ ...connection })
      await refresh()
    } catch (value) { error(value) } finally { setBusy(false) }
  }
  async function toggle() {
    if (!settings) return
    setBusy(true)
    try { setSettings(await api<Settings>('/settings', { method: 'PATCH', body: JSON.stringify({ capture_enabled: !settings.capture_enabled }), signal: AbortSignal.timeout(8000) })) } catch (value) { error(value) } finally { setBusy(false) }
  }
  return <main>
    <header><img className="logo" src="icons/icon-48.png" width="48" height="48" alt="MITM" /><div><h1>MITM 控制台</h1><small>rust_http_proxy</small></div></header>
    <section className="connection"><strong className={settings ? 'online' : ''}>{settings ? '● 已连接' : '○ 未连接'}</strong><span>{connection.origin}</span></section>
    <p role="status" className={settings ? 'hint' : 'error'}>{status}</p>
    <div className="capture"><div><b>明文抓取</b><small>{settings?.capture_cli_managed ? '由启动参数锁定' : '控制服务端请求记录'}</small></div><button disabled={!settings || busy || settings.capture_cli_managed} onClick={() => void toggle()}>{settings?.capture_enabled ? '关闭抓取' : '开启抓取'}</button></div>
    <button className="primary" onClick={() => void chrome.tabs.create({ url: chrome.runtime.getURL('index.html') }).then(() => window.close()).catch(error)}>打开完整管理页 ↗</button>
    <button className="text" onClick={() => setEditing(!editing)}>{editing ? '收起连接设置' : '连接设置 / 切换服务'}</button>
    {editing && <form onSubmit={event => void connect(event)}>
      <label>服务地址<input required type="url" value={draft.origin} onChange={event => setDraft({ ...draft, origin: event.target.value })} placeholder="https://127.0.0.1:444" /></label>
      <label>用户名<input required autoComplete="username" value={draft.username} onChange={event => setDraft({ ...draft, username: event.target.value })} /></label>
      <label>密码<input type="password" autoComplete="current-password" value={draft.password} onChange={event => setDraft({ ...draft, password: event.target.value })} /></label>
      <small>密码仅保留在本次浏览器会话中。切换服务后请重新打开管理页。</small>
      <button disabled={busy} type="submit">{busy ? '连接中…' : '保存并连接'}</button>
    </form>}
    <footer>需先运行 Rust 代理服务并信任其 HTTPS 证书。</footer>
  </main>
}

void loadConnection().then(() => createRoot(document.getElementById('root')!).render(<Popup />))
