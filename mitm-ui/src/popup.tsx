import { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, ApiError, type Settings, type Target } from './api'
import { connection, downloadCa, hostPermission, loadConnection, normalizeOrigin, saveConnection } from './connection'
import { StubRulesDialog } from './StubRules'
import './styles.css'
import './popup.css'

function TargetSettings({ caAvailable }: { caAvailable: boolean }) {
  const [targets, setTargets] = useState<Target[] | null>(null)
  const [suffix, setSuffix] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    api<Target[]>('/targets', { signal: controller.signal }).then(value => {
      setTargets(value)
      setExpanded(!value.some(target => target.enabled))
    }).catch(value => {
      if (!controller.signal.aborted) setError(value instanceof Error ? value.message : String(value))
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false)
    })
    return () => controller.abort()
  }, [])

  async function refresh() {
    setBusy(true)
    setError('')
    try { setTargets(await api<Target[]>('/targets')) }
    catch (value) { setError(value instanceof Error ? value.message : String(value)) }
    finally { setBusy(false) }
  }

  async function update(method: 'POST' | 'PATCH' | 'DELETE', target?: Target) {
    setBusy(true)
    setError('')
    try {
      const value = await api<Target | undefined>(target ? `/targets/${target.id}` : '/targets', {
        method,
        body: method === 'DELETE' ? undefined : JSON.stringify(target ? { enabled: !target.enabled } : { suffix: suffix.trim() }),
      })
      setTargets(current => {
        const remaining = (current ?? []).filter(item => item.id !== (target?.id ?? value?.id) && item.suffix !== value?.suffix)
        return value ? [...remaining, value].sort((left, right) => left.suffix.localeCompare(right.suffix)) : remaining
      })
      if (method === 'POST') setSuffix('')
    } catch (value) { setError(value instanceof Error ? value.message : String(value)) }
    finally { setBusy(false) }
  }

  const enabled = targets?.filter(target => target.enabled).length ?? 0
  return <section className="popup-targets" aria-label="MITM 解密域名后缀管理">
    <div className="popup-targets-head">
      <button aria-expanded={expanded} aria-controls="popup-targets-body" onClick={() => setExpanded(!expanded)}>
        {expanded ? '▾' : '▸'} 解密域名后缀{targets !== null ? ` · ${enabled}/${targets.length} 已启用` : ''}
      </button>
      <span>{targets === null ? '加载目标后缀后可管理' : enabled ? 'Stub 仅对已启用后缀覆盖的域名生效' : '尚无已启用后缀，Stub 不会对新连接生效'}</span>
      <button disabled={busy} onClick={() => void refresh()}>{busy ? '处理中…' : '刷新'}</button>
    </div>
    {!caAvailable && <div role="alert" className="popup-error">服务端 CA 不可用，请先配置 MITM CA；仅添加域名后缀无法启用 Stub。</div>}
    {error && <div role="alert" className="popup-error">{error}</div>}
    <div id="popup-targets-body" className="popup-targets-body" hidden={!expanded}>
      <form className="target-form" onSubmit={event => { event.preventDefault(); if (suffix.trim() && !busy) void update('POST') }}>
        <input required aria-label="新目标后缀" placeholder="example.com" disabled={busy || targets === null} value={suffix} onChange={event => setSuffix(event.target.value)} />
        <button type="submit" disabled={busy || targets === null || !suffix.trim()}>添加后缀</button>
      </form>
      <p className="popup-targets-hint">example.com 包含自身及子域名。客户端需信任 CA；更改后请重新建立连接，已建立的连接不受影响。</p>
      <div className="target-list">
        {targets?.map(target => <div className={`target ${target.enabled ? '' : 'off'}`} key={target.id}>
          <div className="target-main"><span title={target.suffix}>{target.suffix}</span>{target.cli_managed && <em>启动参数</em>}</div>
          <button className={`target-toggle ${target.enabled ? 'on' : ''}`} role="switch" aria-checked={target.enabled}
            aria-label={`${target.enabled ? '停用' : '启用'} ${target.suffix}`} disabled={busy}
            onClick={() => void update('PATCH', target)}><i /></button>
          {!target.cli_managed && <button className="target-remove" aria-label={`删除 ${target.suffix}`} disabled={busy}
            onClick={() => void update('DELETE', target)}>×</button>}
        </div>)}
        {targets?.length === 0 && <p className="popup-targets-hint">尚未配置目标后缀，请添加 Stub 请求对应的域名。</p>}
      </div>
    </div>
  </section>
}

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
    {settings && !busy ? <>
      <TargetSettings caAvailable={settings.ca_available} />
      <StubRulesDialog standalone onClose={() => {}} />
    </> : <div className="popup-empty">{busy ? '正在连接服务…' : '请在连接设置中配置服务地址和认证信息。'}</div>}
  </main>
}

document.documentElement.classList.add('stub-popup')
void loadConnection().then(() => createRoot(document.getElementById('root')!).render(<Popup />))
