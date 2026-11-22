import { useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, ApiError, type Settings, type Target } from './api'
import { connection, downloadCa, hostPermission, loadConnection, normalizeOrigin, saveConnection } from './connection'
import { StubRulesDialog } from './StubRules'
import { TargetDeleteButton } from './TargetDeleteButton'
import './styles.css'
import './popup.css'

type TargetsSummary = { enabled: number; total: number } | null

function TargetSettings({
  caAvailable,
  expanded,
  onSummaryChange,
}: {
  caAvailable: boolean
  expanded: boolean
  onSummaryChange: (summary: TargetsSummary) => void
}) {
  const [targets, setTargets] = useState<Target[] | null>(null)
  const [suffix, setSuffix] = useState('')
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    api<Target[]>('/targets', { signal: controller.signal }).then(value => {
      setTargets(value)
    }).catch(value => {
      if (!controller.signal.aborted) setError(value instanceof Error ? value.message : String(value))
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false)
    })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (targets === null) {
      onSummaryChange(null)
    } else {
      onSummaryChange({
        enabled: targets.filter(target => target.enabled).length,
        total: targets.length,
      })
    }
  }, [targets, onSummaryChange])

  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(''), 2200)
    return () => window.clearTimeout(timer)
  }, [notice])

  async function refresh() {
    setBusy(true)
    setError('')
    try { setTargets(await api<Target[]>('/targets')) }
    catch (value) { setError(value instanceof Error ? value.message : String(value)) }
    finally { setBusy(false) }
  }

  async function update(method: 'POST' | 'PATCH', target?: Target) {
    setBusy(true)
    setError('')
    try {
      const value = await api<Target | undefined>(target ? `/targets/${target.id}` : '/targets', {
        method,
        body: JSON.stringify(target ? { enabled: !target.enabled } : { suffix: suffix.trim() }),
      })
      setTargets(current => {
        const remaining = (current ?? []).filter(item => item.id !== (target?.id ?? value?.id) && item.suffix !== value?.suffix)
        return value ? [...remaining, value].sort((left, right) => left.suffix.localeCompare(right.suffix)) : remaining
      })
      if (method === 'POST' && value) {
        setSuffix('')
        setNotice(`已添加 ${value.suffix}，新连接生效`)
      }
    } catch (value) { setError(value instanceof Error ? value.message : String(value)) }
    finally { setBusy(false) }
  }

  const enabled = targets?.filter(target => target.enabled).length ?? 0
  return <section id="popup-targets" className="popup-targets" aria-label="MITM 解密域名后缀管理" hidden={!expanded}>
    <div className="popup-targets-head">
      <strong>{targets !== null ? `已启用 ${enabled}/${targets.length}` : '解密域名后缀'}</strong>
      <span className={targets !== null && enabled === 0 ? 'warn' : ''}>
        {targets === null ? '加载目标后缀后可管理' : enabled ? 'Stub 仅对已启用后缀覆盖的域名生效' : '尚无已启用后缀，Stub 不会对新连接生效'}
      </span>
      <button type="button" className="popup-btn-ghost" disabled={busy} onClick={() => void refresh()}>{busy ? '刷新中…' : '刷新'}</button>
    </div>
    {!caAvailable && <div role="alert" className="popup-error">服务端 CA 不可用，请先配置 MITM CA；仅添加域名后缀无法启用 Stub。</div>}
    {error && <div role="alert" className="popup-error"><span>{error}</span><button type="button" className="popup-alert-close" aria-label="关闭提示" onClick={() => setError('')}>×</button></div>}
    {notice && <div role="status" className="popup-notice">{notice}</div>}
    <div className="popup-targets-body">
      <form className="target-form" onSubmit={event => { event.preventDefault(); if (suffix.trim() && !busy) void update('POST') }}>
        <span className="clearable">
          <input required aria-label="新目标后缀" placeholder="输入域名后缀，例如 example.com" disabled={busy || targets === null} value={suffix} onChange={event => setSuffix(event.target.value)} />
          {suffix && <button type="button" className="input-clear" aria-label="清空" tabIndex={-1} onClick={() => setSuffix('')}>×</button>}
        </span>
        <button type="submit" disabled={busy || targets === null || !suffix.trim()}>添加后缀</button>
      </form>
      <p className="popup-targets-hint">example.com 包含自身及子域名。客户端需信任 CA；更改后请重新建立连接，已建立的连接不受影响。</p>
      <div className="target-list">
        {targets?.map(target => <div className={`target ${target.enabled ? '' : 'off'}`} key={target.id}>
          <div className="target-main"><span title={target.suffix}>{target.suffix}</span>{target.cli_managed && <em>启动参数</em>}</div>
          <button type="button" className={`target-toggle ${target.enabled ? 'on' : ''}`} role="switch" aria-checked={target.enabled}
            aria-label={`${target.enabled ? '停用' : '启用'} ${target.suffix}`} disabled={busy}
            onClick={() => void update('PATCH', target)}><i /></button>
          {!target.cli_managed && <TargetDeleteButton suffix={target.suffix} disabled={busy} onDelete={async () => {
            await api<void>(`/targets/${target.id}`, { method: 'DELETE' })
            setTargets(current => current?.filter(item => item.id !== target.id) ?? null)
          }} />}
        </div>)}
        {targets?.length === 0 && <p className="popup-targets-empty">尚未配置目标后缀，请添加 Stub 请求对应的域名。</p>}
      </div>
    </div>
  </section>
}

function Popup() {
  const hasSavedSession = Boolean(connection.username && connection.password)
  const requestVersion = useRef(0)
  const [draft, setDraft] = useState({ ...connection })
  const [showPassword, setShowPassword] = useState(false)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [status, setStatus] = useState(
    hasSavedSession ? '正在连接…' : connection.username ? '请输入会话密码重新连接' : '请配置服务地址与认证信息',
  )
  const [connectError, setConnectError] = useState('')
  const [busy, setBusy] = useState(false)
  const [connecting, setConnecting] = useState(hasSavedSession)
  const [networkError, setNetworkError] = useState(false)
  const [caBusy, setCaBusy] = useState(false)
  const [caError, setCaError] = useState('')
  const [caNotice, setCaNotice] = useState('')
  const [editing, setEditing] = useState(!hasSavedSession)
  const [targetsExpanded, setTargetsExpanded] = useState(false)
  const [targetsSummary, setTargetsSummary] = useState<TargetsSummary>(null)

  const handleTargetsSummary = useCallback((summary: TargetsSummary) => {
    setTargetsSummary(summary)
  }, [])

  const applyError = useCallback((value: unknown) => {
    const isNetwork = value instanceof TypeError
    const message = value instanceof ApiError && value.status === 401
      ? '认证失败，请检查用户名和密码'
      : isNetwork
        ? '连接失败，请检查服务地址、访问权限及 HTTPS 证书信任'
        : value instanceof Error ? value.message : String(value)
    setNetworkError(isNetwork)
    setSettings(null)
    setStatus(message)
    setConnectError(message)
    setTargetsSummary(null)
  }, [])

  const refresh = useCallback(async () => {
    const version = ++requestVersion.current
    setConnecting(true)
    try {
      const value = await api<Settings>('/settings', { signal: AbortSignal.timeout(8000) })
      if (version === requestVersion.current) {
        setSettings(value)
        setStatus('已连接')
        setConnectError('')
        setNetworkError(false)
        setEditing(false)
        return true
      }
      return false
    } catch (value) {
      if (version === requestVersion.current) applyError(value)
      return false
    } finally {
      if (version === requestVersion.current) setConnecting(false)
    }
  }, [applyError])

  useEffect(() => {
    if (hasSavedSession) void refresh()
  }, [hasSavedSession, refresh])

  useEffect(() => {
    if (!caNotice) return
    const timer = window.setTimeout(() => setCaNotice(''), 2400)
    return () => window.clearTimeout(timer)
  }, [caNotice])

  async function connect(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    requestVersion.current++
    setSettings(null)
    setTargetsSummary(null)
    setStatus('正在连接…')
    setConnectError('')
    setNetworkError(false)
    setCaError('')
    setTargetsExpanded(false)
    try {
      const origin = normalizeOrigin(draft.origin.trim())
      if (draft.username.includes(':')) throw new Error('用户名不能包含冒号')
      if (!await chrome.permissions.request({ origins: [hostPermission(origin)] })) throw new Error('未获得服务地址访问权限')
      await saveConnection({ ...draft, origin })
      setDraft({ ...connection })
      await refresh()
    } catch (value) {
      applyError(value)
    } finally {
      setBusy(false)
    }
  }

  async function downloadCertificate() {
    setCaBusy(true)
    setCaError('')
    try {
      await downloadCa()
      setCaNotice('CA 证书已开始下载（mitm-ca.crt）')
    } catch (value) {
      setCaError(value instanceof TypeError
        ? 'CA 下载失败：请检查网络、访问权限及服务端 HTTPS 证书信任。服务证书未受信任时，扩展也无法下载 CA，请先在浏览器中检查服务地址。'
        : value instanceof Error ? value.message : String(value))
    } finally {
      setCaBusy(false)
    }
  }

  function toggleTargets() {
    setTargetsExpanded(current => {
      const next = !current
      if (next) setEditing(false)
      return next
    })
  }

  function toggleEditing() {
    setEditing(current => {
      const next = !current
      if (next) {
        setTargetsExpanded(false)
        setDraft({ ...connection })
      }
      return next
    })
  }

  const targetBadgeWarn = targetsSummary !== null && targetsSummary.enabled === 0

  return <main className="popup-shell">
    <header className="popup-header">
      <div className="popup-brand">
        <img src="icons/icon-48.png" width="24" height="24" alt="MITM" />
        <div className="popup-brand-text">
          <strong>MITM · Stub 规则</strong>
          <span className="popup-origin" title={connection.origin}>{connection.origin}</span>
        </div>
      </div>
      <span role="status" className={`popup-status ${settings ? 'online' : connecting || busy ? 'connecting' : 'offline'}`} title={status}>
        <i aria-hidden="true" />
        {settings ? '已连接' : connecting || busy ? '连接中…' : '未连接'}
      </span>
      <div className="popup-header-actions">
        <button
          type="button"
          className={`popup-btn ${targetsExpanded ? 'active' : ''}`}
          disabled={!settings || busy}
          aria-expanded={targetsExpanded}
          aria-controls="popup-targets"
          title="管理 MITM 解密域名后缀"
          onClick={toggleTargets}
        >
          <span>解密域名后缀</span>
          {targetsSummary !== null && (
            <b className={`popup-badge ${targetBadgeWarn ? 'warn' : ''}`}>{targetsSummary.enabled}/{targetsSummary.total}</b>
          )}
        </button>
        <button
          type="button"
          className="popup-btn"
          disabled={caBusy || busy || !connection.username || settings?.ca_available === false}
          title={settings?.ca_available === false ? '服务端未提供 CA 证书' : '下载 MITM CA 证书'}
          onClick={() => void downloadCertificate()}
        >
          {caBusy ? '下载中…' : '下载 CA 证书'}
        </button>
        <button
          type="button"
          className={`popup-btn ${editing ? 'active' : ''}`}
          aria-expanded={editing}
          onClick={toggleEditing}
        >
          {editing ? '收起连接设置' : '连接设置'}
        </button>
      </div>
    </header>

    {connectError && !busy && !connecting && <div role="alert" className="popup-error">
      <div className="popup-error-content">
        <div>{connectError}</div>
        {networkError && connection.origin.startsWith('https:') && <div className="popup-error-hint">
          HTTPS 证书未受信任也会导致此错误，扩展无法区分证书、网络或权限问题。请先打开服务地址检查证书信任；MITM CA 下载后需导入系统并信任。
          <button type="button" className="popup-error-link" onClick={() => void chrome.tabs.create({ url: connection.origin }).catch(applyError)}>检查服务证书 ↗</button>
        </div>}
      </div>
      <button type="button" className="popup-alert-close" aria-label="关闭错误" onClick={() => setConnectError('')}>×</button>
    </div>}
    {caError && <div role="alert" className="popup-error">
      <div className="popup-error-content">{caError}</div>
      <button type="button" className="popup-alert-close" aria-label="关闭错误" onClick={() => setCaError('')}>×</button>
    </div>}
    {caNotice && <div role="status" className="popup-notice">{caNotice}</div>}

    {editing && <form className="popup-connection" onSubmit={event => void connect(event)}>
      <label className="popup-field-origin">
        <span>服务地址</span>
        <input
          required
          type="url"
          autoFocus={!connection.username}
          value={draft.origin}
          onChange={event => setDraft({ ...draft, origin: event.target.value })}
          placeholder="https://127.0.0.1:444"
        />
      </label>
      <label>
        <span>用户名</span>
        <input
          required
          autoComplete="username"
          value={draft.username}
          onChange={event => setDraft({ ...draft, username: event.target.value })}
          placeholder="admin"
        />
      </label>
      <label>
        <span>密码</span>
        <span className="popup-password-wrap">
          <input
            type={showPassword ? 'text' : 'password'}
            autoFocus={Boolean(connection.username && !connection.password)}
            autoComplete="current-password"
            value={draft.password}
            onChange={event => setDraft({ ...draft, password: event.target.value })}
            placeholder="本次会话密码"
          />
          <button
            type="button"
            className="popup-pw-toggle"
            aria-label={showPassword ? '隐藏密码' : '显示密码'}
            title={showPassword ? '隐藏密码' : '显示密码'}
            onClick={() => setShowPassword(current => !current)}
          >{showPassword ? '隐藏' : '显示'}</button>
        </span>
      </label>
      <div className="popup-connection-actions">
        <button className="popup-primary" disabled={busy} type="submit">{busy ? '连接中…' : '保存并连接'}</button>
        {settings && <button type="button" className="popup-btn-ghost" disabled={busy} onClick={() => setEditing(false)}>取消</button>}
      </div>
      <small>密码仅保存在当前浏览器会话内存中，不落盘。重新连接会重载规则列表，请先保存编辑。</small>
    </form>}

    {settings && !busy ? <>
      <TargetSettings caAvailable={settings.ca_available} expanded={targetsExpanded} onSummaryChange={handleTargetsSummary} />
      <StubRulesDialog standalone onClose={() => {}} />
    </> : (
      <div className="popup-empty">
        <div className="popup-empty-card">
          {busy || connecting ? (
            <>
              <span className="loading-spinner" aria-hidden="true" />
              <strong>正在连接 MITM 服务…</strong>
              <p>{connection.origin}</p>
            </>
          ) : (
            <>
              <strong>{connection.username ? '会话密码已过期，请重新验证' : '连接到 rust_http_proxy'}</strong>
              <p>{connection.username
                ? `已记住服务地址 ${connection.origin} 与用户名 ${connection.username}，在上方输入密码即可恢复连接。`
                : '在上方填写代理管理地址（不含 /mitm 路径）与 Basic Auth 账号密码，即可快速管理 Stub 规则与解密域名后缀。'}</p>
            </>
          )}
        </div>
      </div>
    )}
  </main>
}

document.documentElement.classList.add('stub-popup')
void loadConnection().then(() => createRoot(document.getElementById('root')!).render(<Popup />))
