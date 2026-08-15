import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  api,
  fullUrl,
  type HostGroup,
  type RecordDetail,
  type RecordPage,
  type RecordSummary,
  type Settings,
  type Target,
} from './api'

const methods = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']

function formatTime(value: number) {
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
  }).format(value)
}

function App() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [groups, setGroups] = useState<HostGroup[]>([])
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [nextBefore, setNextBefore] = useState<number | null>(null)
  const [selected, setSelected] = useState<RecordDetail | null>(null)
  const [host, setHost] = useState('')
  const [path, setPath] = useState('')
  const [method, setMethod] = useState('')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  const [newTarget, setNewTarget] = useState('')
  const [error, setError] = useState('')
  const refreshTimer = useRef<number | null>(null)
  const selectedIdRef = useRef<string | null>(null)
  const loadedCountRef = useRef(0)

  useEffect(() => {
    selectedIdRef.current = selected?.id ?? null
  }, [selected])

  const queryString = useMemo(() => {
    const params = new URLSearchParams()
    if (host) params.set('host', host)
    if (path) params.set('path', path)
    if (method) params.set('method', method)
    if (status) params.set('status', status)
    if (search) params.set('q', search)
    return params.toString()
  }, [host, path, method, status, search])

  const handleError = useCallback((value: unknown) => {
    setError(value instanceof Error ? value.message : String(value))
  }, [])

  const refreshMeta = useCallback(async () => {
    try {
      const [nextSettings, nextTargets, nextGroups] = await Promise.all([
        api<Settings>('/settings'),
        api<Target[]>('/targets'),
        api<HostGroup[]>('/groups'),
      ])
      setSettings(nextSettings)
      setTargets(nextTargets)
      setGroups(nextGroups)
      setError('')
    } catch (value) {
      handleError(value)
    }
  }, [handleError])

  const refreshRecords = useCallback(
    async (includeDetail = false) => {
      try {
        // 已经「加载更早记录」时按已加载条数拉取，避免刷新后列表缩回第一页导致跳动
        const limit = Math.min(Math.max(loadedCountRef.current, 100), 1000)
        const page = await api<RecordPage>(`/records?limit=${limit}&${queryString}`)
        loadedCountRef.current = page.records.length
        setRecords(page.records)
        setNextBefore(page.next_before)
        const id = selectedIdRef.current
        if (includeDetail && id) {
          const detail = await api<RecordDetail>(`/records/${id}`).catch(() => null)
          if (detail === null) {
            setSelected(null)
          } else {
            // 内容没变就不触发重渲染，避免详情面板闪烁
            setSelected((current) =>
              current && JSON.stringify(current) === JSON.stringify(detail) ? current : detail,
            )
          }
        }
        setError('')
      } catch (value) {
        handleError(value)
      }
    },
    [handleError, queryString],
  )

  useEffect(() => {
    void refreshMeta()
  }, [refreshMeta])

  useEffect(() => {
    void refreshRecords(true)
  }, [refreshRecords])

  useEffect(() => {
    const source = new EventSource('/mitm/api/events')
    let needRecords = false
    let needMeta = false
    let includeDetail = false
    const schedule = () => {
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current)
      refreshTimer.current = window.setTimeout(() => {
        const pending = needRecords ? refreshRecords(includeDetail) : Promise.resolve()
        void pending.then(() => (needMeta ? refreshMeta() : undefined))
        needRecords = needMeta = includeDetail = false
      }, 250)
    }
    const onRecordEvent = (event: MessageEvent) => {
      needRecords = true
      try {
        const data = JSON.parse(event.data) as { record_id?: string }
        // 只有当前选中记录有更新时才重新拉取详情
        if (data.record_id && data.record_id === selectedIdRef.current) includeDetail = true
      } catch {
        includeDetail = true
      }
      schedule()
    }
    const onMetaEvent = () => {
      needMeta = true
      schedule()
    }
    const onFullEvent = () => {
      needRecords = needMeta = includeDetail = true
      schedule()
    }
    source.addEventListener('record_created', onRecordEvent)
    source.addEventListener('record_updated', onRecordEvent)
    source.addEventListener('settings', onMetaEvent)
    source.addEventListener('targets', onMetaEvent)
    source.addEventListener('records_cleared', onFullEvent)
    source.addEventListener('resync', onFullEvent)
    source.onerror = () => setError('实时连接暂时中断，浏览器正在自动重连')
    return () => {
      source.close()
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current)
    }
  }, [refreshMeta, refreshRecords])

  async function updateSettings(patch: Partial<Settings>) {
    try {
      setSettings(await api<Settings>('/settings', { method: 'PATCH', body: JSON.stringify(patch) }))
      setError('')
    } catch (value) {
      handleError(value)
    }
  }

  async function addTarget(event: FormEvent) {
    event.preventDefault()
    if (!newTarget.trim()) return
    try {
      await api<Target>('/targets', { method: 'POST', body: JSON.stringify({ suffix: newTarget }) })
      setNewTarget('')
      await refreshMeta()
    } catch (value) {
      handleError(value)
    }
  }

  async function selectRecord(id: string) {
    try {
      setSelected(await api<RecordDetail>(`/records/${id}`))
      setError('')
    } catch (value) {
      handleError(value)
    }
  }

  async function loadMore() {
    if (nextBefore === null) return
    try {
      const page = await api<RecordPage>(`/records?limit=100&${queryString}&before=${nextBefore}`)
      loadedCountRef.current += page.records.length
      setRecords((current) => [...current, ...page.records])
      setNextBefore(page.next_before)
    } catch (value) {
      handleError(value)
    }
  }

  async function clearRecords() {
    if (!window.confirm('确定清空所有 MITM 明文记录吗？此操作不可撤销。')) return
    try {
      await api<void>('/records', { method: 'DELETE' })
      loadedCountRef.current = 0
      setRecords([])
      setSelected(null)
      await refreshMeta()
    } catch (value) {
      handleError(value)
    }
  }

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">RUST HTTP PROXY</p>
          <h1>MITM Observatory</h1>
        </div>
        <div className="status-line">
          <span className={`dot ${settings?.ca_available ? 'online' : 'offline'}`} />
          {settings?.ca_available ? 'CA READY' : 'CA UNAVAILABLE'}
          <span className="live-pill">● LIVE</span>
        </div>
      </header>

      {error && <div className="error-banner">{error}<button onClick={() => setError('')}>×</button></div>}

      <section className="control-strip">
        <Toggle
          label="明文抓取"
          checked={settings?.capture_enabled ?? false}
          onChange={(checked) => void updateSettings({ capture_enabled: checked })}
        />
        <label className="number-control">留存记录
          <input
            aria-label="留存记录"
            type="number"
            min="1"
            value={settings?.max_records ?? 10000}
            onChange={(event) => setSettings((current) => current && { ...current, max_records: Number(event.target.value) })}
            onBlur={(event) => void updateSettings({ max_records: Number(event.target.value) })}
          />
        </label>
        <label className="number-control">Body 上限
          <select
            aria-label="Body 上限"
            value={settings?.body_limit_bytes ?? 65536}
            onChange={(event) => void updateSettings({ body_limit_bytes: Number(event.target.value) })}
          >
            <option value={16384}>16 KiB</option><option value={65536}>64 KiB</option>
            <option value={262144}>256 KiB</option><option value={1048576}>1 MiB</option>
          </select>
        </label>
      </section>

      <section className="workspace">
        <aside className="sidebar">
          <div className="panel-title"><span>目标域名</span><b>{targets.length}</b></div>
          <form className="target-form" onSubmit={addTarget}>
            <input aria-label="新目标后缀" placeholder="example.com" value={newTarget} onChange={(e) => setNewTarget(e.target.value)} />
            <button type="submit">添加</button>
          </form>
          <div className="target-list">
            {targets.map((target) => (
              <div className="target" key={target.id}><div className="target-main"><span>{target.suffix}</span>{target.cli_managed && <em>启动参数</em>}</div>
                {!target.cli_managed && <button aria-label={`删除 ${target.suffix}`} onClick={() => void api<void>(`/targets/${target.id}`, { method: 'DELETE' }).then(refreshMeta).catch(handleError)}>×</button>}
              </div>
            ))}
            {!targets.length && <p className="empty">尚未配置目标后缀</p>}
          </div>
          <div className="panel-title group-title"><span>URL 分类</span><b>{groups.length}</b></div>
          <button className={!host ? 'group active' : 'group'} onClick={() => { setHost(''); setPath('') }}>全部请求</button>
          {groups.map((group) => (
            <div key={group.host} className="group-block">
              <button className={host === group.host && !path ? 'group active' : 'group'} onClick={() => { setHost(group.host); setPath('') }}>
                <span>{group.host}</span><b>{group.count}</b>
              </button>
              {host === group.host && group.paths.map((item) => (
                <button key={item.path} className={path === item.path ? 'path active' : 'path'} onClick={() => setPath(item.path)}>
                  <span>{item.path}</span><b>{item.count}</b>
                </button>
              ))}
            </div>
          ))}
        </aside>

        <section className="records-panel">
          <div className="filters">
            <input aria-label="搜索 URL" placeholder="搜索 URL…" value={search} onChange={(e) => setSearch(e.target.value)} />
            <select aria-label="请求方法" value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((item) => <option key={item} value={item}>{item || '全部方法'}</option>)}</select>
            <input aria-label="状态码" className="status-input" placeholder="状态码" value={status} onChange={(e) => setStatus(e.target.value.replace(/\D/g, '').slice(0, 3))} />
            <button className="danger" onClick={() => void clearRecords()}>清空</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>时间</th><th>方法</th><th>URL</th><th>状态</th><th>耗时</th><th>抓取</th></tr></thead>
              <tbody>
                {records.map((record) => (
                  <tr key={record.id} className={selected?.id === record.id ? 'selected' : ''} onClick={() => void selectRecord(record.id)}>
                    <td className="mono muted">{formatTime(record.started_at_ms)}</td>
                    <td><span className={`method method-${record.method.toLowerCase()}`}>{record.method}</span></td>
                    <td className="url-cell"><strong>{record.host}</strong><span>{record.path}{record.query ? `?${record.query}` : ''}</span></td>
                    <td className={`mono status-${Math.floor((record.status ?? 0) / 100)}`}>{record.status ?? '…'}</td>
                    <td className="mono muted">{record.duration_ms === null ? '…' : `${record.duration_ms}ms`}</td>
                    <td><span className={`state state-${record.capture_state}`}>{record.capture_state}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!records.length && <div className="empty-table"><span>◎</span><p>等待 MITM 流量</p><small>命中目标的 HTTPS 请求会实时出现在这里</small></div>}
          </div>
          {nextBefore !== null && <button className="load-more" onClick={() => void loadMore()}>加载更早记录</button>}
        </section>

        <Detail detail={selected} onClose={() => setSelected(null)} />
      </section>
    </main>
  )
}

function Toggle({ label, checked, disabled, onChange }: { label: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return <label className={`toggle-control ${disabled ? 'disabled' : ''}`}><span>{label}</span>
    <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    <i aria-hidden="true" />
  </label>
}

function Detail({ detail, onClose }: { detail: RecordDetail | null; onClose: () => void }) {
  const [tab, setTab] = useState<'request' | 'response'>('request')
  useEffect(() => setTab('request'), [detail?.id])
  if (!detail) return <aside className="detail empty-detail"><span>↗</span><p>选择一条记录查看明文</p></aside>
  const request = tab === 'request'
  const headers = request ? detail.request_headers : detail.response_headers
  const body = request ? detail.request_body : detail.response_body
  const note = request ? detail.request_body_note : detail.response_body_note
  const bytes = request ? detail.request_body_bytes : detail.response_body_bytes
  return <aside className="detail">
    <div className="detail-head"><div><span className={`method method-${detail.method.toLowerCase()}`}>{detail.method}</span><b>{detail.status ?? 'PENDING'}</b></div><button aria-label="关闭详情" onClick={onClose}>×</button></div>
    <p className="detail-url">{fullUrl(detail)}</p>
    <div className="detail-meta"><span>{detail.client_ip}</span><span>{detail.proxy_username}</span><span>{detail.duration_ms ?? '…'} ms</span></div>
    <div className="tabs"><button className={tab === 'request' ? 'active' : ''} onClick={() => setTab('request')}>Request</button><button className={tab === 'response' ? 'active' : ''} onClick={() => setTab('response')}>Response</button></div>
    <h3>Headers</h3>
    <pre>{headers.map(([name, value]) => `${name}: ${value}`).join('\n') || '(none)'}</pre>
    <h3>Body <small>{bytes} bytes seen</small></h3>
    {note && <div className="note">{note}</div>}
    <pre className="body-content">{body || '(empty)'}</pre>
    {detail.error && <div className="note error-note">{detail.error}</div>}
  </aside>
}

export default App
