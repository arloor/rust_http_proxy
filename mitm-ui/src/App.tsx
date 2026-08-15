import { FormEvent, type MouseEvent as ReactMouseEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import {
  formatBytes,
  formatCaptureState,
  formatDuration,
  formatTime,
  prettyBody,
  statusTone,
  toCurl,
} from './format'

const methods = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization'])

function App() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [groups, setGroups] = useState<HostGroup[]>([])
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [nextBefore, setNextBefore] = useState<number | null>(null)
  const [selected, setSelected] = useState<RecordDetail | null>(null)
  const [host, setHost] = useState('')
  const [expandedHost, setExpandedHost] = useState('')
  const [path, setPath] = useState('')
  const [method, setMethod] = useState('')
  const [status, setStatus] = useState('')
  const [clientIpInput, setClientIpInput] = useState('')
  const [clientIp, setClientIp] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [groupFilter, setGroupFilter] = useState('')
  const [sidebarWidth, setSidebarWidth] = useState(250)
  const [detailWidth, setDetailWidth] = useState(420)
  const [newTarget, setNewTarget] = useState('')
  const [error, setError] = useState('')
  const [live, setLive] = useState(false)
  const [copied, setCopied] = useState('')
  const refreshTimer = useRef<number | null>(null)
  const selectedIdRef = useRef<string | null>(null)
  const loadedCountRef = useRef(0)
  const queryStringRef = useRef('')
  const copyTimer = useRef<number | null>(null)
  const recordsRef = useRef<RecordSummary[]>([])
  const tableWrapRef = useRef<HTMLDivElement>(null)
  const pinToLatestRef = useRef(true)
  const nextBeforeRef = useRef<number | null>(null)
  const loadingMoreRef = useRef(false)
  const [pinToLatest, setPinToLatest] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [detailLoadingId, setDetailLoadingId] = useState<string | null>(null)
  const detailRequestRef = useRef(0)
  const activeRecordIdRef = useRef<string | null>(null)

  const activeRecordId = detailLoadingId ?? selected?.id ?? null
  const loadingRecord = detailLoadingId
    ? records.find((record) => record.id === detailLoadingId) ?? null
    : null
  const showDetail = detailLoadingId !== null || selected !== null

  useEffect(() => {
    selectedIdRef.current = selected?.id ?? null
  }, [selected])

  useEffect(() => {
    activeRecordIdRef.current = activeRecordId
  }, [activeRecordId])

  useEffect(() => {
    recordsRef.current = records
    if (pinToLatestRef.current) tableWrapRef.current?.scrollTo({ top: 0 })
  }, [records])

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput.trim()), 280)
    return () => window.clearTimeout(timer)
  }, [searchInput])

  useEffect(() => {
    const timer = window.setTimeout(() => setClientIp(clientIpInput.trim()), 280)
    return () => window.clearTimeout(timer)
  }, [clientIpInput])

  const queryString = useMemo(() => {
    const params = new URLSearchParams()
    if (host) params.set('host', host)
    if (path) params.set('path', path)
    if (method) params.set('method', method)
    if (status) params.set('status', status)
    if (clientIp) params.set('client_ip', clientIp)
    if (search) params.set('q', search)
    return params.toString()
  }, [host, path, method, status, clientIp, search])

  queryStringRef.current = queryString

  const handleError = useCallback((value: unknown) => {
    setError(value instanceof Error ? value.message : String(value))
  }, [])

  // 栏宽拖拽：direction=1 表示向右拖变宽（左栏），-1 表示向左拖变宽（右栏）
  const startColumnResize = useCallback(
    (event: ReactMouseEvent, startWidth: number, direction: 1 | -1, min: number, max: number, apply: (width: number) => void) => {
      event.preventDefault()
      const startX = event.clientX
      const onMove = (moveEvent: MouseEvent) => {
        apply(Math.min(max, Math.max(min, startWidth + direction * (moveEvent.clientX - startX))))
      }
      const onUp = () => {
        document.body.classList.remove('col-resizing')
        window.removeEventListener('mousemove', onMove)
        window.removeEventListener('mouseup', onUp)
      }
      document.body.classList.add('col-resizing')
      window.addEventListener('mousemove', onMove)
      window.addEventListener('mouseup', onUp)
    },
    [],
  )

  const copyText = useCallback(async (value: string, label: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        fallbackCopy(value)
      }
      setCopied(label)
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current)
      copyTimer.current = window.setTimeout(() => setCopied(''), 1600)
    } catch {
      try {
        fallbackCopy(value)
        setCopied(label)
      } catch (error) {
        handleError(error)
      }
    }
  }, [handleError])

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
    } catch (value) {
      handleError(value)
    }
  }, [handleError])

  const refreshGroups = useCallback(async () => {
    try {
      setGroups(await api<HostGroup[]>('/groups'))
    } catch (value) {
      handleError(value)
    }
  }, [handleError])

  const refreshRecords = useCallback(
    async (includeDetail = false) => {
      try {
        const qs = queryStringRef.current
        // 已经「加载更早记录」时按已加载条数拉取，避免刷新后列表缩回第一页导致跳动
        const limit = Math.min(Math.max(loadedCountRef.current, 100), 1000)
        const page = await api<RecordPage>(`/records?limit=${limit}&${qs}`)
        loadedCountRef.current = page.records.length
        setRecords(page.records)
        nextBeforeRef.current = page.next_before
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
      } catch (value) {
        handleError(value)
      }
    },
    [handleError],
  )

  useEffect(() => {
    void refreshMeta()
  }, [refreshMeta])

  useEffect(() => {
    loadedCountRef.current = 0
    pinToLatestRef.current = true
    setPinToLatest(true)
    void refreshRecords(true)
  }, [queryString, refreshRecords])

  useEffect(() => {
    const source = new EventSource('/mitm/api/events')
    let needRecords = false
    let needMeta = false
    let needGroups = false
    let includeDetail = false
    const schedule = () => {
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current)
      refreshTimer.current = window.setTimeout(() => {
        const pending = needRecords ? refreshRecords(includeDetail) : Promise.resolve()
        void pending.then(() => {
          if (needMeta) return refreshMeta()
          if (needGroups) return refreshGroups()
          return undefined
        })
        needRecords = needMeta = needGroups = includeDetail = false
      }, 250)
    }
    const onRecordEvent = (event: MessageEvent) => {
      needRecords = true
      if (event.type === 'record_created') needGroups = true
      try {
        const data = JSON.parse(event.data) as { record_id?: string }
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
    source.addEventListener('open', () => setLive(true))
    source.addEventListener('record_created', onRecordEvent)
    source.addEventListener('record_updated', onRecordEvent)
    source.addEventListener('settings', onMetaEvent)
    source.addEventListener('targets', onMetaEvent)
    source.addEventListener('records_cleared', onFullEvent)
    source.addEventListener('resync', onFullEvent)
    source.onerror = () => setLive(false)
    return () => {
      source.close()
      if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current)
    }
  }, [refreshGroups, refreshMeta, refreshRecords])

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
    const requestId = ++detailRequestRef.current
    activeRecordIdRef.current = id
    setDetailLoadingId(id)
    try {
      const detail = await api<RecordDetail>(`/records/${id}`)
      if (requestId !== detailRequestRef.current) return
      setSelected(detail)
      setError('')
    } catch (value) {
      if (requestId !== detailRequestRef.current) return
      activeRecordIdRef.current = selectedIdRef.current
      handleError(value)
    } finally {
      if (requestId === detailRequestRef.current) setDetailLoadingId(null)
    }
  }

  const closeDetail = useCallback(() => {
    detailRequestRef.current += 1
    activeRecordIdRef.current = null
    setDetailLoadingId(null)
    setSelected(null)
  }, [])

  const loadMore = useCallback(async () => {
    const before = nextBeforeRef.current
    if (before === null || loadingMoreRef.current) return
    loadingMoreRef.current = true
    setLoadingMore(true)
    try {
      const page = await api<RecordPage>(`/records?limit=100&${queryStringRef.current}&before=${before}`)
      loadedCountRef.current += page.records.length
      nextBeforeRef.current = page.next_before
      setRecords((current) => [...current, ...page.records])
      setNextBefore(page.next_before)
    } catch (value) {
      handleError(value)
    } finally {
      loadingMoreRef.current = false
      setLoadingMore(false)
    }
  }, [handleError])

  async function clearRecords() {
    if (!window.confirm('确定清空所有 MITM 明文记录吗？此操作不可撤销。')) return
    try {
      await api<void>('/records', { method: 'DELETE' })
      loadedCountRef.current = 0
      nextBeforeRef.current = null
      setRecords([])
      setNextBefore(null)
      setSelected(null)
      await refreshMeta()
    } catch (value) {
      handleError(value)
    }
  }

  function resetFilters() {
    setHost('')
    setExpandedHost('')
    setPath('')
    setMethod('')
    setStatus('')
    setClientIpInput('')
    setClientIp('')
    setSearchInput('')
    setSearch('')
    pinToLatestRef.current = true
    setPinToLatest(true)
  }

  function onTableScroll() {
    const el = tableWrapRef.current
    if (!el) return
    const nearTop = el.scrollTop <= 32
    if (nearTop !== pinToLatestRef.current) {
      pinToLatestRef.current = nearTop
      setPinToLatest(nearTop)
    }
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= 80
    if (nearBottom) void loadMore()
  }

  function jumpToLatest() {
    pinToLatestRef.current = true
    setPinToLatest(true)
    tableWrapRef.current?.scrollTo({ top: 0 })
  }

  const moveSelection = useCallback((delta: number) => {
    const list = recordsRef.current
    if (!list.length) return
    const index = list.findIndex((record) => record.id === activeRecordIdRef.current)
    const next = list[Math.min(list.length - 1, Math.max(0, (index < 0 ? 0 : index) + delta))]
    if (next) void selectRecord(next.id)
  }, [])

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (target.closest('input, textarea, select, [contenteditable="true"]')) return
      if (event.key === 'Escape') {
        closeDetail()
        return
      }
      if (event.key === 'ArrowDown' || event.key === 'j') {
        event.preventDefault()
        moveSelection(1)
      } else if (event.key === 'ArrowUp' || event.key === 'k') {
        event.preventDefault()
        moveSelection(-1)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [closeDetail, moveSelection])

  const hasFilters = Boolean(host || path || method || status || clientIp || search)
  const emptyHint = hasFilters ? '没有匹配的记录' : '等待 MITM 流量'
  const emptySub = hasFilters ? '试试放宽筛选条件' : '命中目标的 HTTPS 请求会实时出现在这里'

  // URL 分类前端搜索：host 命中保留全部 path，仅 path 命中则只展示匹配的 path
  const groupQuery = groupFilter.trim().toLowerCase()
  const filteredGroups = useMemo(() => {
    if (!groupQuery) return groups
    const result: HostGroup[] = []
    for (const group of groups) {
      if (group.host.toLowerCase().includes(groupQuery)) {
        result.push(group)
        continue
      }
      const paths = group.paths.filter((item) => item.path.toLowerCase().includes(groupQuery))
      if (paths.length) result.push({ ...group, paths })
    }
    return result
  }, [groups, groupQuery])

  return (
    <main>
      {error && <div className="error-banner">{error}<button onClick={() => setError('')}>×</button></div>}
      {copied && <div className="copy-toast" role="status">{copied} 已复制</div>}

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
        <div className="status-line">
          <span className={`ca-pill ${settings?.ca_available ? 'online' : 'offline'}`}>
            <span className={`dot ${settings?.ca_available ? 'online' : 'offline'}`} />
            {settings?.ca_available ? 'CA 可用' : 'CA 不可用'}
          </span>
          <span className={`live-pill ${live ? 'on' : 'off'}`}>{live ? '● 实时' : '○ 重连中'}</span>
          <span className="record-count">{records.length} 条记录</span>
        </div>
      </section>

      <section
        className={`workspace ${showDetail ? 'has-detail' : ''}`}
        style={{
          gridTemplateColumns: showDetail
            ? `${sidebarWidth}px 6px minmax(360px, 1fr) 6px ${detailWidth}px`
            : `${sidebarWidth}px 6px minmax(470px, 1fr)`,
        }}
      >
        <aside className="sidebar">
          <div className="panel-title"><span>目标域名</span><b>{targets.length}</b></div>
          <form className="target-form" onSubmit={addTarget}>
            <input aria-label="新目标后缀" placeholder="example.com" value={newTarget} onChange={(e) => setNewTarget(e.target.value)} />
            <button type="submit">添加</button>
          </form>
          <div className="target-list">
            {targets.map((target) => (
              <div className={`target ${host === target.suffix ? 'active' : ''}`} key={target.id}>
                <button className="target-main" onClick={() => { setHost(target.suffix); setExpandedHost(''); setPath('') }} title="按该后缀筛选">
                  <span>{target.suffix}</span>
                  {target.cli_managed && <em>启动参数</em>}
                </button>
                {!target.cli_managed && (
                  <button
                    className="target-remove"
                    aria-label={`删除 ${target.suffix}`}
                    onClick={() => void api<void>(`/targets/${target.id}`, { method: 'DELETE' }).then(refreshMeta).catch(handleError)}
                  >×</button>
                )}
              </div>
            ))}
            {!targets.length && <p className="empty">尚未配置目标后缀</p>}
          </div>
          <div className="panel-title group-title"><span>URL 分类</span><b>{groupQuery ? `${filteredGroups.length}/${groups.length}` : groups.length}</b></div>
          <input
            aria-label="搜索 URL 分类"
            className="group-search"
            placeholder="搜索 host / path…"
            value={groupFilter}
            onChange={(e) => setGroupFilter(e.target.value)}
          />
          <button className={!host ? 'group active' : 'group'} onClick={() => { setHost(''); setExpandedHost(''); setPath('') }}>全部请求</button>
          {filteredGroups.map((group) => {
            const expanded = groupQuery ? true : expandedHost === group.host
            return (
            <div key={group.host} className="group-block">
              <button
                className={host === group.host && !path ? 'group active' : 'group'}
                aria-expanded={expanded}
                onClick={() => {
                  setHost(group.host)
                  setPath('')
                  setExpandedHost((current) => current === group.host ? '' : group.host)
                }}
              >
                <span>{group.host}</span><b>{group.count}</b>
              </button>
              {expanded && group.paths.map((item) => (
                <button key={item.path} className={path === item.path ? 'path active' : 'path'} onClick={() => setPath(item.path)}>
                  <span>{item.path}</span><b>{item.count}</b>
                </button>
              ))}
            </div>
            )
          })}
          {groupQuery && !filteredGroups.length && <p className="empty">没有匹配的分类</p>}
        </aside>

        <div
          className="col-resizer"
          role="separator"
          aria-orientation="vertical"
          aria-label="调整侧栏宽度"
          onMouseDown={(event) => startColumnResize(event, sidebarWidth, 1, 180, 480, setSidebarWidth)}
        />

        <section className="records-panel">
          <div className="filters">
            <input aria-label="搜索 URL" placeholder="搜索 URL…" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} />
            <input aria-label="客户端 IP" className="client-ip-input" placeholder="客户端 IP" value={clientIpInput} onChange={(e) => setClientIpInput(e.target.value)} />
            <select aria-label="请求方法" value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((item) => <option key={item} value={item}>{item || '全部方法'}</option>)}</select>
            <input aria-label="状态码" className="status-input" placeholder="状态码" value={status} onChange={(e) => setStatus(e.target.value.replace(/\D/g, '').slice(0, 3))} />
            <button className="danger" onClick={() => void clearRecords()}>清空</button>
          </div>
          {hasFilters && (
            <div className="filter-chips">
              {host && <button onClick={() => { setHost(''); setExpandedHost(''); setPath('') }}>host: {host} ×</button>}
              {path && <button onClick={() => setPath('')}>path: {path} ×</button>}
              {method && <button onClick={() => setMethod('')}>{method} ×</button>}
              {status && <button onClick={() => setStatus('')}>状态 {status} ×</button>}
              {clientIp && <button onClick={() => { setClientIpInput(''); setClientIp('') }}>客户端 {clientIp} ×</button>}
              {search && <button onClick={() => { setSearchInput(''); setSearch('') }}>搜索 “{search}” ×</button>}
              <button className="reset" onClick={resetFilters}>清除筛选</button>
            </div>
          )}
          <div className="table-wrap" ref={tableWrapRef} onScroll={onTableScroll}>
            <table>
              <thead><tr><th>时间</th><th>方法</th><th>URL</th><th>状态</th><th>耗时</th><th>抓取</th></tr></thead>
              <tbody>
                {records.map((record) => (
                  <tr
                    key={record.id}
                    className={activeRecordId === record.id ? 'selected' : ''}
                    onClick={() => {
                      if (activeRecordId === record.id) closeDetail()
                      else void selectRecord(record.id)
                    }}
                  >
                    <td className="mono muted">{formatTime(record.started_at_ms)}</td>
                    <td><span className={`method method-${record.method.toLowerCase()}`}>{record.method}</span></td>
                    <td className="url-cell"><strong>{record.host}</strong><span>{record.path}{record.query ? `?${record.query}` : ''}</span></td>
                    <td><span className={`status-badge status-${statusTone(record.status)}`}>{record.status ?? '…'}</span></td>
                    <td className="mono muted">{formatDuration(record.duration_ms)}</td>
                    <td><span className={`state state-${record.capture_state}`}>{formatCaptureState(record.capture_state)}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!records.length && <div className="empty-table"><span>◎</span><p>{emptyHint}</p><small>{emptySub}</small></div>}
          </div>
          <div className="table-footer">
            {!pinToLatest && <button className="jump-latest" onClick={jumpToLatest}>回到最新</button>}
            {loadingMore && <span className="loading-more">正在加载更早记录…</span>}
            {!loadingMore && nextBefore === null && records.length > 0 && !pinToLatest && (
              <span className="loading-more">已到最早记录</span>
            )}
          </div>
        </section>

        {showDetail && (
          <div
            className="col-resizer"
            role="separator"
            aria-orientation="vertical"
            aria-label="调整详情宽度"
            onMouseDown={(event) => startColumnResize(event, detailWidth, -1, 320, 800, setDetailWidth)}
          />
        )}
        {detailLoadingId
          ? <DetailLoading record={loadingRecord} onClose={closeDetail} />
          : selected && <Detail detail={selected} onClose={closeDetail} onCopy={copyText} />}
      </section>
    </main>
  )
}

function fallbackCopy(value: string) {
  const area = document.createElement('textarea')
  area.value = value
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.left = '-9999px'
  document.body.appendChild(area)
  area.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(area)
  if (!ok) throw new Error('复制失败，请手动选择文本')
}

function Toggle({ label, checked, disabled, onChange }: { label: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return <label className={`toggle-control ${disabled ? 'disabled' : ''}`}><span>{label}</span>
    <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    <i aria-hidden="true" />
  </label>
}

function DetailLoading({ record, onClose }: { record: RecordSummary | null; onClose: () => void }) {
  return (
    <aside className="detail detail-loading" aria-busy="true" aria-live="polite">
      <div className="detail-head">
        <div>
          {record && <span className={`method method-${record.method.toLowerCase()}`}>{record.method}</span>}
          {record && <span className={`status-badge status-${statusTone(record.status)}`}>{record.status ?? '…'}</span>}
        </div>
        <button aria-label="关闭详情" onClick={onClose}>×</button>
      </div>
      {record && <p className="detail-url loading-detail-url">{fullUrl(record)}</p>}
      <div className="detail-loading-message">
        <span className="loading-spinner" aria-hidden="true" />
        <span><strong>正在加载详情</strong><small>正在读取 Headers 和 Body…</small></span>
      </div>
      <div className="skeleton-section" aria-hidden="true">
        <span className="skeleton-heading" />
        <span className="skeleton-line" />
        <span className="skeleton-line short" />
        <span className="skeleton-line" />
      </div>
      <div className="skeleton-section body-skeleton" aria-hidden="true">
        <span className="skeleton-heading" />
        <span className="skeleton-line" />
        <span className="skeleton-line medium" />
        <span className="skeleton-line short" />
        <span className="skeleton-line medium" />
      </div>
    </aside>
  )
}

function Detail({
  detail,
  onClose,
  onCopy,
}: {
  detail: RecordDetail
  onClose: () => void
  onCopy: (value: string, label: string) => void
}) {
  const [tab, setTab] = useState<'request' | 'response'>('request')
  const [pretty, setPretty] = useState(true)
  useEffect(() => setTab('request'), [detail.id])
  const request = tab === 'request'
  const headers = request ? detail.request_headers : detail.response_headers
  const rawBody = request ? detail.request_body : detail.response_body
  const body = pretty ? prettyBody(rawBody) : rawBody
  const note = request ? detail.request_body_note : detail.response_body_note
  const bytes = request ? detail.request_body_bytes : detail.response_body_bytes
  const truncated = request ? detail.request_body_truncated : detail.response_body_truncated
  const url = fullUrl(detail)
  return (
    <aside className="detail">
      <div className="detail-head">
        <div>
          <span className={`method method-${detail.method.toLowerCase()}`}>{detail.method}</span>
          <b className={`status-badge status-${statusTone(detail.status)}`}>{detail.status ?? 'PENDING'}</b>
          <span className={`state state-${detail.capture_state}`}>{formatCaptureState(detail.capture_state)}</span>
        </div>
        <button aria-label="关闭详情" onClick={onClose}>×</button>
      </div>
      <div className="detail-url-row">
        <p className="detail-url">{url}</p>
        <div className="detail-actions">
          <button className="ghost" onClick={() => void onCopy(url, 'URL')}>复制 URL</button>
          <button className="ghost" onClick={() => void onCopy(toCurl(detail), 'cURL')}>复制 cURL</button>
        </div>
      </div>
      <div className="detail-meta">
        <span>{detail.client_ip}</span>
        <span>{detail.proxy_username}</span>
        <span>{formatDuration(detail.duration_ms)}</span>
        {detail.request_version && <span>{detail.request_version}</span>}
        {detail.response_version && <span>→ {detail.response_version}</span>}
      </div>
      <div className="tabs">
        <button className={tab === 'request' ? 'active' : ''} onClick={() => setTab('request')}>Request</button>
        <button className={tab === 'response' ? 'active' : ''} onClick={() => setTab('response')}>Response</button>
      </div>
      <h3>
        Headers
        <span className="heading-actions">
          <small>{headers.length}</small>
          <button className="ghost compact" onClick={() => void onCopy(headers.map(([name, value]) => `${name}: ${value}`).join('\n'), 'Headers')}>复制</button>
        </span>
      </h3>
      <div className="header-list">
        {headers.length === 0 && <div className="empty-headers">(none)</div>}
        {headers.map(([name, value], index) => (
          <div className={`header-row ${SENSITIVE_HEADERS.has(name.toLowerCase()) ? 'sensitive' : ''}`} key={`${name}-${index}`}>
            <span className="header-name">{name}</span>
            <span className="header-value">{value}</span>
          </div>
        ))}
      </div>
      <h3>
        Body
        <span className="heading-actions">
          <small>{formatBytes(bytes)}{truncated ? ' · 已截断' : ''}</small>
          <label className="pretty-toggle">
            <input type="checkbox" checked={pretty} onChange={(event) => setPretty(event.target.checked)} />
            格式化
          </label>
          <button className="ghost compact" disabled={!rawBody} onClick={() => void onCopy(body || rawBody, 'Body')}>复制</button>
        </span>
      </h3>
      {note && <div className="note">{note}</div>}
      <pre className="body-content">{body || '(empty)'}</pre>
      {detail.error && <div className="note error-note">{detail.error}</div>}
    </aside>
  )
}

export default App
