import { FormEvent, type InputHTMLAttributes, type MouseEvent as ReactMouseEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  api,
  fullUrl,
  type HostGroup,
  type RecordDetail,
  type RecordPage,
  type RecordSummary,
  type Settings,
  type Target,
  type TlsErrorGroup,
} from './api'
import {
  formatBytes,
  formatCaptureState,
  formatClientAddr,
  formatDuration,
  formatTime,
  parsePositiveInt,
  prettyBody,
  statusTone,
  toCurl,
  toExportText,
  toHttpResponse,
  exportFilename,
} from './format'
import { isEventStream, isLargeSseData, limitPrettyLines, parseSseFrames, summarizeSseData, SSE_PREVIEW_LINES, type SseFrame } from './sse'
import { filterUrlGroups } from './urlGroups'

const methods = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']
const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization'])

function App() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [groups, setGroups] = useState<HostGroup[]>([])
  const [tlsErrors, setTlsErrors] = useState<TlsErrorGroup[]>([])
  const [showTlsErrors, setShowTlsErrors] = useState(false)
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [recordsTotal, setRecordsTotal] = useState(0)
  const [nextBefore, setNextBefore] = useState<number | null>(null)
  const [selected, setSelected] = useState<RecordDetail | null>(null)
  const [host, setHost] = useState('')
  const [targetSuffixFilter, setTargetSuffixFilter] = useState('')
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
  const [detailWidth, setDetailWidth] = useState(800)
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
  const workspaceRef = useRef<HTMLElement>(null)
  const pinToLatestRef = useRef(true)
  const nextBeforeRef = useRef<number | null>(null)
  const loadingMoreRef = useRef(false)
  const [pinToLatest, setPinToLatest] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [detailLoadingId, setDetailLoadingId] = useState<string | null>(null)
  // 详情的 Request/Response tab 提到这一层：切换记录或关闭详情时 Detail 会卸载，状态不能丢
  const [detailTab, setDetailTab] = useState<'request' | 'response'>('request')
  // 详情「拉到了最下面」的状态同样跨 record 和详情关闭/重开保持
  const detailAtBottomRef = useRef(false)
  // 图片预览点开的大图（data URL），非空时显示缩放 lightbox
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null)
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
    if (targetSuffixFilter && !targets.some((target) => target.suffix === targetSuffixFilter)) {
      setTargetSuffixFilter('')
    }
  }, [targets, targetSuffixFilter])

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
  // max 按工作区当前宽度动态计算，避免列宽之和超过视口
  const startColumnResize = useCallback(
    (event: ReactMouseEvent, startWidth: number, direction: 1 | -1, min: number, max: () => number, apply: (width: number) => void) => {
      event.preventDefault()
      const startX = event.clientX
      const onMove = (moveEvent: MouseEvent) => {
        apply(Math.min(max(), Math.max(min, startWidth + direction * (moveEvent.clientX - startX))))
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

  // 窗口尺寸变化（或详情开合）时夹取列宽，保证三栏不超出视口
  useEffect(() => {
    const clampColumns = () => {
      const el = workspaceRef.current
      if (!el) return
      const available = el.clientWidth - (showDetail ? 12 : 6) - (showDetail ? 360 : 470)
      const maxSidebar = Math.max(180, Math.min(480, available - (showDetail ? detailWidth : 0)))
      if (sidebarWidth > maxSidebar) setSidebarWidth(maxSidebar)
      if (showDetail) {
        const maxDetail = Math.max(320, Math.min(800, available - Math.min(sidebarWidth, maxSidebar)))
        if (detailWidth > maxDetail) setDetailWidth(maxDetail)
      }
    }
    clampColumns()
    window.addEventListener('resize', clampColumns)
    return () => window.removeEventListener('resize', clampColumns)
  }, [sidebarWidth, detailWidth, showDetail])

  const showCopied = useCallback((label: string) => {
    setCopied(label)
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current)
    copyTimer.current = window.setTimeout(() => setCopied(''), 1600)
  }, [])

  const copyText = useCallback(async (value: string, label: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        fallbackCopy(value)
      }
      showCopied(label)
    } catch {
      try {
        fallbackCopy(value)
        showCopied(label)
      } catch (error) {
        handleError(error)
      }
    }
  }, [handleError, showCopied])

  // 图片 body 复制的是图片本身：base64 还原为二进制写入剪贴板；
  // 剪贴板只可靠支持 PNG，其他格式先经 canvas 转成 PNG
  const copyImage = useCallback(async (dataUrl: string, label: string) => {
    try {
      const blob = await blobFromDataUrl(dataUrl)
      const png = blob.type === 'image/png' ? blob : await toPngBlob(blob)
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })])
      showCopied(label)
    } catch (error) {
      handleError(error)
    }
  }, [handleError, showCopied])

  const refreshMeta = useCallback(async () => {
    try {
      const [nextSettings, nextTargets, nextGroups, nextTlsErrors] = await Promise.all([
        api<Settings>('/settings'),
        api<Target[]>('/targets'),
        api<HostGroup[]>('/groups'),
        api<TlsErrorGroup[]>('/tls-errors'),
      ])
      setSettings(nextSettings)
      setTargets(nextTargets)
      setGroups(nextGroups)
      setTlsErrors(nextTlsErrors)
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
        setRecordsTotal(page.total)
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

  // DB 大小、prune 后过期的 URL 分类计数等没有事件驱动，周期性兜底刷新
  useEffect(() => {
    const timer = window.setInterval(() => void refreshMeta(), 10_000)
    return () => window.clearInterval(timer)
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
      needRecords = needMeta = needGroups = includeDetail = true
      schedule()
    }
    source.addEventListener('open', () => {
      setLive(true)
      setError('')
    })
    source.addEventListener('record_created', onRecordEvent)
    source.addEventListener('record_updated', onRecordEvent)
    source.addEventListener('settings', onMetaEvent)
    source.addEventListener('targets', onMetaEvent)
    source.addEventListener('tls_errors', onMetaEvent)
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
      return true
    } catch (value) {
      handleError(value)
      return false
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
      setRecordsTotal(page.total)
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
      setRecordsTotal(0)
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

  // 点击列表中的客户端地址：已按该 IP 筛选则取消，否则加入筛选
  function toggleClientIpFilter(ip: string) {
    if (clientIp === ip) {
      setClientIpInput('')
      setClientIp('')
    } else {
      setClientIpInput(ip)
      setClientIp(ip)
    }
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
        if (lightboxSrc) {
          setLightboxSrc(null)
          return
        }
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
  }, [closeDetail, moveSelection, lightboxSrc])

  const hasFilters = Boolean(host || path || method || status || clientIp || search)
  const tlsErrorTotal = tlsErrors.reduce((total, group) => total + group.count, 0)
  const emptyHint = hasFilters ? '没有匹配的记录' : '等待 MITM 流量'
  const emptySub = hasFilters ? '试试放宽筛选条件' : '命中目标的 HTTPS 请求会实时出现在这里'

  // URL 分类前端搜索：粘贴完整 URL 时按 host + path 解析；host 命中保留全部 path，仅 path 命中则只展示匹配的 path
  const groupQuery = groupFilter.trim().toLowerCase()
  const filteredGroups = useMemo(
    () => filterUrlGroups(groups, groupQuery, targetSuffixFilter),
    [groups, groupQuery, targetSuffixFilter],
  )
  const groupListFiltered = Boolean(groupQuery || targetSuffixFilter)

  return (
    <main>
      {error && <div className="error-banner">{error}<button onClick={() => setError('')}>×</button></div>}
      {copied && <div className="copy-toast" role="status">{copied} 已复制</div>}

      <section className="control-strip">
        <Toggle
          label={settings?.capture_cli_managed ? '明文抓取（启动参数）' : '明文抓取'}
          checked={settings?.capture_enabled ?? false}
          disabled={settings?.capture_cli_managed ?? false}
          title={settings?.capture_cli_managed ? '由 --mitm-dump 启动参数锁定，需修改启动命令并重启' : undefined}
          onChange={(checked) => void updateSettings({ capture_enabled: checked })}
        />
        <MaxRecordsControl
          value={settings?.max_records ?? 1000}
          onCommit={(max_records) => updateSettings({ max_records })}
        />
        <label className="number-control">Body 上限
          <select
            aria-label="Body 上限"
            value={settings?.body_limit_bytes ?? 1048576}
            onChange={(event) => void updateSettings({ body_limit_bytes: Number(event.target.value) })}
          >
            <option value={16384}>16 KiB</option><option value={65536}>64 KiB</option>
            <option value={262144}>256 KiB</option><option value={1048576}>1 MiB</option>
            <option value={4194304}>4 MiB</option><option value={10485760}>10 MiB</option>
          </select>
        </label>
        <div className="status-line">
          <span className={`ca-pill ${settings?.ca_available ? 'online' : 'offline'}`}>
            <span className={`dot ${settings?.ca_available ? 'online' : 'offline'}`} />
            {settings?.ca_available ? 'CA 可用' : 'CA 不可用'}
          </span>
          {tlsErrorTotal > 0 && (
            <button
              className={`ca-alert-pill ${showTlsErrors ? 'active' : ''}`}
              title="客户端不信任 MITM CA 导致的 TLS 握手失败，点击查看分组统计"
              onClick={() => setShowTlsErrors((current) => !current)}
            >⚠ CA 未信任 {tlsErrorTotal}</button>
          )}
          <span className={`live-pill ${live ? 'on' : 'off'}`}>{live ? '● 实时' : '○ 重连中'}</span>
          <span className="record-count" title="数据库中的记录总条数">{recordsTotal} 条记录</span>
          <span className="record-count" title="mitm.sqlite3 主库 + WAL + SHM 总大小；下调留存并应用后会压缩。每 10 秒刷新">DB {formatBytes(settings?.db_bytes ?? 0)}</span>
        </div>
        {showTlsErrors && tlsErrorTotal > 0 && (
          <div className="tls-error-panel">
            <div className="tls-error-head">
              <span>CA 未信任错误 · 按域名 + 客户端 IP 聚合</span>
              <button aria-label="关闭" onClick={() => setShowTlsErrors(false)}>×</button>
            </div>
            {tlsErrors.map((group) => (
              <div className="tls-error-row" key={`${group.authority}|${group.client_ip}`}>
                <div className="tls-error-target">
                  <strong>{group.authority}</strong>
                  <span>{group.client_ip}</span>
                </div>
                <b className="tls-error-count">{group.count} 次</b>
                <span className="tls-error-time">{formatTime(group.last_seen_ms)}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section
        ref={workspaceRef}
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
            <ClearableInput aria-label="新目标后缀" placeholder="example.com" value={newTarget} onChange={setNewTarget} />
            <button type="submit">添加</button>
          </form>
          <div className="target-list">
            {targets.map((target) => (
              <div className={`target ${targetSuffixFilter === target.suffix ? 'active' : ''}`} key={target.id}>
                <button
                  className="target-main"
                  aria-pressed={targetSuffixFilter === target.suffix}
                  onClick={() => {
                    setTargetSuffixFilter((current) => current === target.suffix ? '' : target.suffix)
                    setExpandedHost('')
                  }}
                  title="筛选 URL 分类，再次点击取消"
                >
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
          <div className="panel-title group-title"><span>URL 分类</span><b>{groupListFiltered ? `${filteredGroups.length}/${groups.length}` : groups.length}</b></div>
          <ClearableInput
            aria-label="搜索 URL 分类"
            className="group-search"
            placeholder="搜索 host / path，或粘贴完整 URL…"
            value={groupFilter}
            onChange={setGroupFilter}
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
          {groupListFiltered && !filteredGroups.length && <p className="empty">没有匹配的分类</p>}
        </aside>

        <div
          className="col-resizer"
          role="separator"
          aria-orientation="vertical"
          aria-label="调整侧栏宽度"
          onMouseDown={(event) => startColumnResize(event, sidebarWidth, 1, 180, () => {
            const w = workspaceRef.current?.clientWidth ?? window.innerWidth
            return Math.max(180, Math.min(480, w - (showDetail ? 360 + 12 + detailWidth : 470 + 6)))
          }, setSidebarWidth)}
        />

        <section className="records-panel">
          <div className="filters">
            <ClearableInput aria-label="搜索 URL" placeholder="搜索 URL…" value={searchInput} onChange={setSearchInput} />
            <ClearableInput aria-label="客户端 IP" className="client-ip-input" placeholder="客户端 IP" value={clientIpInput} onChange={setClientIpInput} />
            <select aria-label="请求方法" value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((item) => <option key={item} value={item}>{item || '全部方法'}</option>)}</select>
            <ClearableInput aria-label="状态码" className="status-input" placeholder="状态码" value={status} onChange={(value) => setStatus(value.replace(/\D/g, '').slice(0, 3))} />
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
              <thead><tr><th>时间</th><th>方法</th><th>URL</th><th>客户端</th><th>状态</th><th>耗时</th><th>抓取</th></tr></thead>
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
                    <td className="client-cell">
                      <button
                        className={`client-addr ${clientIp === record.client_ip ? 'active' : ''}`}
                        title={clientIp === record.client_ip ? '取消客户端 IP 筛选' : '按该客户端 IP 筛选'}
                        onClick={(event) => {
                          event.stopPropagation()
                          toggleClientIpFilter(record.client_ip)
                        }}
                      >{formatClientAddr(record.client_ip, record.client_port)}</button>
                    </td>
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
            onMouseDown={(event) => startColumnResize(event, detailWidth, -1, 320, () => {
              const w = workspaceRef.current?.clientWidth ?? window.innerWidth
              return Math.max(320, Math.min(800, w - 360 - 12 - sidebarWidth))
            }, setDetailWidth)}
          />
        )}
        {detailLoadingId
          ? <DetailLoading record={loadingRecord} tab={detailTab} onTabChange={setDetailTab} onClose={closeDetail} />
          : selected && (
            <Detail
              detail={selected}
              tab={detailTab}
              onTabChange={setDetailTab}
              onClose={closeDetail}
              onCopy={copyText}
              onCopyImage={copyImage}
              atBottomRef={detailAtBottomRef}
              onZoomImage={setLightboxSrc}
            />
          )}
      </section>
      {lightboxSrc && <ImageLightbox src={lightboxSrc} onClose={() => setLightboxSrc(null)} />}
    </main>
  )
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(objectUrl)
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

async function blobFromDataUrl(dataUrl: string): Promise<Blob> {
  const [head, data] = dataUrl.split(',')
  const mime = /data:(.*?);base64/.exec(head)?.[1] ?? 'application/octet-stream'
  const binary = atob(data)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  return new Blob([bytes], { type: mime })
}

async function toPngBlob(blob: Blob): Promise<Blob> {
  const bitmap = await createImageBitmap(blob)
  const canvas = document.createElement('canvas')
  canvas.width = bitmap.width
  canvas.height = bitmap.height
  canvas.getContext('2d')?.drawImage(bitmap, 0, 0)
  bitmap.close()
  return new Promise((resolve, reject) =>
    canvas.toBlob((png) => (png ? resolve(png) : reject(new Error('图片转换为 PNG 失败'))), 'image/png'),
  )
}

function ClearableInput({
  value,
  onChange,
  className,
  ...props
}: {
  value: string
  onChange: (value: string) => void
} & Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange' | 'className'> & { className?: string }) {
  return (
    <span className={className ? `clearable ${className}` : 'clearable'}>
      <input {...props} value={value} onChange={(event) => onChange(event.target.value)} />
      {value && (
        <button type="button" className="input-clear" aria-label="清空" tabIndex={-1} onClick={() => onChange('')}>×</button>
      )}
    </span>
  )
}

function MaxRecordsControl({
  value,
  onCommit,
}: {
  value: number
  onCommit: (next: number) => Promise<boolean>
}) {
  const [draft, setDraft] = useState(String(value))
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const savedTimer = useRef<number | null>(null)

  useEffect(() => {
    if (!dirty && !saving) setDraft(String(value))
  }, [value, dirty, saving])

  async function commit(raw = draft) {
    const parsed = parsePositiveInt(raw)
    if (parsed === null) {
      setDraft(String(value))
      setDirty(false)
      return
    }
    setDraft(String(parsed))
    if (parsed === value) {
      setDirty(false)
      return
    }
    setSaving(true)
    const ok = await onCommit(parsed)
    setSaving(false)
    if (!ok) {
      setDirty(true)
      return
    }
    setDirty(false)
    setSaved(true)
    if (savedTimer.current !== null) window.clearTimeout(savedTimer.current)
    savedTimer.current = window.setTimeout(() => setSaved(false), 1600)
  }

  return (
    <label className={`number-control${dirty ? ' dirty' : ''}`} title="点击「应用」后生效；降低条数会删除旧记录并在后台压缩数据库">
      留存记录
      <input
        aria-label="留存记录"
        type="number"
        min="1"
        step="1"
        disabled={saving}
        value={draft}
        onChange={(event) => {
          setDraft(event.target.value)
          setDirty(event.target.value !== String(value))
          setSaved(false)
        }}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            setDraft(String(value))
            setDirty(false)
            event.currentTarget.blur()
          }
        }}
      />
      {dirty && (
        <button type="button" className="apply-setting" disabled={saving} onClick={() => void commit()}>
          {saving ? '保存中' : '应用'}
        </button>
      )}
      {saved && !dirty && <span className="setting-saved">已保存</span>}
    </label>
  )
}

function Toggle({ label, checked, disabled, title, onChange }: { label: string; checked: boolean; disabled?: boolean; title?: string; onChange: (value: boolean) => void }) {
  return <label className={`toggle-control ${disabled ? 'disabled' : ''}`} title={title}><span>{label}</span>
    <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
    <i aria-hidden="true" />
  </label>
}

function DetailLoading({
  record,
  tab,
  onTabChange,
  onClose,
}: {
  record: RecordSummary | null
  tab: 'request' | 'response'
  onTabChange: (tab: 'request' | 'response') => void
  onClose: () => void
}) {
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
      <div className="tabs">
        <button className={tab === 'request' ? 'active' : ''} onClick={() => onTabChange('request')}>Request</button>
        <button className={tab === 'response' ? 'active' : ''} onClick={() => onTabChange('response')}>Response</button>
      </div>
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
  tab,
  onTabChange,
  onClose,
  onCopy,
  onCopyImage,
  atBottomRef,
  onZoomImage,
}: {
  detail: RecordDetail
  tab: 'request' | 'response'
  onTabChange: (tab: 'request' | 'response') => void
  onClose: () => void
  onCopy: (value: string, label: string) => void
  onCopyImage: (dataUrl: string, label: string) => void
  atBottomRef: { current: boolean }
  onZoomImage: (dataUrl: string) => void
}) {
  const [pretty, setPretty] = useState(true)
  const asideRef = useRef<HTMLElement>(null)
  const scrollToBottomIfPinned = useCallback(() => {
    const el = asideRef.current
    if (el && atBottomRef.current) el.scrollTop = el.scrollHeight
  }, [atBottomRef])
  // 切换 record 后，如果之前处于「拉到了最下面」状态，新记录也保持吸底
  useEffect(() => scrollToBottomIfPinned(), [detail.id, scrollToBottomIfPinned])
  const onDetailScroll = () => {
    const el = asideRef.current
    if (el) atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight <= 8
  }
  const request = tab === 'request'
  const headers = request ? detail.request_headers : detail.response_headers
  const rawBody = request ? detail.request_body : detail.response_body
  const body = pretty ? prettyBody(rawBody) : rawBody
  const note = request ? detail.request_body_note : detail.response_body_note
  const bytes = request ? detail.request_body_bytes : detail.response_body_bytes
  const truncated = request ? detail.request_body_truncated : detail.response_body_truncated
  const imageMediaType = request ? detail.request_body_image : detail.response_body_image
  const eventStream = !request && isEventStream(headers)
  // 后端只对完整（未截断）的图片 body 落 base64，此时可直接预览
  const imagePreview = imageMediaType && rawBody && !truncated ? `data:${imageMediaType};base64,${rawBody}` : null
  const url = fullUrl(detail)
  return (
    <aside className="detail" ref={asideRef} onScroll={onDetailScroll}>
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
          <button className="ghost" onClick={() => void onCopy(toHttpResponse(detail), '响应')}>复制响应</button>
          <button className="ghost" onClick={() => downloadText(exportFilename(detail), toExportText(detail))}>导出文本</button>
        </div>
      </div>
      <div className="detail-meta">
        <span>{formatClientAddr(detail.client_ip, detail.client_port)}</span>
        <span>{detail.proxy_username}</span>
        <span>{formatDuration(detail.duration_ms)}</span>
        {detail.request_version && <span>{detail.request_version}</span>}
        {detail.response_version && <span>→ {detail.response_version}</span>}
      </div>
      <div className="tabs">
        <button className={tab === 'request' ? 'active' : ''} onClick={() => onTabChange('request')}>Request</button>
        <button className={tab === 'response' ? 'active' : ''} onClick={() => onTabChange('response')}>Response</button>
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
            <button
              className="ghost compact header-copy"
              aria-label={`复制 ${name}`}
              title="复制（key 和 value 以换行分隔）"
              onClick={() => void onCopy(`${name}\n${value}`, name)}
            >复制</button>
          </div>
        ))}
      </div>
      <h3>
        Body
        <span className="heading-actions">
          <small>{formatBytes(bytes)}{truncated ? ' · 已截断' : ''}{imageMediaType ? ` · ${imageMediaType}` : ''}</small>
          {!imagePreview && (
            <label className="pretty-toggle">
              <input type="checkbox" checked={pretty} onChange={(event) => setPretty(event.target.checked)} />
              {eventStream ? '事件视图' : '格式化'}
            </label>
          )}
          {imagePreview
            ? <button className="ghost compact" onClick={() => void onCopyImage(imagePreview, '图片')}>复制图片</button>
            : <button className="ghost compact" disabled={!rawBody} onClick={() => void onCopy(body || rawBody, 'Body')}>复制</button>}
        </span>
      </h3>
      {note && <div className="note">{note}</div>}
      {imagePreview
        ? (
          <img
            className="body-image-preview"
            src={imagePreview}
            alt={`${imageMediaType} 预览`}
            title="点击查看大图"
            onClick={() => onZoomImage(imagePreview)}
            onLoad={scrollToBottomIfPinned}
          />
        )
        : eventStream && pretty
          ? <SseBody key={detail.id} body={rawBody} onCopy={onCopy} />
          : <pre className="body-content">{body || '(empty)'}</pre>}
      {detail.error && <div className="note error-note">{detail.error}</div>}
    </aside>
  )
}

function SseBody({ body, onCopy }: { body: string; onCopy: (value: string, label: string) => void }) {
  const frames = parseSseFrames(body)
  const containerRef = useRef<HTMLDivElement>(null)
  const pinnedRef = useRef(true)
  const jumpingRef = useRef(false)
  const seenRef = useRef(frames.length)
  const [atLatest, setAtLatest] = useState(true)
  const [unseen, setUnseen] = useState(0)
  useEffect(() => {
    const el = containerRef.current
    if (el && pinnedRef.current) {
      el.scrollTop = el.scrollHeight
      seenRef.current = frames.length
      setAtLatest(true)
      setUnseen(0)
    } else {
      setUnseen(Math.max(0, frames.length - seenRef.current))
    }
  }, [body, frames.length])
  const onScroll = () => {
    const el = containerRef.current
    if (!el) return
    const latest = el.scrollHeight - el.scrollTop - el.clientHeight <= 8
    if (latest) {
      jumpingRef.current = false
      pinnedRef.current = true
      seenRef.current = frames.length
      setUnseen(0)
      setAtLatest(true)
    } else if (!jumpingRef.current) {
      // 平滑跳转途中的中间位置不算用户主动离开底部
      if (pinnedRef.current) seenRef.current = frames.length
      pinnedRef.current = false
      setUnseen(Math.max(0, frames.length - seenRef.current))
      setAtLatest(false)
    }
  }
  const jumpToLatest = () => {
    const el = containerRef.current
    if (!el) return
    pinnedRef.current = true
    jumpingRef.current = true
    seenRef.current = frames.length
    el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' })
    setAtLatest(true)
    setUnseen(0)
  }

  if (!frames.length) return <div className="sse-empty">等待首个事件…</div>
  return (
    <div className="sse-body">
      <div className="sse-events" ref={containerRef} onScroll={onScroll}>
        {frames.map((frame, index) => (
          <SseEventCard key={index} frame={frame} index={index} onCopy={onCopy} />
        ))}
      </div>
      {!atLatest && (
        <button className="sse-jump-latest" onClick={jumpToLatest} title="滚动到底部并恢复自动吸附">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M3 4l5 5 5-5" />
            <path d="M3 8.5l5 5 5-5" />
          </svg>
          <span>{unseen > 0 ? `${unseen} 条新事件` : '回到最新事件'}</span>
        </button>
      )}
    </div>
  )
}

function SseEventCard({
  frame,
  index,
  onCopy,
}: {
  frame: SseFrame
  index: number
  onCopy: (value: string, label: string) => void
}) {
  const raw = frame.hasData ? frame.data : ''
  const large = frame.hasData && isLargeSseData(raw)
  const [expanded, setExpanded] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const pretty = useMemo(() => {
    if (!raw || (large && !expanded)) return ''
    return prettyBody(raw)
  }, [raw, large, expanded])
  const summary = useMemo(() => (large ? summarizeSseData(raw) : null), [large, raw])
  const preview = useMemo(() => {
    if (!pretty) return null
    return showAll ? { text: pretty, hiddenLines: 0, totalLines: pretty.split('\n').length } : limitPrettyLines(pretty, SSE_PREVIEW_LINES)
  }, [pretty, showAll])

  return (
    <article className={`sse-event${frame.pending ? ' pending' : ''}${large ? ' large' : ''}${large && !expanded ? ' collapsed' : ''}`}>
      <div className="sse-event-head">
        <span className="sse-sequence">#{index + 1}</span>
        <b>{frame.comments.length > 0 && !frame.hasData ? 'heartbeat' : frame.event}</b>
        {large && <span className="sse-size">{formatBytes(raw.length)}</span>}
        {frame.id !== null && <span>id: {frame.id || '(empty)'}</span>}
        {frame.retry !== null && <span>retry: {frame.retry}ms</span>}
        {frame.pending && <em>接收中</em>}
        <span className="sse-actions">
          {large && (
            <button
              className="ghost compact"
              aria-expanded={expanded}
              title={expanded ? '收起大事件' : '展开查看内容'}
              onClick={() => {
                setExpanded((current) => !current)
                if (expanded) setShowAll(false)
              }}
            >{expanded ? '收起' : '展开'}</button>
          )}
          {(frame.hasData || frame.comments.length > 0) && (
            <button
              className="ghost compact sse-copy"
              title="复制该事件内容"
              onClick={() => void onCopy(frame.hasData ? prettyBody(raw) : frame.comments.join('\n'), `事件 #${index + 1}`)}
            >复制</button>
          )}
        </span>
      </div>
      {frame.comments.map((comment, commentIndex) => (
        <div className="sse-comment" key={commentIndex}>: {comment || '(heartbeat)'}</div>
      ))}
      {frame.unknownFields.map(([name, value], fieldIndex) => (
        <div className="sse-field" key={`${name}-${fieldIndex}`}><span>{name}</span>{value}</div>
      ))}
      {large && !expanded && summary && (summary.facts.length > 0 || summary.largeFields.length > 0) && (
        <div className="sse-summary">
          {summary.facts.map((fact) => <span className="sse-fact" key={fact}>{fact}</span>)}
          {summary.largeFields.map((field) => (
            <span className="sse-fact heavy" key={field.name}>{field.name} {formatBytes(field.bytes)}</span>
          ))}
        </div>
      )}
      {frame.hasData && (!large || expanded) && (
        <>
          <pre>{preview?.text || '(empty data)'}</pre>
          {preview && (preview.hiddenLines > 0 || showAll || (large && preview.totalLines > SSE_PREVIEW_LINES)) && (
            <div className="sse-event-foot">
              <span>
                {preview.hiddenLines > 0
                  ? `预览前 ${preview.totalLines - preview.hiddenLines} 行 · 共 ${preview.totalLines} 行`
                  : `共 ${preview.totalLines} 行`}
              </span>
              {preview.hiddenLines > 0 && (
                <button className="ghost compact" onClick={() => setShowAll(true)}>显示全部</button>
              )}
              {showAll && preview.totalLines > SSE_PREVIEW_LINES && (
                <button className="ghost compact" onClick={() => setShowAll(false)}>仅预览</button>
              )}
            </div>
          )}
        </>
      )}
    </article>
  )
}

function ImageLightbox({ src, onClose }: { src: string; onClose: () => void }) {
  const [zoom, setZoom] = useState(1)
  const [naturalWidth, setNaturalWidth] = useState(0)
  const bodyRef = useRef<HTMLDivElement>(null)

  const zoomBy = useCallback((factor: number) => {
    setZoom((current) => Math.min(10, Math.max(0.1, current * factor)))
  }, [])

  // React 的 onWheel 是 passive 的，无法 preventDefault，需要原生监听阻止页面滚动
  useEffect(() => {
    const el = bodyRef.current
    if (!el) return
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      zoomBy(event.deltaY < 0 ? 1.2 : 1 / 1.2)
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [zoomBy])

  return (
    <div className="image-lightbox" onClick={onClose}>
      <div className="lightbox-toolbar" onClick={(event) => event.stopPropagation()}>
        <button onClick={() => zoomBy(1 / 1.2)}>－</button>
        <span>{Math.round(zoom * 100)}%</span>
        <button onClick={() => zoomBy(1.2)}>＋</button>
        <button onClick={() => setZoom(1)}>重置</button>
        <span className="lightbox-hint">滚轮缩放 · 双击切换 100%/200% · 点击空白或 Esc 关闭</span>
        <button aria-label="关闭大图" onClick={onClose}>×</button>
      </div>
      <div className="lightbox-body" ref={bodyRef} onClick={onClose}>
        <img
          src={src}
          alt="图片大图"
          onClick={(event) => event.stopPropagation()}
          onDoubleClick={() => setZoom((current) => (current === 1 ? 2 : 1))}
          onLoad={(event) => setNaturalWidth(event.currentTarget.naturalWidth)}
          style={naturalWidth ? { width: naturalWidth * zoom } : undefined}
        />
      </div>
    </div>
  )
}

export default App
