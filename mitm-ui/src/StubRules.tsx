import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from 'react'
import { api, fullUrl, type FileStubRule, type HeaderEdit, type RecordDetail, type StubMatchResult, type StubMatchType, type StubMode, type StubRule, type StubRules } from './api'
import { exactRuleUrl, parseExactUrl, regexFromExactUrl } from './stubUrl'
import { describeVerdict, ruleLabel, summarizeMatch } from './stubVerdict'

export const headerOpLabel = { add: '增加', set: '覆盖', remove: '删除' }

const modes: { value: StubMode; label: string; hint: string }[] = [
  { value: 'response', label: '静态响应', hint: '不访问上游，直接返回下方的状态码和 Body。' },
  { value: 'upstream', label: '替代上游', hint: '转发到指定地址，原路径和 query 追加在其后，保留原 Host。' },
  { value: 'headers', label: '原始服务', hint: '照常请求原服务，只应用下方的 Header 修改。' },
]
const modeLabel: Record<StubMode, string> = { response: '静态响应', upstream: '替代上游', headers: '原始服务' }
const matchTypes: { value: StubMatchType; label: string }[] = [{ value: 'exact', label: 'URL' }, { value: 'regex', label: '正则' }]
const NO_BODY_STATUS = [204, 205, 304]

// `url` is the editable text of an exact match; it is split into authority + path on save.
type Draft = StubRule & { url: string }

const blankDraft = (): Draft => ({
  id: '', note: '', enabled: true, mode: 'headers', match_type: 'regex', authority: '', path: '', url_pattern: '', url: '',
  body: '', status: 200, upstream: '', request_headers: [], response_headers: [],
})

const toDraft = (rule: StubRule): Draft => ({
  ...structuredClone(rule), url: rule.match_type === 'exact' ? exactRuleUrl(rule.authority, rule.path) : '',
})

function draftFromRecord(record: RecordDetail): Draft {
  const parsed = parseExactUrl(`https://${record.authority}${record.path}`)
  const status = record.status && record.status >= 200 && record.status <= 599 ? record.status : 200
  const reusableBody = !record.response_body_truncated && !record.response_body_image && record.response_body.length <= 1024 * 1024
  const contentType = record.response_headers.find(([name]) => name.toLowerCase() === 'content-type')?.[1]
  return {
    ...blankDraft(),
    mode: 'response',
    match_type: 'exact',
    url: 'error' in parsed ? '' : exactRuleUrl(parsed.authority, parsed.path),
    status,
    body: reusableBody && !NO_BODY_STATUS.includes(status) ? record.response_body : '',
    response_headers: contentType ? [{ enabled: true, op: 'set', name: 'content-type', value: contentType }] : [],
  }
}

function toPayload({ url, ...rule }: Draft): StubRule | { error: string } {
  if (rule.match_type === 'regex') return { ...rule, authority: '', path: '' }
  const parsed = parseExactUrl(url)
  return 'error' in parsed ? parsed : { ...rule, authority: parsed.authority, path: parsed.path, url_pattern: '' }
}

const matchText = (rule: StubRule) => rule.match_type === 'regex' ? rule.url_pattern : exactRuleUrl(rule.authority, rule.path)
const sameExactMatch = (a: Pick<StubRule, 'match_type' | 'authority' | 'path'>, b: StubRule | { error: string }) =>
  !('error' in b) && a.match_type === 'exact' && b.match_type === 'exact' && a.authority === b.authority && a.path === b.path

export function StubRulesDialog({ onClose, record }: { onClose: () => void; record?: RecordDetail }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [rules, setRules] = useState<StubRules>({ file: [], ui: [] })
  const [loading, setLoading] = useState(true)
  const [draft, setDraft] = useState<Draft | null>(record ? draftFromRecord(record) : null)
  const [file, setFile] = useState<FileStubRule | null>(null)
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [listBusy, setListBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [probeUrl, setProbeUrl] = useState(record ? fullUrl(record) : '')
  const [probe, setProbe] = useState<StubMatchResult | null>(null)
  const [probeError, setProbeError] = useState('')
  const [showHelp, setShowHelp] = useState(false)
  const [onlyActive, setOnlyActive] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [dragId, setDragId] = useState<string | null>(null)
  const [dropId, setDropId] = useState<string | null>(null)

  // Re-evaluate whenever the rules change; skip while a list mutation is still in flight.
  useEffect(() => {
    const url = probeUrl.trim()
    if (!url) { setProbe(null); setProbeError(''); return }
    if (loading || listBusy) return
    let cancelled = false
    const timer = window.setTimeout(() => {
      api<StubMatchResult>(`/stubs/match?url=${encodeURIComponent(url)}`)
        .then((result) => { if (!cancelled) { setProbe(result); setProbeError('') } })
        .catch((e: Error) => { if (!cancelled) { setProbe(null); setProbeError(e.message) } })
    }, 250)
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [probeUrl, rules, loading, listBusy])

  useEffect(() => {
    dialog.current?.showModal()
    api<StubRules>('/stubs').then((loaded) => {
      setRules(loaded)
      if (!record) return
      // Reopen the rule that already covers this request instead of failing on save with a conflict.
      const prefilled = toPayload(draftFromRecord(record))
      const existing = loaded.ui.find((rule) => sameExactMatch(rule, prefilled))
      if (existing) {
        setDraft(toDraft(existing)); setDirty(false); setNotice('该地址已有 UI 规则，已为你打开')
      }
    }).catch((e: Error) => setError(e.message)).finally(() => setLoading(false))
  }, [record])

  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(''), 2500)
    return () => window.clearTimeout(timer)
  }, [notice])

  const canLeave = () => !busy && (!dirty || window.confirm('放弃尚未保存的修改？'))
  const close = () => { if (canLeave()) onClose() }
  const choose = (next: Draft | null, fileRule: FileStubRule | null = null) => {
    if (!canLeave()) return
    setDraft(next); setFile(fileRule); setDirty(false); setError(''); setConfirmDelete(false)
  }
  const patch = (value: Partial<Draft>) => { if (draft) { setDraft({ ...draft, ...value }); setDirty(true); setConfirmDelete(false) } }

  const setMatchType = (match_type: StubMatchType) => {
    if (!draft || draft.match_type === match_type) return
    patch(match_type === 'regex' && !draft.url_pattern ? { match_type, url_pattern: regexFromExactUrl(draft.url) } : { match_type })
  }

  const save = async (event?: FormEvent) => {
    event?.preventDefault()
    if (!draft || busy) return
    const payload = toPayload(draft)
    if ('error' in payload) { setError(payload.error); return }
    setBusy(true); setError('')
    try {
      const saved = await api<StubRule>(draft.id ? `/stubs/${draft.id}` : '/stubs', { method: draft.id ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      setRules((current) => ({
        ...current,
        ui: current.ui.some((rule) => rule.id === saved.id) ? current.ui.map((rule) => rule.id === saved.id ? saved : rule) : [...current.ui, saved],
      }))
      setDraft(toDraft(saved)); setDirty(false); setNotice(draft.id ? '已保存，后续请求立即生效' : '已创建，后续请求立即生效')
    } catch (e) { setError((e as Error).message) }
    finally { setBusy(false) }
  }

  const remove = async () => {
    if (!draft?.id) return
    setBusy(true); setError('')
    try {
      await api(`/stubs/${draft.id}`, { method: 'DELETE' })
      setRules((current) => ({ ...current, ui: current.ui.filter((rule) => rule.id !== draft.id) }))
      setDraft(null); setDirty(false); setConfirmDelete(false); setNotice('规则已删除')
    } catch (e) { setError((e as Error).message) }
    finally { setBusy(false) }
  }

  const toggle = async (rule: StubRule) => {
    setListBusy(true); setError('')
    try {
      const saved = await api<StubRule>(`/stubs/${rule.id}`, { method: 'PUT', body: JSON.stringify({ ...rule, enabled: !rule.enabled }) })
      setRules((current) => ({ ...current, ui: current.ui.map((item) => item.id === saved.id ? saved : item) }))
      // The switch persists immediately; keep any unsaved edits of the open rule in sync with it.
      setDraft((current) => current?.id === saved.id ? { ...current, enabled: saved.enabled } : current)
    } catch (e) { setError((e as Error).message) }
    finally { setListBusy(false) }
  }

  const reorder = async (ids: string[]) => {
    const previous = rules.ui
    const byId = new Map(previous.map((rule) => [rule.id, rule]))
    setRules((current) => ({ ...current, ui: ids.flatMap((id) => byId.get(id) ?? []) }))
    setListBusy(true); setError('')
    try { await api('/stubs/order', { method: 'PUT', body: JSON.stringify(ids) }) }
    catch (e) { setError((e as Error).message); setRules((current) => ({ ...current, ui: previous })) }
    finally { setListBusy(false) }
  }
  const moveTo = (id: string, target: number) => {
    const ids = rules.ui.map((rule) => rule.id)
    const index = ids.indexOf(id)
    if (index < 0 || target < 0 || target >= ids.length || target === index) return
    ids.splice(index, 1)
    ids.splice(target, 0, id)
    void reorder(ids)
  }

  const onFormKeyDown = (event: KeyboardEvent) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
      event.preventDefault()
      if (dirty) void save()
    }
  }

  // Only rules that would decide the response are blocked by a file rule; header-only rules still stack on top.
  const shadowedByFile = (rule: StubRule | { error: string }) =>
    !('error' in rule) && rule.mode !== 'headers' && rules.file.some((item) => sameExactMatch({ ...item, match_type: 'exact' }, rule))
  const probing = probeUrl.trim() !== ''
  const reorderable = !listBusy && !probing
  const uiIds = rules.ui.map((rule) => rule.id)
  const labelOf = (id: string) => ruleLabel(id, uiIds)
  const verdicts = new Map(probe?.verdicts.map((item) => [item.id, { ...describeVerdict(item, labelOf), kind: item.verdict }]))
  const verdictTag = (id: string) => {
    const verdict = verdicts.get(id)
    return verdict && <span className={`stub-verdict ${verdict.kind}`}>{verdict.text}</span>
  }
  const dimmed = (id: string) => {
    const verdict = verdicts.get(id)
    return verdict ? (verdict.active ? 'hit' : 'dim') : ''
  }
  const hidden = (id: string) => onlyActive && verdicts.get(id)?.active === false
  const visibleFile = rules.file.filter((rule) => !hidden(rule.id))
  const visibleUiCount = rules.ui.filter((rule) => !hidden(rule.id)).length
  const hiddenCount = rules.file.length - visibleFile.length + rules.ui.length - visibleUiCount
  const parsedUrl = draft?.match_type === 'exact' && draft.url.trim() ? parseExactUrl(draft.url) : null
  const editing = draft || file

  return <dialog className="stub-dialog" ref={dialog} aria-labelledby="stub-title"
    onMouseDown={(event) => {
      if (event.target !== event.currentTarget || event.button !== 0) return
      // 原生 dialog 的遮罩事件也以 dialog 为目标，需用坐标排除内部空白区域。
      const { left, right, top, bottom } = event.currentTarget.getBoundingClientRect()
      if (event.clientX < left || event.clientX > right || event.clientY < top || event.clientY > bottom) close()
    }}
    onCancel={(event) => { event.preventDefault(); if (editing) choose(null); else close() }}>
    <header className="stub-dialog-head">
      <h2 id="stub-title">Stub 规则</h2>
      <span>按顺序拦截 HTTPS 请求：返回静态响应、转发到替代上游，或修改 Header</span>
      <button type="button" className={`stub-help-toggle ${showHelp ? 'active' : ''}`} aria-expanded={showHelp} onClick={() => setShowHelp(!showHelp)}>执行顺序与短路规则</button>
      <button type="button" className="stub-icon-btn" aria-label="关闭规则配置" onClick={close}>×</button>
    </header>
    {showHelp && <div className="stub-help-panel"><OrderHelp /></div>}
    <div className="stub-layout">
      <aside className="stub-list-panel" aria-label="规则列表">
        <div className="stub-list-toolbar">
          <input type="search" aria-label="测试 URL" spellCheck={false} placeholder="输入 URL，查看哪些规则生效…" value={probeUrl} onChange={(e) => setProbeUrl(e.target.value)} />
          <button type="button" className="stub-primary" disabled={loading} onClick={() => choose(blankDraft())}>＋ 新建</button>
        </div>
        {probing && <div className={`stub-probe-summary ${probeError ? 'error' : ''}`} role="status">
          {probeError || (probe ? <>
            <div className="stub-probe-line">
              <b>{summarizeMatch(probe, labelOf)}</b>
              <label className="stub-only-active"><Switch checked={onlyActive} label="只看生效的规则" onChange={setOnlyActive} />只看生效</label>
            </div>
            <code title="精确规则按域名 + 路径匹配，正则规则匹配此完整 URL">{probe.url}</code>
          </> : '正在计算…')}
        </div>}
        <div className="stub-list-scroll">
          {loading && <p className="stub-list-empty">正在加载…</p>}
          {!loading && !rules.file.length && !rules.ui.length && <p className="stub-list-empty">还没有规则</p>}
          {visibleFile.length > 0 && <>
            <h3 className="stub-list-heading">配置文件 · 只读，优先级最高</h3>
            <ul>{visibleFile.map((rule) => <li key={rule.id} className={`stub-row file ${file?.id === rule.id ? 'selected' : ''} ${dimmed(rule.id)}`}>
              <span className="stub-row-order" title="配置文件规则">F</span>
              <button type="button" className="stub-row-main" onClick={() => choose(null, rule)}>
                <code>{exactRuleUrl(rule.authority, rule.path)}</code>
                <span className="stub-row-meta">
                  <ModeTag mode={rule.mode} status={rule.status} />{rule.headers.length > 0 && <span>响应头 {rule.headers.length}</span>}
                </span>
                {verdictTag(rule.id)}
              </button>
            </li>)}</ul>
          </>}
          {visibleUiCount > 0 && <>
            <h3 className="stub-list-heading">UI 规则 · 自上而下执行，{probing ? '清空测试 URL 后可拖动排序' : '可拖动排序'}</h3>
            <ul>{rules.ui.map((rule, index) => {
              if (hidden(rule.id)) return null
              const requestCount = rule.request_headers.filter((edit) => edit.enabled).length
              const responseCount = rule.response_headers.filter((edit) => edit.enabled).length
              return <li key={rule.id}
                className={`stub-row ${draft?.id === rule.id ? 'selected' : ''} ${rule.enabled ? '' : 'off'} ${dimmed(rule.id)} ${dropId === rule.id && dragId !== rule.id ? 'drop-target' : ''} ${dragId === rule.id ? 'dragging' : ''}`}
                draggable={reorderable}
                onDragStart={(event) => { event.dataTransfer.effectAllowed = 'move'; event.dataTransfer.setData('text/plain', rule.id); setDragId(rule.id) }}
                onDragOver={(event) => { if (dragId) { event.preventDefault(); setDropId(rule.id) } }}
                onDragEnd={() => { setDragId(null); setDropId(null) }}
                onDrop={(event) => { event.preventDefault(); if (dragId && reorderable) moveTo(dragId, index); setDragId(null); setDropId(null) }}>
                <span className="stub-row-order">{index + 1}</span>
                <button type="button" className="stub-row-main" onClick={() => choose(toDraft(rule))}>
                  <code>{matchText(rule)}</code>
                  <span className="stub-row-meta">
                    <ModeTag mode={rule.mode} status={rule.status} />
                    {rule.match_type === 'regex' && <span className="stub-tag">正则</span>}
                    {requestCount > 0 && <span>请求头 {requestCount}</span>}
                    {responseCount > 0 && <span>响应头 {responseCount}</span>}
                    {!probe && shadowedByFile(rule) && <span className="stub-row-warn">被配置文件屏蔽</span>}
                    {rule.note && <span className="stub-row-note" title={rule.note}>{rule.note}</span>}
                  </span>
                  {verdictTag(rule.id)}
                </button>
                <Switch checked={rule.enabled} disabled={listBusy} label={`${rule.enabled ? '停用' : '启用'}规则 ${index + 1}`} onChange={() => void toggle(rule)} />
              </li>
            })}</ul>
          </>}
          {hiddenCount > 0 && <p className="stub-list-hidden">
            {visibleFile.length + visibleUiCount === 0 ? '没有生效的规则，' : ''}已隐藏 {hiddenCount} 条未生效的规则
            <button type="button" onClick={() => setOnlyActive(false)}>全部显示</button>
          </p>}
        </div>
      </aside>

      <section className="stub-editor" aria-label={file ? '配置文件规则详情' : '规则编辑'}>
        {(error || notice) && <div className="stub-banners">
          {error && <div className="stub-error" role="alert">{error}<button type="button" className="stub-icon-btn" aria-label="关闭错误" onClick={() => setError('')}>×</button></div>}
          {notice && <div className="stub-success" role="status">{notice}</div>}
        </div>}
        {!editing && <EmptyEditor onCreate={() => choose(blankDraft())} disabled={loading} help={!showHelp} />}
        {file && <FileRuleView rule={file} />}
        {draft && <form className="stub-form" onSubmit={(event) => void save(event)} onKeyDown={onFormKeyDown}>
          <div className="stub-editor-head">
            <h3>{draft.id ? `规则 ${rules.ui.findIndex((rule) => rule.id === draft.id) + 1}` : '新建规则'}</h3>
            {draft.id && !draft.enabled && <span className="stub-tag off">已停用</span>}
            <input className="stub-note-input" aria-label="规则备注" maxLength={200} placeholder="添加备注…" disabled={busy} value={draft.note} onChange={(e) => patch({ note: e.target.value })} />
            <span className="stub-editor-head-actions">
              {draft.id && (confirmDelete
                ? <><button type="button" className="stub-danger-solid" disabled={busy} onClick={() => void remove()}>确认删除</button><button type="button" disabled={busy} onClick={() => setConfirmDelete(false)}>取消</button></>
                : <button type="button" className="stub-danger" disabled={busy} onClick={() => setConfirmDelete(true)}>删除</button>)}
            </span>
          </div>
          <div className="stub-form-body"><fieldset disabled={busy}>
            {shadowedByFile(toPayload(draft)) && <div className="stub-warning">配置文件中有相同地址的规则，它总是先决定响应，此规则（含 Header 修改）会被整条跳过。如只需修改 Header，请把响应来源改为「原始服务」。</div>}
            <Field title="匹配请求" aside={<Segmented label="匹配方式" value={draft.match_type} options={matchTypes} onChange={setMatchType} />}>
              {draft.match_type === 'exact'
                ? <>
                  <input required aria-label="请求 URL" spellCheck={false} className="mono" placeholder="https://api.example.com/api/profile" value={draft.url} onChange={(e) => patch({ url: e.target.value })} />
                  <small>{parsedUrl && 'error' in parsedUrl ? <span className="stub-invalid">{parsedUrl.error}</span>
                    : <>匹配该域名和路径的所有请求方法{parsedUrl?.ignoredQuery ? '；query 和 # 部分不参与匹配，已忽略' : '，忽略 query'}。</>}</small>
                </>
                : <>
                  <input required aria-label="URL 正则" maxLength={4096} spellCheck={false} className="mono" placeholder={String.raw`^https://api\.example\.com/v1/`} value={draft.url_pattern} onChange={(e) => patch({ url_pattern: e.target.value })} />
                  <small>匹配完整 URL（含 query，默认 :443 省略），Rust 正则语法；<code>(?i)</code> 忽略大小写，<code>^</code> / <code>$</code> 限定范围。</small>
                </>}
            </Field>
            <Field title="响应来源" aside={<Segmented label="响应来源" value={draft.mode} options={modes} onChange={(mode) => patch({ mode })} />}>
              <small>{modes.find((mode) => mode.value === draft.mode)?.hint}</small>
              {draft.mode === 'response' && <div className="stub-response-fields">
                <label>状态码<input type="number" min="200" max="599" required aria-label="响应状态码" value={draft.status ?? 200} onChange={(e) => patch({ status: Number(e.target.value) })} /></label>
                <textarea aria-label="Response Body" spellCheck={false} placeholder={'响应正文，例如：\n{ "ok": true }'} value={draft.body} onChange={(e) => patch({ body: e.target.value })} />
                <small>按原文返回，最大 1 MiB，Content-Length 自动计算；需要时在下方响应头设置 Content-Type。</small>
              </div>}
              {draft.mode === 'upstream' && <input type="url" required aria-label="替代上游 URL" spellCheck={false} className="mono" placeholder="http://127.0.0.1:9010" value={draft.upstream ?? ''} onChange={(e) => patch({ upstream: e.target.value })} />}
            </Field>
            <Field title="Header 修改" aside={<small>按行顺序执行</small>}>
              <HeaderEditor key={`req-${draft.id}`} title="请求头" edits={draft.request_headers} onChange={(request_headers) => patch({ request_headers })}
                note={draft.mode === 'response' && draft.request_headers.length > 0 ? '静态响应不访问上游，请求头修改只体现在抓取记录中。' : undefined} />
              <HeaderEditor key={`res-${draft.id}`} title="响应头" edits={draft.response_headers} onChange={(response_headers) => patch({ response_headers })} />
              <small>增加：追加同名值；覆盖：替换全部同名值；删除：移除全部同名值。Host、Content-Length 等传输层 Header 不可修改。</small>
            </Field>
          </fieldset></div>
          <footer className="stub-form-footer">
            <span>{!draft.id ? '未保存的新规则' : dirty ? '有未保存的修改' : '已保存'}</span>
            {draft.id && dirty && <button type="button" disabled={busy} onClick={() => { const saved = rules.ui.find((rule) => rule.id === draft.id); if (saved) { setDraft(toDraft(saved)); setDirty(false); setError('') } }}>撤销修改</button>}
            <button className="stub-primary" disabled={busy || (Boolean(draft.id) && !dirty)} title="Ctrl/⌘ + S">{busy ? '保存中…' : draft.id ? '保存' : '创建规则'}</button>
          </footer>
        </form>}
      </section>
    </div>
  </dialog>
}

function EmptyEditor({ onCreate, disabled, help }: { onCreate: () => void; disabled: boolean; help: boolean }) {
  return <div className="stub-empty">
    <p>从左侧选择规则进行编辑，或</p>
    <button type="button" className="stub-primary" disabled={disabled} onClick={onCreate}>＋ 新建规则</button>
    {help && <div className="stub-empty-help"><OrderHelp /></div>}
  </div>
}

function OrderHelp() {
  return <>
    <h4>执行顺序与短路规则</h4>
    <ol>
      <li><b>顺序</b>：先配置文件规则，再按列表自上而下执行 UI 规则；配置文件规则命中后，UI 规则仍会继续执行。</li>
      <li><b>响应来源</b>：第一条命中的「静态响应 / 替代上游」规则决定响应，配置文件规则总是最先；都未命中则请求原始服务。</li>
      <li><b>短路</b>：响应确定后，后面再命中的「静态响应 / 替代上游」规则整条跳过（包括它的 Header 修改），标记为被屏蔽。</li>
      <li><b>叠加</b>：「原始服务」规则从不短路，命中即按列表顺序叠加 Header 修改，后执行的修改作用在前面的结果之上。</li>
      <li><b>停用</b>：停用的规则或 Header 行直接跳过，不影响其他规则。</li>
    </ol>
    <small>静态响应不访问上游，请求头修改只体现在抓取记录中。左上角输入 URL 可查看每条规则对它是否生效。</small>
  </>
}

function FileRuleView({ rule }: { rule: FileStubRule }) {
  const upstream = typeof rule.upstream?.url_base === 'string' ? rule.upstream.url_base : null
  return <div className="stub-form">
    <div className="stub-editor-head">
      <h3>配置文件规则</h3><span className="stub-tag file">只读</span>
    </div>
    <div className="stub-form-body">
      <Field title="匹配请求"><code className="stub-readonly">{exactRuleUrl(rule.authority, rule.path)}</code><small>精确匹配域名和路径，忽略 query。</small></Field>
      <Field title="响应来源" aside={<ModeTag mode={rule.mode} status={rule.status} />}>
        {upstream && <code className="stub-readonly">{upstream}</code>}
        {rule.upstream && Object.keys(rule.upstream).length > 1 && <pre>{JSON.stringify(rule.upstream, null, 2)}</pre>}
        {rule.body !== null && <pre>{rule.body || '(empty)'}</pre>}
      </Field>
      {rule.headers.length > 0 && <Field title="响应头"><pre>{rule.headers.map(([name, value]) => `${name}: ${value}`).join('\n')}</pre></Field>}
      <small>修改 --mitm-stub-config-file 指定的 YAML 并重启代理后生效。</small>
    </div>
  </div>
}

function Field({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return <section className="stub-field"><div className="stub-field-head"><h4>{title}</h4>{aside}</div>{children}</section>
}

function ModeTag({ mode, status }: { mode: StubMode; status: number | null }) {
  return <span className={`stub-tag mode-${mode}`}>{modeLabel[mode]}{mode === 'response' ? ` ${status ?? 200}` : ''}</span>
}

function Segmented<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: { value: T; label: string }[]; onChange: (value: T) => void }) {
  return <div className="stub-segmented" role="radiogroup" aria-label={label}>
    {options.map((option) => <button type="button" role="radio" key={option.value} aria-checked={option.value === value}
      className={option.value === value ? 'active' : ''} onClick={() => onChange(option.value)}>{option.label}</button>)}
  </div>
}

function Switch({ checked, disabled, label, onChange }: { checked: boolean; disabled?: boolean; label: string; onChange: (checked: boolean) => void }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label} title={label} disabled={disabled}
    className={`stub-switch ${checked ? 'on' : ''}`} onClick={() => onChange(!checked)}><i aria-hidden="true" /></button>
}

function HeaderEditor({ title, edits, onChange, note }: { title: string; edits: HeaderEdit[]; onChange: (edits: HeaderEdit[]) => void; note?: string }) {
  const [focusNew, setFocusNew] = useState(false)
  const update = (index: number, patch: Partial<HeaderEdit>) => onChange(edits.map((edit, i) => i === index ? { ...edit, ...patch } : edit))
  return <div className="stub-headers">
    <div className="stub-headers-head">
      <span>{title}{edits.length > 0 && <small>{edits.filter((edit) => edit.enabled).length}/{edits.length}</small>}</span>
      <button type="button" aria-label={`添加${title}`} onClick={() => { setFocusNew(true); onChange([...edits, { enabled: true, op: 'set', name: '', value: '' }]) }}>＋ 添加</button>
    </div>
    {edits.map((edit, index) => <div className={`stub-header-edit ${edit.enabled ? '' : 'off'}`} key={index}>
      <Switch checked={edit.enabled} label={`${edit.enabled ? '停用' : '启用'}${title} ${index + 1}`} onChange={(enabled) => update(index, { enabled })} />
      <select aria-label={`${title} ${index + 1} 操作`} value={edit.op} onChange={(e) => update(index, { op: e.target.value as HeaderEdit['op'] })}>
        <option value="set">覆盖</option><option value="add">增加</option><option value="remove">删除</option>
      </select>
      <input required aria-label={`${title} ${index + 1} 名称`} placeholder="名称" spellCheck={false} autoFocus={focusNew && index === edits.length - 1} value={edit.name} onChange={(e) => update(index, { name: e.target.value })} />
      <input aria-label={`${title} ${index + 1} 值`} placeholder={edit.op === 'remove' ? '移除全部同名值' : '值（可为空）'} spellCheck={false} disabled={edit.op === 'remove'} value={edit.op === 'remove' ? '' : edit.value} onChange={(e) => update(index, { value: e.target.value })} />
      <button type="button" className="stub-icon-btn" aria-label={`移除${title} ${index + 1}`} onClick={() => onChange(edits.filter((_, i) => i !== index))}>×</button>
    </div>)}
    {note && <small className="stub-headers-note">{note}</small>}
  </div>
}
