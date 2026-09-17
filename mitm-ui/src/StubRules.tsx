import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type FileStubRule, type HeaderEdit, type RecordDetail, type StubRule, type StubRules } from './api'

const modeLabel = { response: '覆写响应', upstream: '转发上游', headers: '仅修改 Headers', mod_header: 'mod-header' }
export const headerOpLabel = { add: '增加', set: '覆盖', remove: '删除' }
const emptyRule = (record?: RecordDetail): StubRule => ({
  id: '', authority: record ? (new URL(`https://${record.authority}`).port ? record.authority : `${record.host}:443`) : '',
  path: record?.path ?? '/', enabled: true, mode: 'mod_header', status: 200,
  body: '', upstream: '', url_pattern: '', request_headers: [], response_headers: [],
})

export function StubRulesDialog({ onClose, record }: { onClose: () => void; record?: RecordDetail }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const editor = useRef<HTMLElement>(null)
  const editorTrigger = useRef<HTMLElement | null>(null)
  const [rules, setRules] = useState<StubRules>({ file: [], ui: [] })
  const [loading, setLoading] = useState(true)
  const [draft, setDraft] = useState<StubRule | null>(record ? emptyRule(record) : null)
  const [file, setFile] = useState<FileStubRule | null>(null)
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [filter, setFilter] = useState('')
  const [deleting, setDeleting] = useState(false)
  const reload = async () => { setRules(await api<StubRules>('/stubs')); setLoading(false) }
  useEffect(() => {
    dialog.current?.showModal()
    void reload().catch((e: Error) => { setError(e.message); setLoading(false) })
  }, [])
  const canLeave = () => !busy && (!dirty || window.confirm('放弃尚未保存的规则修改？'))
  const close = () => { if (canLeave()) onClose() }
  const choose = (rule: StubRule | null, fileRule: FileStubRule | null = null) => {
    if (!canLeave()) return
    if (rule || fileRule) editorTrigger.current = document.activeElement as HTMLElement
    else requestAnimationFrame(() => editorTrigger.current?.focus())
    setDraft(rule); setFile(fileRule); setDirty(false); setError(''); setNotice(''); setDeleting(false)
    editor.current?.scrollTo({ top: 0 })
  }
  const patch = (value: Partial<StubRule>) => { if (draft) { setDraft({ ...draft, ...value }); setDirty(true); setNotice('') } }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!draft) return
    setBusy(true); setError(''); setNotice('')
    try {
      const saved = await api<StubRule>(draft.id ? `/stubs/${draft.id}` : '/stubs', { method: draft.id ? 'PUT' : 'POST', body: JSON.stringify(draft) })
      setDraft(saved); setDirty(false); setNotice(shadowed(saved) ? '已保存；文件规则优先，此 UI 规则暂不生效' : saved.enabled ? '已保存，后续匹配请求立即生效' : '已保存，规则已停用')
      editor.current?.scrollTo({ top: 0 })
      await reload()
    } catch (e) { setError((e as Error).message); editor.current?.scrollTo({ top: 0 }) }
    finally { setBusy(false) }
  }
  const remove = async () => {
    if (!draft?.id) return
    setBusy(true); setError('')
    try {
      await api(`/stubs/${draft.id}`, { method: 'DELETE' })
      setDraft(null); setDirty(false); setDeleting(false); setNotice('规则已删除'); await reload()
    } catch (e) { setError((e as Error).message); editor.current?.scrollTo({ top: 0 }) }
    finally { setBusy(false) }
  }
  const shadowed = (rule: StubRule) => rule.mode !== 'mod_header' && rules.file.some((item) => item.authority === rule.authority.trim().toLowerCase() && item.path === rule.path)
  const visible = (rule: { authority: string; path: string; url_pattern?: string }) => `${rule.authority}${rule.path}${rule.url_pattern ?? ''}`.toLowerCase().includes(filter.toLowerCase())
  return <dialog className="stub-dialog" ref={dialog} onCancel={(event) => { event.preventDefault(); if (draft || file) choose(null); else close() }} aria-labelledby="stub-title">
    <header className="stub-dialog-head"><div><span className="stub-eyebrow">MITM STUB</span><h2 id="stub-title">请求与响应规则</h2></div><button type="button" className="stub-close" aria-label="关闭规则配置" onClick={close}>×</button></header>
    <div className="stub-policy"><b>文件优先</b><span>文件规则优先 → UI 按创建顺序首次命中 → 原始请求。mod-header 按完整 URL 正则匹配，其余模式精确匹配域名和路径。</span></div>
    <div className="stub-layout">
      <section className="stub-table-panel" aria-label="已有规则" inert={Boolean(draft || file)}>
        <div className="stub-table-toolbar"><div><strong>已有规则</strong><span>{rules.file.length} 条文件规则 · {rules.ui.length} 条 UI 规则</span></div><input aria-label="筛选规则" placeholder="筛选网址或正则…" value={filter} onChange={(e) => setFilter(e.target.value)} /><button className="stub-primary" disabled={loading || busy} onClick={() => choose(emptyRule())}>＋ 新建规则</button></div>
        {!draft && !file && error && <div className="stub-error" role="alert">{error}</div>}
        {!draft && !file && notice && <div className="stub-success" role="status">{notice}</div>}
        <div className="stub-table-scroll">
          <table className="stub-rules-table" aria-label="规则列表"><colgroup><col className="rule-source-col" /><col className="rule-match-col" /><col /><col /><col className="rule-body-col" /><col className="rule-action-col" /></colgroup><thead><tr><th scope="col">来源 / 状态</th><th scope="col">匹配网址</th><th scope="col">请求头</th><th scope="col">响应头</th><th scope="col">Body 来源</th><th scope="col">操作</th></tr></thead><tbody>
            {rules.file.filter(visible).map((rule) => <RuleRow key={rule.id} rule={rule} selected={file?.id === rule.id} onSelect={() => choose(null, rule)} />)}
            {rules.ui.filter(visible).map((rule) => <RuleRow key={rule.id} rule={rule} selected={draft?.id === rule.id} shadowed={shadowed(rule)} onSelect={() => choose(structuredClone(rule))} />)}
            {(loading || ![...rules.file, ...rules.ui].some(visible)) && <tr><td colSpan={6} className="stub-table-empty">{loading ? '正在加载规则…' : filter ? '没有匹配的规则，请调整筛选条件。' : '暂无规则，点击「新建规则」开始配置。'}</td></tr>}
          </tbody></table>
        </div>
        <p className="stub-table-foot">文件规则优先，UI 规则按创建顺序匹配。列表展示已保存的配置；UI 规则重启后保留。</p>
      </section>
      {(draft || file) && <>
      <button className="stub-editor-backdrop" aria-label="收起编辑面板" onClick={() => choose(null)} />
      <section className="stub-editor" ref={editor} aria-label={file ? '文件规则详情' : '规则编辑面板'}>
        <div className="stub-editor-toolbar"><strong>{file ? '查看文件规则' : draft?.id ? '编辑规则' : '新建规则'}</strong><button type="button" autoFocus aria-label="关闭编辑面板" onClick={() => choose(null)}>×</button></div>
        {error && <div className="stub-error" role="alert">{error}</div>}
        {notice && <div className="stub-success" role="status">{notice}</div>}
        {file && <div className="stub-file-detail"><div className="stub-section-title"><h3>配置文件规则</h3><span className="stub-badge file">只读 · 优先匹配</span></div><p className="stub-muted">修改配置文件并重启代理后生效。UI 无法覆盖或删除文件规则。</p><dl><dt>域名</dt><dd>{file.authority}</dd><dt>路径</dt><dd>{file.path}</dd><dt>操作</dt><dd>{modeLabel[file.mode]}</dd>{file.status && <><dt>状态码</dt><dd>{file.status}</dd></>}</dl>{file.upstream && <><h3>上游配置</h3><pre>{JSON.stringify(file.upstream, null, 2)}</pre></>}{!!file.headers.length && <><h3>Response Headers</h3><pre>{file.headers.map(([name, value]) => `${name}: ${value}`).join('\n')}</pre></>}{file.body !== null && <><h3>Response Body <small>来自 body_file · 文本预览</small></h3><pre>{file.body || '(empty)'}</pre></>}</div>}
        {draft && <form onSubmit={(event) => void save(event)} className="stub-form">
          <div className="stub-section-title"><h3>{draft.id ? '编辑 UI 规则' : '新建 UI 规则'}</h3><label className="stub-enabled"><input type="checkbox" checked={draft.enabled} disabled={busy} onChange={(e) => patch({ enabled: e.target.checked })} />启用规则</label></div>
          {shadowed(draft) && <div className="stub-warning">被文件规则覆盖：保存后保留此 UI 规则，但相同域名与路径始终使用文件规则。</div>}
          <fieldset disabled={busy}>
            <label className="stub-mode-label">规则操作<select aria-label="规则操作" value={draft.mode} onChange={(e) => patch({ mode: e.target.value as StubRule['mode'] })}><option value="response">覆写响应 · 直接返回 Body</option><option value="upstream">转发上游 · 使用替代服务</option><option value="mod_header">mod-header · URL 正则修改请求/响应头</option>{draft.mode === 'headers' && <option value="headers">仅修改 Headers · 原有精确匹配</option>}</select></label>
            {draft.mode === 'mod_header' ? <label className="stub-upstream">URL 正则<input required aria-label="URL 正则" maxLength={4096} spellCheck={false} placeholder={String.raw`^https://api\.example\.com/api/`} value={draft.url_pattern ?? ''} onChange={(e) => patch({ url_pattern: e.target.value })} /><small>匹配完整 HTTPS URL（含路径和 query；默认 :443 省略）。使用 Rust 正则语法，区分大小写，可用 (?i) 忽略大小写；^ 和 $ 限定匹配范围。</small><small>仅修改请求/响应头，保留原始上游、状态码和 Body。命中文件规则时仍以文件为准。</small></label> : <div className="stub-match-fields"><label>目标域名 <input required aria-label="目标域名" placeholder="api.example.com:443" value={draft.authority} onChange={(e) => patch({ authority: e.target.value })} /></label><label>请求路径 <input required aria-label="请求路径" placeholder="/api/profile" value={draft.path} onChange={(e) => patch({ path: e.target.value })} /></label></div>}
            {draft.mode === 'response' && <section className="stub-body-editor"><div className="stub-section-title"><h3>Response Body</h3><label>状态码 <input type="number" min="200" max="599" required aria-label="响应状态码" value={draft.status ?? 200} onChange={(e) => patch({ status: Number(e.target.value) })} /></label></div><textarea aria-label="Response Body" spellCheck={false} placeholder={'直接编写响应正文，例如：\n{ "ok": true }'} value={draft.body} onChange={(e) => patch({ body: e.target.value })} /><p className="stub-muted">按原文返回，支持空 Body，最大 1 MiB。可在下方设置 Content-Type；Content-Length 自动计算。</p></section>}
            {draft.mode === 'upstream' && <label className="stub-upstream">上游 URL<input type="url" required aria-label="上游 URL" placeholder="http://127.0.0.1:9010" value={draft.upstream ?? ''} onChange={(e) => patch({ upstream: e.target.value })} /><small>原始路径和 query 将追加到此 URL 后面；保留原请求虚拟主机。</small></label>}
            <HeaderEditor title="Request Headers" edits={draft.request_headers} onChange={(request_headers) => patch({ request_headers })} />
            {draft.mode === 'response' && <p className="stub-muted">静态响应不会发送到上游；请求头修改仅体现在抓取记录中。</p>}
            <HeaderEditor title="Response Headers" edits={draft.response_headers} onChange={(response_headers) => patch({ response_headers })} />
            <p className="stub-muted">增加：追加同名值；覆盖：替换全部同名值；删除：移除全部同名值。Host、连接和报文长度相关头由传输层管理。</p>
          </fieldset>
          <footer className="stub-form-footer"><span>{!draft.id ? '尚未保存的新规则' : dirty ? '有未保存的修改' : '已同步'}{!draft.enabled ? ' · 当前停用' : ''}</span><div>{draft.id && <button type="button" className="stub-danger" disabled={busy} onClick={() => setDeleting(true)}>删除规则</button>}<button className="stub-primary" disabled={busy || (Boolean(draft.id) && !dirty)}>{busy ? '保存中…' : '保存规则'}</button></div></footer>
          {deleting && <div className="stub-warning stub-delete-confirm">删除此 UI 规则？后续请求将恢复默认行为。<button type="button" disabled={busy} onClick={() => setDeleting(false)}>取消</button><button type="button" className="stub-danger" disabled={busy} onClick={() => void remove()}>确认删除</button></div>}
        </form>}
      </section>
      </>}
    </div>
  </dialog>
}

function RuleRow({ rule, selected, shadowed = false, onSelect }: {
  rule: StubRule | FileStubRule; selected: boolean; shadowed?: boolean; onSelect: () => void
}) {
  const ui = 'request_headers' in rule
  const regex = ui && rule.mode === 'mod_header'
  const match = regex ? rule.url_pattern : `https://${rule.authority}${rule.path}`
  const upstream = ui ? rule.upstream : typeof rule.upstream?.url_base === 'string' ? rule.upstream.url_base : null
  const requestHeaders: HeaderEdit[] = ui ? rule.request_headers : Object.entries(rule.upstream?.headers ?? {}).map(([name, value]) => ({ enabled: true, op: 'set', name, value: String(value) }))
  const responseHeaders: HeaderEdit[] = ui ? rule.response_headers : rule.headers.map(([name, value]) => ({ enabled: true, op: 'set', name, value }))
  const staticResponse = rule.mode === 'response'
  return <tr className={selected ? 'selected' : ''}>
    <td><span className="stub-card-values"><span className={`stub-badge ${!ui ? 'file' : ''}`}>{ui ? 'UI 规则' : '配置文件 · 只读'}</span>{ui && <span className={`stub-rule-state ${shadowed ? 'shadowed' : rule.enabled ? 'enabled' : ''}`}>{shadowed ? '被文件规则覆盖' : rule.enabled ? '已启用' : '已停用'}</span>}</span></td>
    <td><span className="stub-card-values"><span className="stub-match-kind">{regex ? '正则匹配' : '精确匹配'} · {modeLabel[rule.mode]}</span><code className="stub-table-url">{match}</code><span className="stub-card-muted">{regex ? '完整 URL · 含 query' : '域名 + 路径 · 忽略 query'} · 所有方法</span></span></td>
    <td><span className="stub-card-values"><HeaderSummary edits={requestHeaders} fallback="保留原始请求头" />{!ui && Boolean(rule.upstream?.authority) && <span className="stub-card-muted">Host：{String(rule.upstream?.authority)}</span>}{staticResponse && <span className="stub-card-muted">不发送上游{requestHeaders.some((edit) => edit.enabled) ? '，修改仅用于抓取' : ''}</span>}</span></td>
    <td><span className="stub-card-values"><HeaderSummary edits={responseHeaders} fallback={staticResponse ? 'Stub 自动生成' : '保留原始响应头'} />{staticResponse && <span className="stub-card-muted">状态码 {rule.status ?? 200} · 长度自动计算</span>}</span></td>
    <td><span className="stub-card-values"><span className="stub-card-muted">请求：客户端原文</span><span className={staticResponse || upstream ? 'stub-card-changed' : ''}>响应：{staticResponse ? ui ? 'UI 编写的正文' : '配置文件 body_file' : upstream ? '替代上游' : '原始上游（不覆写）'}</span>{upstream && <code>{upstream}</code>}</span></td>
    <td><button type="button" aria-label={`${ui ? '编辑' : '查看'}规则 ${match}`} onClick={onSelect}>{ui ? '编辑' : '查看'}</button></td>
  </tr>

}

function HeaderSummary({ edits, fallback }: { edits: HeaderEdit[]; fallback: string }) {
  if (!edits.length) return <span className="stub-card-muted">{fallback}</span>
  return <>{edits.map((edit, index) => <span className={`stub-card-header ${edit.enabled ? '' : 'off'}`} key={index}><em className={`stub-card-op ${edit.op}`}>{edit.enabled ? headerOpLabel[edit.op] : '停用'}</em><code>{edit.name}{edit.op !== 'remove' && <> = {edit.value || '(空值)'}</>}</code></span>)}</>
}

function HeaderEditor({ title, edits, onChange }: { title: string; edits: HeaderEdit[]; onChange: (edits: HeaderEdit[]) => void }) {
  const update = (index: number, patch: Partial<HeaderEdit>) => onChange(edits.map((edit, i) => i === index ? { ...edit, ...patch } : edit))
  const enabledCount = edits.filter((edit) => edit.enabled).length
  const countLabel = edits.length ? `${enabledCount}/${edits.length} 项启用` : '0 项操作'
  return <section className="stub-headers"><div className="stub-section-title"><h3>{title} <small>{countLabel}</small></h3><button type="button" aria-label={`添加 ${title}`} onClick={() => onChange([...edits, { enabled: true, op: 'set', name: '', value: '' }])}>＋ 添加 Header</button></div>{!edits.length && <div className="stub-headers-empty">未配置 Header 修改</div>}{edits.map((edit, index) => <div className={`stub-header-edit ${edit.enabled ? '' : 'off'}`} key={index}><button type="button" role="switch" aria-checked={edit.enabled} className={`stub-header-toggle ${edit.enabled ? 'on' : ''}`} aria-label={`${edit.enabled ? '关闭' : '开启'} ${title} 操作 ${index + 1}`} title={edit.enabled ? '临时关闭此 Header 修改' : '开启此 Header 修改'} onClick={() => update(index, { enabled: !edit.enabled })}><i aria-hidden="true" /></button><select aria-label={`${title} 操作 ${index + 1}`} value={edit.op} onChange={(e) => update(index, { op: e.target.value as HeaderEdit['op'] })}><option value="add">增加</option><option value="set">覆盖</option><option value="remove">删除</option></select><input required aria-label={`${title} 名称 ${index + 1}`} placeholder="Header 名称" value={edit.name} onChange={(e) => update(index, { name: e.target.value })} /><input aria-label={`${title} 值 ${index + 1}`} placeholder={edit.op === 'remove' ? '移除全部同名值' : 'Header 值（可为空）'} disabled={edit.op === 'remove'} value={edit.op === 'remove' ? '' : edit.value} onChange={(e) => update(index, { value: e.target.value })} /><button type="button" className="stub-remove-header" aria-label={`移除 ${title} 操作 ${index + 1}`} onClick={() => onChange(edits.filter((_, i) => i !== index))}>×</button></div>)}</section>
}
