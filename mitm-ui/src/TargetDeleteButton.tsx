import { useEffect, useId, useRef, useState } from 'react'

export function TargetDeleteButton({ suffix, disabled = false, onDelete }: {
  suffix: string
  disabled?: boolean
  onDelete: () => Promise<unknown>
}) {
  const [open, setOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState('')
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  const descriptionId = useId()

  useEffect(() => {
    if (!open) return
    const element = dialog.current
    element?.showModal()
    return () => element?.close()
  }, [open])

  async function remove() {
    if (deleting) return
    setDeleting(true)
    setError('')
    try {
      await onDelete()
      setOpen(false)
    } catch (value) {
      setError(value instanceof Error ? value.message : String(value))
    } finally {
      setDeleting(false)
    }
  }

  return <>
    <button type="button" className="target-remove" aria-label={`删除 ${suffix}`} disabled={disabled}
      onClick={() => { setError(''); setOpen(true) }}>×</button>
    {open && <dialog ref={dialog} className="target-delete-dialog" role="alertdialog"
      aria-labelledby={titleId} aria-describedby={descriptionId}
      onCancel={event => { event.preventDefault(); if (!deleting) setOpen(false) }}>
      <h2 id={titleId}>删除解密域名后缀？</h2>
      <div id={descriptionId}>
        <p className="target-delete-suffix">{suffix}</p>
        <p>删除后，此后缀不再用于新连接的解密匹配。已建立的连接和 Stub 规则保留。</p>
      </div>
      {error && <p className="target-delete-error" role="alert">{error}</p>}
      <div className="target-delete-actions">
        <button type="button" autoFocus disabled={deleting} onClick={() => setOpen(false)}>取消</button>
        <button type="button" className="target-delete-confirm" disabled={deleting}
          onClick={() => void remove()}>{deleting ? '删除中…' : '确认删除'}</button>
      </div>
    </dialog>}
  </>
}
