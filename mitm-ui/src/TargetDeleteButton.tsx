import { useState } from 'react'
import { ConfirmDialog } from './ConfirmDialog'

export function TargetDeleteButton({ suffix, disabled = false, onDelete }: {
  suffix: string
  disabled?: boolean
  onDelete: () => Promise<unknown>
}) {
  const [open, setOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState('')

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
    <button
      type="button"
      className="target-remove"
      aria-label={`删除 ${suffix}`}
      title={`删除 ${suffix}`}
      disabled={disabled}
      onClick={() => { setError(''); setOpen(true) }}
    >×</button>
    <ConfirmDialog
      open={open}
      title="删除解密域名后缀？"
      confirmLabel={deleting ? '删除中…' : '确认删除'}
      cancelLabel="取消"
      busy={deleting}
      error={error}
      onConfirm={remove}
      onCancel={() => setOpen(false)}
    >
      <p className="target-delete-suffix">{suffix}</p>
      <p>删除后，此后缀不再用于新连接的解密匹配。已建立的连接和 Stub 规则保留。</p>
    </ConfirmDialog>
  </>
}
