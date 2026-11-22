import { useEffect, useId, useRef, type ReactNode } from 'react'

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = '确认',
  cancelLabel = '取消',
  tone = 'danger',
  busy = false,
  error = '',
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  children: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  tone?: 'danger' | 'primary'
  busy?: boolean
  error?: string
  onConfirm: () => void | Promise<unknown>
  onCancel: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  const descriptionId = useId()

  useEffect(() => {
    if (!open) return
    const element = dialog.current
    element?.showModal()
    return () => element?.close()
  }, [open])

  if (!open) return null

  return (
    <dialog
      ref={dialog}
      className="confirm-dialog"
      role="alertdialog"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      onMouseDown={(event) => {
        if (busy || event.target !== event.currentTarget || event.button !== 0) return
        const { left, right, top, bottom } = event.currentTarget.getBoundingClientRect()
        if (event.clientX < left || event.clientX > right || event.clientY < top || event.clientY > bottom) {
          onCancel()
        }
      }}
      onCancel={(event) => {
        event.preventDefault()
        if (!busy) onCancel()
      }}
    >
      <h2 id={titleId}>{title}</h2>
      <div id={descriptionId} className="confirm-dialog-body">{children}</div>
      {error && <p className="confirm-dialog-error" role="alert">{error}</p>}
      <div className="confirm-dialog-actions">
        <button type="button" autoFocus disabled={busy} onClick={onCancel}>{cancelLabel}</button>
        <button
          type="button"
          className={tone === 'danger' ? 'confirm-dialog-danger' : 'confirm-dialog-primary'}
          disabled={busy}
          onClick={() => void onConfirm()}
        >
          {confirmLabel}
        </button>
      </div>
    </dialog>
  )
}
