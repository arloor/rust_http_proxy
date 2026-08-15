import type { RecordDetail } from './api'
import { fullUrl } from './api'

const CAPTURE_LABELS: Record<string, string> = {
  complete: '完成',
  capturing: '抓取中',
  interrupted: '中断',
  capture_stopped: '已停止',
  upgraded: '已提升',
  error: '错误',
}

export function formatCaptureState(state: string): string {
  return CAPTURE_LABELS[state] ?? state
}

export function formatTime(value: number, now = Date.now()): string {
  const date = new Date(value)
  const today = new Date(now)
  const sameDay = date.toDateString() === today.toDateString()
  return new Intl.DateTimeFormat('zh-CN', {
    month: sameDay ? undefined : '2-digit',
    day: sameDay ? undefined : '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
  }).format(value)
}

export function formatDuration(ms: number | null): string {
  if (ms === null) return '…'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

// 端口为 0 表示老记录没有端口数据，只显示 IP；IPv6 地址加方括号
export function formatClientAddr(ip: string, port: number): string {
  if (!port) return ip
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`
}

export function statusTone(status: number | null): string {
  if (status === null) return 'pending'
  return String(Math.floor(status / 100))
}

export function prettyBody(body: string): string {
  const trimmed = body.trim()
  if (!trimmed) return ''
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      return body
    }
  }
  return body
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

export function toCurl(detail: RecordDetail): string {
  const lines = [`curl ${shellQuote(fullUrl(detail))}`]
  if (detail.method && detail.method !== 'GET') {
    lines.push(`  -X ${detail.method}`)
  }
  for (const [name, value] of detail.request_headers) {
    if (['host', 'content-length'].includes(name.toLowerCase())) continue
    lines.push(`  -H ${shellQuote(`${name}: ${value}`)}`)
  }
  if (detail.request_body) {
    lines.push(`  --data-raw ${shellQuote(detail.request_body)}`)
  }
  return lines.join(' \\\n')
}
