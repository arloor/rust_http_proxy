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

// 留存记录等设置框：只接受 ≥1 的整数，空值/小数/科学计数都视为未完成输入
export function parsePositiveInt(raw: string): number | null {
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) return null
  const n = Number(trimmed)
  return Number.isInteger(n) && n >= 1 ? n : null
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

const REASON_PHRASES: Record<number, string> = {
  100: 'Continue',
  101: 'Switching Protocols',
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  204: 'No Content',
  206: 'Partial Content',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
}

export function statusLine(detail: Pick<RecordDetail, 'response_version' | 'status'>): string {
  const version = detail.response_version || 'HTTP/1.1'
  if (detail.status === null) return version
  const reason = REASON_PHRASES[detail.status]
  return reason ? `${version} ${detail.status} ${reason}` : `${version} ${detail.status}`
}

export function formatHeaders(headers: [string, string][]): string {
  return headers.map(([name, value]) => `${name}: ${value}`).join('\n')
}

// 原始 HTTP 响应：status line + headers + 空行 + body（body 按抓取原文，图片为 base64）
export function toHttpResponse(detail: RecordDetail): string {
  const headers = formatHeaders(detail.response_headers)
  return `${statusLine(detail)}\n${headers}${headers ? '\n' : ''}\n${detail.response_body}`
}

export function toExportText(detail: RecordDetail): string {
  return `${toCurl(detail)}\n\n${toHttpResponse(detail)}`
}

// Windows 文件名非法字符 \ / : * ? " < > | 以及空白一律换成下划线
export function exportFilename(detail: Pick<RecordDetail, 'method' | 'host' | 'path' | 'started_at_ms'>): string {
  const date = new Date(detail.started_at_ms)
  const pad = (n: number, width = 2) => String(n).padStart(width, '0')
  const stamp = `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
  const safe = (value: string) => value.replace(/[^\w.-]+/g, '_').replace(/^_|_$/g, '')
  const path = safe(detail.path).slice(0, 48) || 'root'
  return `${detail.method}_${safe(detail.host)}_${path}_${stamp}.txt`
}
