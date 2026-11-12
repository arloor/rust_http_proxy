import { isExtension, managementFetch } from './connection'

// Keep incomplete lines across chunks, including a CRLF split between chunks.
export class EventParser {
  private buffer = ''
  private type = ''
  private data: string[] = []
  constructor(private emit: (event: MessageEvent) => void) {}
  push(chunk: string) {
    this.buffer += chunk
    while (true) {
      const end = this.buffer.search(/[\r\n]/)
      if (end < 0 || (this.buffer[end] === '\r' && end === this.buffer.length - 1)) return
      const line = this.buffer.slice(0, end)
      this.buffer = this.buffer.slice(end + (this.buffer.slice(end, end + 2) === '\r\n' ? 2 : 1))
      if (!line) {
        if (this.data.length) this.emit(new MessageEvent(this.type || 'message', { data: this.data.join('\n') }))
        this.type = ''; this.data = []
      } else {
        const colon = line.indexOf(':')
        const field = colon < 0 ? line : line.slice(0, colon)
        const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
        if (field === 'event') this.type = value
        if (field === 'data') this.data.push(value)
      }
    }
  }
}

class AuthenticatedEvents {
  private target = new EventTarget()
  private controller = new AbortController()
  private timer?: ReturnType<typeof setTimeout>
  onerror: (() => void) | null = null
  constructor() { void this.connect() }
  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    this.target.addEventListener(type, listener as EventListener)
  }
  close() { this.controller.abort(); clearTimeout(this.timer) }
  private async connect() {
    try {
      const response = await managementFetch('/mitm/api/events', { signal: this.controller.signal })
      if (!response.ok || !response.body || !response.headers.get('content-type')?.includes('text/event-stream')) {
        await response.body?.cancel()
        throw new Error('事件连接失败')
      }
      this.target.dispatchEvent(new MessageEvent('open'))
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
      const parser = new EventParser(event => this.target.dispatchEvent(event))
      try {
        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          parser.push(value)
        }
      } finally { reader.releaseLock() }
    } catch { /* Reconnect and resync via the existing open handler. */ }
    if (!this.controller.signal.aborted) {
      this.onerror?.()
      this.timer = setTimeout(() => void this.connect(), 3000)
    }
  }
}

export function managementEvents() {
  return isExtension ? new AuthenticatedEvents() : new EventSource('/mitm/api/events')
}
