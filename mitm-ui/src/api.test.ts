import { describe, expect, it } from 'vitest'
import { fullUrl } from './api'
import { formatBytes, formatCaptureState, formatDuration, formatTime, prettyBody, statusTone, toCurl } from './format'

describe('fullUrl', () => {
  it('includes query when present', () => {
    expect(fullUrl({ authority: 'api.example.com', path: '/v1/users', query: 'page=2' })).toBe(
      'https://api.example.com/v1/users?page=2',
    )
  })
})

describe('format helpers', () => {
  it('localizes capture states', () => {
    expect(formatCaptureState('complete')).toBe('完成')
    expect(formatCaptureState('interrupted')).toBe('中断')
    expect(formatCaptureState('unknown')).toBe('unknown')
  })

  it('formats duration and bytes', () => {
    expect(formatDuration(null)).toBe('…')
    expect(formatDuration(218)).toBe('218ms')
    expect(formatDuration(1194)).toBe('1.19s')
    expect(formatBytes(80)).toBe('80 B')
    expect(formatBytes(2048)).toBe('2.0 KiB')
  })

  it('omits the date when the record is from today', () => {
    const now = Date.parse('2026-08-15T14:46:29.271+08:00')
    const text = formatTime(now, now)
    expect(text).toMatch(/14:46:29/)
    expect(text).not.toMatch(/08/)
  })

  it('pretty-prints JSON and leaves other bodies alone', () => {
    expect(prettyBody('{"hello":"world"}')).toBe('{\n  "hello": "world"\n}')
    expect(prettyBody('<html>ok</html>')).toBe('<html>ok</html>')
  })

  it('maps status tones', () => {
    expect(statusTone(null)).toBe('pending')
    expect(statusTone(503)).toBe('5')
  })

  it('builds a curl command without host/content-length', () => {
    const curl = toCurl({
      id: '1',
      started_at_ms: 0,
      completed_at_ms: 1,
      client_ip: '127.0.0.1',
      proxy_username: 'admin',
      authority: 'httpbin.org',
      host: 'httpbin.org',
      path: '/post',
      query: null,
      method: 'POST',
      status: 200,
      duration_ms: 10,
      capture_state: 'complete',
      request_version: 'HTTP/1.1',
      request_headers: [
        ['host', 'httpbin.org'],
        ['content-type', 'application/json'],
        ['content-length', '18'],
      ],
      request_body: '{"hello":"world"}',
      request_body_bytes: 17,
      request_body_truncated: false,
      request_body_note: null,
      response_version: 'HTTP/2',
      response_headers: [],
      response_body: '',
      response_body_bytes: 0,
      response_body_truncated: false,
      response_body_note: null,
      error: null,
    })
    expect(curl).toContain("curl 'https://httpbin.org/post'")
    expect(curl).toContain('-X POST')
    expect(curl).toContain(" -H 'content-type: application/json'")
    expect(curl).not.toContain('content-length')
    expect(curl).not.toContain(" -H 'host:")
  })
})
