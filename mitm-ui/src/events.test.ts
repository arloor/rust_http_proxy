import { afterEach, expect, it, vi } from 'vitest'
import { EventParser } from './events'

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.resetModules() })

it('parses chunked CRLF, multiline data and heartbeats without emitting incomplete frames', () => {
  const events: MessageEvent[] = []
  const parser = new EventParser(event => events.push(event))
  for (const char of ': heartbeat\r\n\r\nevent: record_created\r\ndata: first\r\ndata: second\r\n\r\ndata: next\n\nevent: pending\ndata: unfinished') parser.push(char)
  expect(events.map(event => [event.type, event.data])).toEqual([['record_created', 'first\nsecond'], ['message', 'next']])
})

it('reconnects after EOF and cancels retries when closed', async () => {
  vi.useFakeTimers()
  vi.stubGlobal('chrome', { runtime: { id: 'test' }, storage: {
    local: { get: async () => ({ connection: { origin: 'https://localhost:444', username: 'admin' } }) },
    session: { get: async () => ({}) },
  } })
  const fetch = vi.fn().mockImplementation(async () => new Response('event: settings\ndata: {}\n\n', { headers: { 'Content-Type': 'text/event-stream' } }))
  vi.stubGlobal('fetch', fetch)
  vi.resetModules()
  const { loadConnection } = await import('./connection')
  await loadConnection()
  const { managementEvents } = await import('./events')
  const source = managementEvents()
  const opened = vi.fn()
  const changed = vi.fn()
  const failed = vi.fn()
  source.addEventListener('open', opened)
  source.addEventListener('settings', changed)
  source.onerror = failed
  await vi.advanceTimersByTimeAsync(0)
  expect(opened).toHaveBeenCalledTimes(1)
  expect(changed).toHaveBeenCalledTimes(1)
  expect(failed).toHaveBeenCalledTimes(1)
  await vi.advanceTimersByTimeAsync(3000)
  expect(opened).toHaveBeenCalledTimes(2)
  source.close()
  await vi.advanceTimersByTimeAsync(9000)
  expect(fetch).toHaveBeenCalledTimes(2)
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true)
})
