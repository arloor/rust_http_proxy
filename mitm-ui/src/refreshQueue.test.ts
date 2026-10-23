import { afterEach, expect, it, vi } from 'vitest'
import { createRefreshQueue } from './refreshQueue'

afterEach(() => vi.useRealTimers())

it('flushes during continuous traffic and preserves the batch flags', async () => {
  vi.useFakeTimers()
  const refresh = vi.fn(async (_dirty: Set<string>) => {})
  const queue = createRefreshQueue(250, refresh)
  queue.add('records', 'meta')
  for (let i = 0; i < 5; i++) {
    await vi.advanceTimersByTimeAsync(50)
    queue.add('records')
  }
  expect(refresh).toHaveBeenCalledTimes(1)
  expect(refresh.mock.calls[0][0]).toEqual(new Set(['records', 'meta']))
  queue.dispose()
})

it('serializes requests and drains changes received during a refresh', async () => {
  vi.useFakeTimers()
  let finish!: () => void
  const refresh = vi.fn((_dirty: Set<string>) => new Promise<void>((resolve) => { finish = resolve }))
  const queue = createRefreshQueue(200, refresh)
  queue.add('records')
  await vi.advanceTimersByTimeAsync(200)
  queue.add('meta')
  await vi.advanceTimersByTimeAsync(1000)
  expect(refresh).toHaveBeenCalledTimes(1)
  finish()
  await vi.advanceTimersByTimeAsync(200)
  expect(refresh).toHaveBeenCalledTimes(2)
  expect(refresh.mock.calls[1][0]).toEqual(new Set(['meta']))
  queue.dispose()
  finish()
})

it('disposes pending work', async () => {
  vi.useFakeTimers()
  const refresh = vi.fn(async () => {})
  const queue = createRefreshQueue<string>(200, refresh)
  queue.add('recent')
  queue.dispose()
  queue.add('recent')
  await vi.advanceTimersByTimeAsync(1000)
  expect(refresh).not.toHaveBeenCalled()
})
